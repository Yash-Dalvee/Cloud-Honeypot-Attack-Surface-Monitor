"""
honeypot_server.py
-------------------
A lightweight, Paramiko-based SSH honeypot.

SECURITY DESIGN GOALS
======================
1. The server NEVER validates credentials against a real system - all
   logins are captured for telemetry and then either rejected or granted
   into a fully simulated, sandboxed fake shell.
2. The fake shell NEVER executes real OS commands. It pattern-matches a
   small set of common recon commands (uname, whoami, cat /etc/passwd,
   wget, curl, ls, pwd, id, ps) and returns realistic canned output
   strings defined in config/settings.json / hardcoded fixtures below.
3. Every connection, auth attempt, and "command" typed by the attacker is
   written as a structured, Cowrie-compatible JSON event to the honeypot
   event log so it can be consumed by src/log_parser.py.
4. No inbound data is ever passed to shell=True, subprocess, eval, or exec.

Run standalone:
    python -m src.honeypot_server --config config/settings.json

This will bind to the configured port (default 2222) and log all
attacker activity to data/honeypot_events.log (JSON-lines, Cowrie-style).
"""

import argparse
import json
import logging
import os
import socket
import sys
import threading
import time
import uuid
from datetime import datetime, timezone

try:
    import paramiko
except ImportError:  # pragma: no cover
    paramiko = None

LOG = logging.getLogger("honeypot_server")

DEFAULT_SETTINGS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config",
    "settings.json",
)

# ---------------------------------------------------------------------------
# Canned, safe responses for the fake interactive shell. Nothing here ever
# touches the real filesystem or a real process table.
# ---------------------------------------------------------------------------
FAKE_COMMAND_RESPONSES = {
    "uname -a": "Linux prod-db-server-01 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 x86_64 GNU/Linux",
    "uname": "Linux",
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "pwd": "/root",
    "hostname": "prod-db-server-01",
    "cat /etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "admin:x:1000:1000:admin:/home/admin:/bin/bash"
    ),
    "cat /proc/cpuinfo": "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) CPU @ 2.20GHz",
    "ls": "backup.tar.gz  config.yml  logs  scripts",
    "ls -la": (
        "total 32\n"
        "drwxr-xr-x  5 root root 4096 Aug 10 09:12 .\n"
        "drwxr-xr-x 20 root root 4096 Aug 10 09:12 ..\n"
        "-rw-r--r--  1 root root 1284 Aug 10 09:12 config.yml\n"
        "drwxr-xr-x  2 root root 4096 Aug 10 09:12 logs"
    ),
    "ps": "  PID TTY          TIME CMD\n    1 ?        00:00:02 init\n  842 ?        00:00:00 sshd",
    "history -c": "",
    "busybox": "BusyBox v1.30.1 (Debian 1:1.30.1-6) multi-call binary.",
}
FAKE_DEFAULT_RESPONSE = ""  # unknown commands return empty output, like a locked-down box


def utcnow_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def load_settings(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def ensure_host_key(key_path):
    """
    Generate an RSA host key for the honeypot on first run if one does not
    already exist. This key identifies the DECOY server only - it is not
    used for any production system.
    """
    if os.path.exists(key_path):
        return paramiko.RSAKey(filename=key_path)
    os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(key_path)
    LOG.info("Generated new honeypot host key at %s", key_path)
    return key


class EventLogger:
    """Writes Cowrie-compatible JSON-lines events to disk (and stdout)."""

    def __init__(self, log_path):
        self.log_path = log_path
        os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
        self._lock = threading.Lock()

    def emit(self, event: dict):
        event.setdefault("timestamp", utcnow_iso())
        line = json.dumps(event, ensure_ascii=False)
        with self._lock:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        LOG.info("EVENT %s", line)


class HoneypotSSHServer(paramiko.ServerInterface):
    """
    Paramiko ServerInterface implementation.

    IMPORTANT: check_auth_password / check_auth_publickey ALWAYS record the
    attempt and then return AUTH_FAILED for a configurable number of
    attempts before "succeeding" into the fake shell - this maximizes the
    amount of credential telemetry captured per session, matching real
    botnet brute-force harvesting behavior seen in production honeypots.
    """

    def __init__(self, session_id, src_ip, src_port, event_logger: EventLogger, success_after=3):
        self.session_id = session_id
        self.src_ip = src_ip
        self.src_port = src_port
        self.event_logger = event_logger
        self.success_after = success_after
        self.attempt_count = 0
        self.event = threading.Event()
        self.last_username = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.attempt_count += 1
        self.last_username = username
        self.event_logger.emit({
            "eventid": "cowrie.login.failed" if self.attempt_count < self.success_after else "cowrie.login.success",
            "session": self.session_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_port": 22,
            "protocol": "ssh",
            "username": username,
            "password": password,
        })
        if self.attempt_count >= self.success_after:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.event_logger.emit({
            "eventid": "cowrie.client.fingerprint",
            "session": self.session_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "username": username,
            "key_fingerprint": key.get_fingerprint().hex(),
            "key_type": key.get_name(),
        })
        # Never accept public keys - force the attacker down the password
        # brute-force path so credential telemetry is captured.
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        # Attacker issued `ssh host "some command"` (non-interactive exec).
        cmd = command.decode(errors="replace") if isinstance(command, bytes) else command
        self.event_logger.emit({
            "eventid": "cowrie.command.input",
            "session": self.session_id,
            "src_ip": self.src_ip,
            "input": cmd,
        })
        response = FAKE_COMMAND_RESPONSES.get(cmd.strip(), FAKE_DEFAULT_RESPONSE)
        try:
            channel.send((response + "\n").encode() if response else b"")
            channel.send_exit_status(0)
        except Exception:
            pass
        threading.Timer(0.3, channel.close).start()
        return True


def handle_fake_shell(channel, session_id, src_ip, event_logger: EventLogger, hostname="prod-db-server-01"):
    """
    Drives a simulated interactive shell over an authenticated channel.
    Reads attacker keystrokes line-by-line, echoes a realistic prompt, and
    responds with static, safe canned output. No input is ever passed to a
    real shell, subprocess, eval, or exec.
    """
    prompt = f"root@{hostname}:~# "
    try:
        channel.send(f"Linux {hostname} 4.19.0-21-amd64 x86_64\n".encode())
        channel.send(prompt.encode())
        buf = b""
        while True:
            data = channel.recv(1024)
            if not data:
                break
            buf += data
            channel.send(data)  # local echo
            if b"\r" in buf or b"\n" in buf:
                line = buf.replace(b"\r", b"").replace(b"\n", b"").decode(errors="replace").strip()
                buf = b""
                channel.send(b"\r\n")
                if not line:
                    channel.send(prompt.encode())
                    continue
                if line in ("exit", "logout", "quit"):
                    channel.send(b"logout\r\n")
                    break
                event_logger.emit({
                    "eventid": "cowrie.command.input",
                    "session": session_id,
                    "src_ip": src_ip,
                    "input": line,
                })
                response = FAKE_COMMAND_RESPONSES.get(line, FAKE_DEFAULT_RESPONSE)
                if response:
                    channel.send(response.replace("\n", "\r\n").encode() + b"\r\n")
                elif line.split(" ")[0] not in ("", "clear"):
                    channel.send(f"-bash: {line.split(' ')[0]}: command not found\r\n".encode())
                channel.send(prompt.encode())
    except (EOFError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            channel.close()
        except Exception:
            pass


def handle_connection(client_sock, addr, host_key, event_logger: EventLogger, settings: dict, success_after=3):
    src_ip, src_port = addr
    session_id = uuid.uuid4().hex[:8]
    start_time = time.time()

    event_logger.emit({
        "eventid": "cowrie.session.connect",
        "session": session_id,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": settings["honeypot"].get("bind_port", 2222),
        "protocol": "ssh",
        "sensor": socket.gethostname(),
    })

    transport = paramiko.Transport(client_sock)
    transport.local_version = settings["honeypot"].get("ssh_banner", "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2")
    transport.add_server_key(host_key)
    server = HoneypotSSHServer(session_id, src_ip, src_port, event_logger, success_after=success_after)

    try:
        transport.start_server(server=server)
        channel = transport.accept(settings["honeypot"].get("session_timeout_seconds", 30))
        if channel is None:
            return
        if server.event.wait(10):
            handle_fake_shell(
                channel, session_id, src_ip, event_logger,
                hostname=settings["honeypot"].get("hostname_fake", "prod-db-server-01"),
            )
    except paramiko.SSHException as exc:
        LOG.debug("SSH negotiation failed for %s: %s", src_ip, exc)
    except Exception as exc:  # noqa: BLE001 - keep the honeypot alive no matter what
        LOG.debug("Unhandled connection error for %s: %s", src_ip, exc)
    finally:
        duration = round(time.time() - start_time, 3)
        event_logger.emit({
            "eventid": "cowrie.session.closed",
            "session": session_id,
            "src_ip": src_ip,
            "duration": duration,
        })
        try:
            transport.close()
        except Exception:
            pass


def serve_forever(settings_path=DEFAULT_SETTINGS_PATH):
    if paramiko is None:
        raise RuntimeError("paramiko is required to run the honeypot server. pip install paramiko")

    settings = load_settings(settings_path)
    hp_cfg = settings["honeypot"]

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(settings_path)))
    host_key_path = os.path.join(base_dir, hp_cfg.get("host_key_path", "config/honeypot_host_key"))
    log_path = os.path.join(base_dir, "data", "honeypot_events.log")

    host_key = ensure_host_key(host_key_path)
    event_logger = EventLogger(log_path)

    bind_host = hp_cfg.get("bind_host", "0.0.0.0")
    bind_port = int(hp_cfg.get("bind_port", 2222))
    max_conn = int(hp_cfg.get("max_connections", 200))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_host, bind_port))
    sock.listen(max_conn)

    LOG.info("Honeypot listening on %s:%s (fake hostname=%s)", bind_host, bind_port, hp_cfg.get("hostname_fake"))
    LOG.info("Events logged to %s", log_path)

    try:
        while True:
            client_sock, addr = sock.accept()
            LOG.info("Connection from %s:%s", addr[0], addr[1])
            t = threading.Thread(
                target=handle_connection,
                args=(client_sock, addr, host_key, event_logger, settings),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        LOG.info("Shutting down honeypot server.")
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(description="Cloud Honeypot SSH Server (Paramiko-based, non-interactive shell simulation)")
    parser.add_argument("--config", default=DEFAULT_SETTINGS_PATH, help="Path to config/settings.json")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if paramiko is None:
        print("ERROR: paramiko is not installed. Run: pip install -r requirements.txt", file=sys.stderr)
        sys.exit(1)

    serve_forever(args.config)


if __name__ == "__main__":
    main()
