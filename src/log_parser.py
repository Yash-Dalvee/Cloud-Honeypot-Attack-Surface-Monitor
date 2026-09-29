"""
log_parser.py
-------------
Parses raw Cowrie-style honeypot logs (either a JSON array, as produced by
the sample dataset, or newline-delimited JSON as produced by real Cowrie
installs / src/honeypot_server.py) into normalized per-session attacker
telemetry records, and exports an ECS-flavored JSON document set suitable
for direct ingestion into Elasticsearch/Wazuh.
"""

import argparse
import json
import os
from collections import defaultdict
from datetime import datetime, timezone

DEFAULT_INPUT = os.path.join("data", "cowrie_sample_logs.json")
DEFAULT_NORMALIZED_OUTPUT = os.path.join("data", "normalized_events.json")
DEFAULT_ELK_OUTPUT = os.path.join("data", "elk_export.json")

TIMESTAMP_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
)


def parse_timestamp(ts: str):
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    # Fall back to fromisoformat (handles offsets like +00:00)
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def load_raw_events(input_path: str):
    """
    Supports both:
      - A JSON array of event objects: [ {...}, {...}, ... ]
      - JSON-lines (one JSON object per line), the native Cowrie format.
    """
    with open(input_path, "r", encoding="utf-8") as fh:
        content = fh.read().strip()

    if not content:
        return []

    if content.startswith("["):
        return json.loads(content)

    events = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        events.append(json.loads(line))
    return events


class SessionRecord:
    """Aggregates all events belonging to a single Cowrie session id."""

    def __init__(self, session_id, src_ip):
        self.session_id = session_id
        self.src_ip = src_ip
        self.src_port = None
        self.dst_port = None
        self.protocol = None
        self.sensor = None
        self.first_seen = None
        self.last_seen = None
        self.duration = None
        self.login_attempts = []       # list of {username, password, success, timestamp}
        self.commands = []             # list of {input, timestamp}
        self.successful_login = None   # {username, password} of first success, if any

    def touch(self, ts):
        if ts is None:
            return
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts

    def to_dict(self):
        return {
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "sensor": self.sensor,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "duration_seconds": self.duration,
            "login_attempt_count": len(self.login_attempts),
            "login_attempts": self.login_attempts,
            "successful_login": self.successful_login,
            "commands_executed": [c["input"] for c in self.commands],
            "command_events": self.commands,
            "command_count": len(self.commands),
            "attack_classification": self.classify(),
        }

    def classify(self):
        """Heuristic classification for quick triage in the report."""
        cmds = " ".join(c["input"].lower() for c in self.commands)
        if any(tok in cmds for tok in ("wget", "curl", "busybox", "chmod +x", "tftp")):
            return "malware_download_attempt"
        if "cat /etc/passwd" in cmds or "cat /etc/shadow" in cmds:
            return "credential_harvesting_recon"
        if self.commands:
            return "post_auth_recon"
        if len(self.login_attempts) >= 3:
            return "credential_brute_force"
        return "probe_only"


def normalize_events(raw_events):
    sessions = {}
    order = []

    for evt in raw_events:
        session_id = evt.get("session")
        src_ip = evt.get("src_ip")
        if session_id is None:
            continue
        if session_id not in sessions:
            sessions[session_id] = SessionRecord(session_id, src_ip)
            order.append(session_id)

        rec = sessions[session_id]
        ts = parse_timestamp(evt["timestamp"]) if evt.get("timestamp") else None
        rec.touch(ts)

        eventid = evt.get("eventid", "")

        if eventid == "cowrie.session.connect":
            rec.src_port = evt.get("src_port")
            rec.dst_port = evt.get("dst_port")
            rec.protocol = evt.get("protocol", "ssh")
            rec.sensor = evt.get("sensor")

        elif eventid in ("cowrie.login.failed", "cowrie.login.success"):
            attempt = {
                "username": evt.get("username", ""),
                "password": evt.get("password", ""),
                "success": eventid == "cowrie.login.success",
                "timestamp": evt.get("timestamp"),
            }
            rec.login_attempts.append(attempt)
            if attempt["success"] and rec.successful_login is None:
                rec.successful_login = {"username": attempt["username"], "password": attempt["password"]}

        elif eventid == "cowrie.command.input":
            rec.commands.append({"input": evt.get("input", ""), "timestamp": evt.get("timestamp")})

        elif eventid == "cowrie.session.closed":
            rec.duration = evt.get("duration")

        elif eventid == "cowrie.client.fingerprint":
            # Public key fingerprinting attempts are informational only;
            # not aggregated into login_attempts (no password material).
            pass

    return [sessions[sid].to_dict() for sid in order]


def compute_aggregate_stats(sessions):
    ip_counts = defaultdict(int)
    username_counts = defaultdict(int)
    password_counts = defaultdict(int)
    credential_pair_counts = defaultdict(int)
    protocol_counts = defaultdict(int)
    classification_counts = defaultdict(int)
    command_counts = defaultdict(int)
    hourly_attempts = defaultdict(int)

    for s in sessions:
        ip_counts[s["src_ip"]] += 1
        protocol_counts[s.get("protocol") or "unknown"] += 1
        classification_counts[s["attack_classification"]] += 1

        for attempt in s["login_attempts"]:
            u = attempt["username"] or "(blank)"
            p = attempt["password"] or "(blank)"
            username_counts[u] += 1
            password_counts[p] += 1
            credential_pair_counts[f"{u}:{p}"] += 1
            if attempt.get("timestamp"):
                hour_bucket = attempt["timestamp"][:13]  # YYYY-MM-DDTHH
                hourly_attempts[hour_bucket] += 1

        for cmd in s["commands_executed"]:
            command_counts[cmd] += 1

    def top_n(d, n=10):
        return sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:n]

    return {
        "total_sessions": len(sessions),
        "unique_source_ips": len(ip_counts),
        "total_login_attempts": sum(len(s["login_attempts"]) for s in sessions),
        "total_commands_executed": sum(s["command_count"] for s in sessions),
        "top_source_ips": top_n(ip_counts, 10),
        "top_usernames": top_n(username_counts, 10),
        "top_passwords": top_n(password_counts, 10),
        "top_credential_pairs": top_n(credential_pair_counts, 10),
        "top_commands": top_n(command_counts, 10),
        "protocol_breakdown": dict(protocol_counts),
        "attack_classification_breakdown": dict(classification_counts),
        "brute_force_attempts_by_hour": dict(sorted(hourly_attempts.items())),
    }


def build_elk_documents(sessions, geo_lookup=None, index_name="honeypot-events"):
    """
    Produces ECS-flavored documents, one per session, ready for bulk
    ingestion into Elasticsearch or Wazuh. geo_lookup, if provided, is a
    dict of {ip: enrichment_dict} as produced by geo_enricher.py.
    """
    geo_lookup = geo_lookup or {}
    docs = []
    for s in sessions:
        geo = geo_lookup.get(s["src_ip"], {})
        doc = {
            "_index": index_name,
            "_source": {
                "@timestamp": s["first_seen"],
                "event": {
                    "kind": "event",
                    "category": ["intrusion_detection"],
                    "type": ["info"],
                    "dataset": "cowrie.honeypot",
                    "outcome": "success" if s["successful_login"] else "failure",
                },
                "source": {
                    "ip": s["src_ip"],
                    "port": s["src_port"],
                    "geo": {
                        "country_name": geo.get("country"),
                        "city_name": geo.get("city"),
                        "region_name": geo.get("regionName"),
                        "location": {"lat": geo.get("lat"), "lon": geo.get("lon")},
                    },
                    "as": {
                        "number": geo.get("asn_number"),
                        "organization": {"name": geo.get("isp") or geo.get("asname")},
                    },
                },
                "destination": {"port": s["dst_port"]},
                "network": {"protocol": s.get("protocol", "ssh"), "transport": "tcp"},
                "honeypot": {
                    "session_id": s["session_id"],
                    "sensor": s.get("sensor"),
                    "duration_seconds": s.get("duration_seconds"),
                    "login_attempt_count": s["login_attempt_count"],
                    "successful_login": s["successful_login"],
                    "commands_executed": s["commands_executed"],
                    "attack_classification": s["attack_classification"],
                },
                "rule": {
                    "name": "Honeypot interaction detected",
                    "description": f"Attacker session classified as {s['attack_classification']}",
                },
            },
        }
        docs.append(doc)
    return docs


def run(input_path=DEFAULT_INPUT, normalized_output=DEFAULT_NORMALIZED_OUTPUT,
        elk_output=DEFAULT_ELK_OUTPUT, index_name="honeypot-events", geo_lookup=None):
    raw_events = load_raw_events(input_path)
    sessions = normalize_events(raw_events)
    stats = compute_aggregate_stats(sessions)

    normalized_payload = {"sessions": sessions, "aggregate_stats": stats}
    os.makedirs(os.path.dirname(normalized_output) or ".", exist_ok=True)
    with open(normalized_output, "w", encoding="utf-8") as fh:
        json.dump(normalized_payload, fh, indent=2, default=str)

    elk_docs = build_elk_documents(sessions, geo_lookup=geo_lookup, index_name=index_name)
    os.makedirs(os.path.dirname(elk_output) or ".", exist_ok=True)
    with open(elk_output, "w", encoding="utf-8") as fh:
        json.dump(elk_docs, fh, indent=2, default=str)

    return sessions, stats


def main():
    parser = argparse.ArgumentParser(description="Parse Cowrie honeypot logs into normalized telemetry + ELK export")
    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--normalized-output", default=DEFAULT_NORMALIZED_OUTPUT)
    parser.add_argument("--elk-output", default=DEFAULT_ELK_OUTPUT)
    parser.add_argument("--index-name", default="honeypot-events")
    args = parser.parse_args()

    sessions, stats = run(
        input_path=args.input,
        normalized_output=args.normalized_output,
        elk_output=args.elk_output,
        index_name=args.index_name,
    )
    print(f"Parsed {len(sessions)} sessions from {args.input}")
    print(f"  -> Normalized telemetry: {args.normalized_output}")
    print(f"  -> ELK/Wazuh export:     {args.elk_output}")
    print(f"  Unique source IPs: {stats['unique_source_ips']}")
    print(f"  Total login attempts: {stats['total_login_attempts']}")
    print(f"  Total commands executed: {stats['total_commands_executed']}")


if __name__ == "__main__":
    main()
