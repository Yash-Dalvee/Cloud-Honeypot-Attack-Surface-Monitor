# Cloud Honeypot & Attack Surface Monitor

A production-ready, self-contained toolkit for deploying a decoy SSH/Telnet
service, capturing attacker telemetry (credentials, source IPs, commands,
session duration), enriching that telemetry with geolocation/ASN data, and
producing analyst-ready HTML/Markdown threat intelligence reports plus a
structured export for Elastic Stack (ELK) or Wazuh ingestion.

---

## ⚠️ Security Disclaimer

**Read this before deploying.**

- This project is intended **only** for deployment on infrastructure that
  you own, or that you are explicitly and contractually authorized to
  monitor. Deploying decoy services on networks/hosts you do not control
  or lack authorization for may violate computer misuse laws in your
  jurisdiction.
- The honeypot server (`src/honeypot_server.py`) **never** grants an
  attacker a real shell, **never** executes attacker-supplied input via
  `subprocess`, `os.system`, `eval`, or `exec`, and **never** touches the
  real filesystem of the host it runs on. All "command execution" is a
  closed set of canned, static string responses.
- Passwords captured from attackers are **not** validated against any
  real account and are stored only as forensic telemetry. Treat the
  resulting logs as sensitive data (they may occasionally contain
  credentials attackers have reused from breached, real accounts) and
  restrict access accordingly.
- Run the honeypot container with a **non-privileged, isolated network
  segment**, no outbound internet access if possible, and monitor
  resource usage — the fake shell will still consume threads/sockets
  under heavy connection load.
- The bundled GeoIP enrichment defaults to **offline mode** (a static
  lookup table), so the project has zero external network dependencies
  out of the box. Enabling live `ip-api.com` queries sends attacker IP
  addresses to a third-party API — review ip-api.com's terms before
  enabling `offline_mode: false` in production.

---

## Architecture

```
                         ┌─────────────────────────────────────────┐
                         │        Attacker / Botnet Scanner         │
                         └───────────────────┬───────────────────────┘
                                              │ SSH/Telnet probe (port 2222→22)
                                              ▼
                         ┌─────────────────────────────────────────┐
                         │     src/honeypot_server.py (Paramiko)     │
                         │  • Fake SSH banner & host key              │
                         │  • Captures ALL auth attempts               │
                         │  • Fake shell: canned responses ONLY        │
                         │  • Never executes real commands             │
                         └───────────────────┬───────────────────────┘
                                              │ writes JSON-lines events
                                              ▼
                         ┌─────────────────────────────────────────┐
                         │   data/honeypot_events.log (Cowrie-fmt)   │
                         │   OR data/cowrie_sample_logs.json         │
                         │   (bulk ingest of existing Cowrie logs)   │
                         └───────────────────┬───────────────────────┘
                                              │
                                              ▼
                         ┌─────────────────────────────────────────┐
                         │        src/log_parser.py                  │
                         │  • Groups events into sessions             │
                         │  • Extracts creds, commands, duration      │
                         │  • Heuristic attack classification         │
                         │  • Aggregate stats (top IPs/creds/cmds)    │
                         └──────────┬──────────────────┬──────────────┘
                                    │                  │
                                    ▼                  ▼
                 ┌────────────────────────┐  ┌────────────────────────────┐
                 │  src/geo_enricher.py    │  │ data/normalized_events.json │
                 │  • Country/City/ISP/ASN │  │ (per-session telemetry)     │
                 │  • ip-api / GeoLite2 /  │  └──────────────┬──────────────┘
                 │    offline static table │                 │
                 └───────────┬─────────────┘                 │
                              │                               │
                              ▼                               ▼
                 ┌─────────────────────────────────────────────────────┐
                 │              src/report_generator.py                  │
                 │  • Top 10 Attacker IPs   • Brute-force trend chart    │
                 │  • Top 10 Usernames/PWs  • Geolocation heatmap chart  │
                 │  • Attack classification • Self-contained HTML/MD     │
                 └───────────────────┬─────────────────────┬─────────────┘
                                      │                     │
                                      ▼                     ▼
                     reports/attack_report.html   data/elk_export.json
                     reports/attack_report.md     (ECS docs → Elasticsearch
                     (analyst dashboard)            / Wazuh bulk ingest)
```

---

## Directory Structure

```
honeypot_monitor/
├── config/
│   └── settings.json              # All tunables: ports, geo mode, report options
├── data/
│   ├── cowrie_sample_logs.json    # 11 realistic multi-origin attacker sessions
│   ├── geo_static_fallback.json   # Offline GeoIP/ASN lookup table (no network needed)
│   ├── normalized_events.json     # Generated: parsed session telemetry
│   ├── elk_export.json            # Generated: ECS docs for Elasticsearch/Wazuh
│   └── geo_cache.json             # Generated: geo lookup cache
├── src/
│   ├── __init__.py
│   ├── honeypot_server.py         # Paramiko SSH honeypot (safe, non-executing)
│   ├── log_parser.py              # Cowrie log ingester + normalizer + stats
│   ├── geo_enricher.py            # IP → Country/City/ISP/ASN enrichment
│   └── report_generator.py        # HTML + Markdown report builder (matplotlib charts)
├── tests/
│   └── test_parser.py             # 17 unit tests covering parsing & classification
├── reports/                        # Generated: attack_report.html / .md
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── README.md
```

---

## Quick Start (Local, No Docker)

```bash
git clone <your-repo-url> honeypot_monitor
cd honeypot_monitor
pip install -r requirements.txt

# 1) Process the bundled sample attack dataset end-to-end
python -m src.report_generator --settings config/settings.json

# Output:
#   reports/attack_report.html   <- open in any browser
#   reports/attack_report.md     <- for Slack/Confluence/GitHub
#   data/elk_export.json         <- bulk-import into Elasticsearch/Wazuh
#   data/normalized_events.json  <- raw normalized telemetry
```

```bash
# 2) (Optional) Run the live honeypot server on port 2222
python -m src.honeypot_server --config config/settings.json

# In another terminal, simulate an attacker:
ssh -p 2222 root@127.0.0.1
# Try any password - it will be logged, and after 3 attempts you'll be
# dropped into a fully simulated fake shell (try `uname -a`, `cat /etc/passwd`).
```

```bash
# 3) Run the test suite
pytest tests/test_parser.py -v
```

---

## Docker Deployment

```bash
# Build and start the honeypot listener (host port 2222 -> container 2222)
docker compose up -d --build honeypot

# Check logs
docker compose logs -f honeypot

# Generate a report from whatever the honeypot has captured so far
docker compose run --rm report-generator

# The generated report will appear on your host at:
#   ./reports/attack_report.html
```

To expose the honeypot on the real SSH port (22) instead of 2222, edit the
`ports:` mapping in `docker-compose.yml` to `"22:2222"` (requires the host's
real SSH daemon to be moved to another port first, or run on a dedicated
decoy host).

Scheduling periodic reports (cron on the Docker host):

```cron
0 * * * * cd /opt/honeypot_monitor && docker compose run --rm report-generator
```

---

## Configuration (`config/settings.json`)

| Key | Purpose |
|---|---|
| `honeypot.bind_port` | Port the decoy SSH service listens on (default `2222`) |
| `honeypot.ssh_banner` | Fake SSH version banner presented to scanners |
| `honeypot.hostname_fake` | Fake hostname shown in the simulated shell prompt |
| `geo_enrichment.offline_mode` | `true` (default) = zero-network static lookup table; `false` = live `ip-api.com` queries |
| `report_generator.top_n_ips` / `top_n_credentials` | How many rows to show in report tables |
| `elk_export.index_name` | Target Elasticsearch/Wazuh index name for exported docs |

---

## Sample Terminal Output

```text
$ python -m src.log_parser --input data/cowrie_sample_logs.json
Parsed 11 sessions from data/cowrie_sample_logs.json
  -> Normalized telemetry: data/normalized_events.json
  -> ELK/Wazuh export:     data/elk_export.json
  Unique source IPs: 6
  Total login attempts: 33
  Total commands executed: 16

$ python -m src.report_generator --settings config/settings.json
Report generation complete.
  HTML report:        ./reports/attack_report.html
  Markdown report:    ./reports/attack_report.md
  ELK/Wazuh export:   ./data/elk_export.json
  Normalized events:  ./data/normalized_events.json
  Total sessions analyzed: 11
  Unique attacker IPs:     6
```

```text
$ python -m src.honeypot_server --config config/settings.json
2026-08-23 09:41:02 [INFO] honeypot_server: Honeypot listening on 0.0.0.0:2222 (fake hostname=prod-db-server-01)
2026-08-23 09:41:02 [INFO] honeypot_server: Events logged to /app/data/honeypot_events.log
2026-08-23 09:41:17 [INFO] honeypot_server: Connection from 185.220.101.45:51422
2026-08-23 09:41:19 [INFO] honeypot_server: EVENT {"eventid": "cowrie.login.failed", "session": "9f1a2b3c", "src_ip": "185.220.101.45", "username": "root", "password": "123456", ...}
2026-08-23 09:41:22 [INFO] honeypot_server: EVENT {"eventid": "cowrie.login.success", "session": "9f1a2b3c", "src_ip": "185.220.101.45", "username": "root", "password": "toor", ...}
2026-08-23 09:41:25 [INFO] honeypot_server: EVENT {"eventid": "cowrie.command.input", "session": "9f1a2b3c", "src_ip": "185.220.101.45", "input": "uname -a"}
```

---

## Sample Generated Report Preview

`reports/attack_report.md` (excerpt, generated from the bundled sample dataset):

```markdown
# Cloud Honeypot & Attack Surface Monitor - Threat Intelligence Report

**Prepared for:** Acme Cloud Security Operations
**Generated:** 2026-08-23 09:49:34 UTC
**Classification:** TLP:AMBER - Internal Threat Intelligence

## Executive Summary

- **Total honeypot sessions observed:** 11
- **Unique attacker source IPs:** 6
- **Total credential attempts captured:** 33
- **Total post-auth commands captured:** 16

## Top 10 Attacker Source IPs

| Rank | Source IP | Sessions | Country | City | ISP / ASN |
|------|-----------|----------|---------|------|-----------|
| 1 | `185.220.101.45` | 3 | Germany | Frankfurt | Tor Exit Relay Network (AS208294 FRANTECH SOLUTIONS) |
| 2 | `45.155.205.233` | 2 | Netherlands | Amsterdam | MEVSPACE sp. z o.o. (AS202448 MEVSPACE) |
| 3 | `194.169.175.36` | 2 | Bulgaria | Sofia | Trending Web Sofia (AS62282 TRENDING-WEB) |
| 4 | `103.145.13.20` | 2 | Vietnam | Hanoi | Viettel Group (AS7552 VIETEL-AS-AP) |
| 5 | `91.240.118.168` | 1 | Ukraine | Kyiv | FOP Gubina (AS58271 UAB-ASN) |
| 6 | `218.92.0.212` | 1 | China | Nanjing | China Telecom (AS4134 CHINANET-BACKBONE) |

## Top 10 Targeted Usernames

| Rank | Username | Attempts |
|------|----------|----------|
| 1 | `root` | 16 |
| 2 | `admin` | 9 |
| 3 | `support` | 2 |
...

## Attack Classification Breakdown

| Classification | Sessions |
|-----------------|----------|
| Malware Download Attempt | 5 |
| Credential Brute Force | 5 |
| Probe Only | 1 |
```

The HTML version (`reports/attack_report.html`) renders the same data as a
dark-themed SOC dashboard with:

- KPI cards (sessions, unique IPs, credential attempts, commands captured)
- A geolocation-enriched Top-10 attacker IP table
- Bar chart of top attacker IPs
- Bar chart of top targeted username:password pairs
- Line chart of brute-force attempts over time (hourly buckets)
- Bar chart heatmap-style summary of sessions by country
- Attack classification and post-auth command breakdown tables

All charts are rendered server-side with `matplotlib` and embedded as
base64 PNGs, so the HTML report is a single portable file — no CDN, no
JavaScript charting library, and no internet connection required to view it.

---

## ELK / Wazuh Ingestion

`data/elk_export.json` contains one ECS-flavored document per honeypot
session, ready for bulk import:

```bash
# Elasticsearch bulk import example (requires a bulk-formatted transform,
# or import per-document via the _bulk API / Logstash http_poller / Filebeat)
curl -X POST "localhost:9200/honeypot-events/_doc/_bulk" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary @data/elk_export.json
```

Each document includes `event.*`, `source.ip` / `source.geo` / `source.as`,
`destination.port`, `network.protocol`, and a `honeypot.*` object with
session id, duration, credentials, commands, and attack classification —
directly mappable to Wazuh's custom decoder/rule pipeline or an
Elasticsearch index template.

---

## Running Tests

```bash
pip install -r requirements.txt
pytest tests/test_parser.py -v
```

The suite covers: JSON-array and JSON-lines log ingestion, session
grouping, credential/command extraction, duration capture, attack
classification heuristics, aggregate statistics (top IPs/usernames/
passwords/credential pairs/hourly brute-force buckets), ECS/ELK document
construction, and a safety regression test confirming captured attacker
commands are never executed anywhere in the parsing pipeline.

---

## License & Attribution

Provided as a reference implementation for internal security tooling.
Adapt credentials, banners, and fake filesystem content to match your
organization's actual environment for maximum decoy realism, and rotate
the honeypot's SSH host key (`config/honeypot_host_key`) periodically.
