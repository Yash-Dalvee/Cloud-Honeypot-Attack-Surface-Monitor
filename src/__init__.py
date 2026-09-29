"""
Cloud Honeypot & Attack Surface Monitor
-----------------------------------------
A defensive security toolkit for deploying a decoy SSH/Telnet service,
ingesting Cowrie-style honeypot telemetry, enriching attacker source IPs
with geolocation/ASN data, and generating analyst-ready threat reports.

This package is intended ONLY for deployment on infrastructure you own
or are explicitly authorized to monitor. See README.md for the full
security disclaimer.
"""

__version__ = "1.0.0"
__all__ = ["honeypot_server", "log_parser", "geo_enricher", "report_generator"]
