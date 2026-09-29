"""
geo_enricher.py
----------------
Enriches attacker source IPs with Country, City, Region, ISP, and ASN
information. Resolution order:

  1. Local cache (data/geo_cache.json) - avoids repeat lookups.
  2. If settings.geo_enrichment.offline_mode is true (default, so this
     project runs with zero network access), a bundled static lookup
     table at data/geo_static_fallback.json is used, with a deterministic
     synthetic fallback for any IP not in that table.
  3. If offline_mode is false: live query against the free ip-api.com
     JSON API (no key required, rate-limited to 45 req/min).
  4. If ip-api is unreachable and a MaxMind GeoLite2 .mmdb file is present
     (see settings.geo_enrichment.geolite2_fallback_db), the `geoip2`
     library is used as a final fallback.

No enrichment path ever fails the pipeline - if all lookups are
unavailable for a given IP, a clearly-labeled "Unknown" record is
returned so downstream reporting never crashes on missing geo data.
"""

import argparse
import json
import os
import time
import hashlib

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

try:
    import geoip2.database
except ImportError:  # pragma: no cover
    geoip2 = None

DEFAULT_SETTINGS_PATH = os.path.join("config", "settings.json")
DEFAULT_STATIC_FALLBACK = os.path.join("data", "geo_static_fallback.json")
DEFAULT_CACHE_PATH = os.path.join("data", "geo_cache.json")

UNKNOWN_RECORD_TEMPLATE = {
    "country": "Unknown",
    "countryCode": "XX",
    "city": "Unknown",
    "regionName": "Unknown",
    "isp": "Unknown",
    "org": "Unknown",
    "as": "Unknown",
    "asname": "Unknown",
    "asn_number": None,
    "lat": None,
    "lon": None,
}


def load_json(path, default=None):
    if not os.path.exists(path):
        return default if default is not None else {}
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_json(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def _extract_asn_number(as_field: str):
    """Pulls the numeric ASN out of a string like 'AS208294 FRANTECH SOLUTIONS'."""
    if not as_field:
        return None
    token = as_field.split(" ")[0]
    if token.upper().startswith("AS"):
        try:
            return int(token[2:])
        except ValueError:
            return None
    return None


def _synthetic_unknown_for_ip(ip: str):
    """
    Deterministic placeholder so repeated lookups of the same unseen IP are
    stable across runs, while being unambiguously labeled as unresolved.
    """
    record = dict(UNKNOWN_RECORD_TEMPLATE)
    record["_note"] = f"No geo data available for {ip} in offline mode and no cache/live entry found."
    return record


class GeoEnricher:
    def __init__(self, settings: dict, base_dir: str = "."):
        geo_cfg = settings.get("geo_enrichment", {})
        self.offline_mode = geo_cfg.get("offline_mode", True)
        self.ip_api_url_template = geo_cfg.get(
            "ip_api_url",
            "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,isp,org,as,asname,query",
        )
        self.timeout = geo_cfg.get("request_timeout_seconds", 5)
        self.rate_limit_delay = geo_cfg.get("rate_limit_delay_seconds", 1.5)
        self.cache_path = os.path.join(base_dir, geo_cfg.get("cache_path", DEFAULT_CACHE_PATH))
        self.static_fallback_path = os.path.join(base_dir, "data", "geo_static_fallback.json")
        self.geolite2_city_path = os.path.join(base_dir, geo_cfg.get("geolite2_fallback_db", ""))
        self.geolite2_asn_path = os.path.join(base_dir, geo_cfg.get("geolite2_asn_db", ""))

        self.cache = load_json(self.cache_path, default={})
        self.static_fallback = load_json(self.static_fallback_path, default={})

    def _lookup_static(self, ip: str):
        record = self.static_fallback.get(ip)
        if record:
            enriched = dict(record)
            enriched["asn_number"] = _extract_asn_number(record.get("as", ""))
            enriched["query"] = ip
            enriched["source"] = "static_fallback"
            return enriched
        return None

    def _lookup_ip_api(self, ip: str):
        if requests is None:
            return None
        try:
            url = self.ip_api_url_template.format(ip=ip)
            resp = requests.get(url, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") != "success":
                return None
            data["asn_number"] = _extract_asn_number(data.get("as", ""))
            data["source"] = "ip-api.com"
            return data
        except Exception:
            return None

    def _lookup_geolite2(self, ip: str):
        if geoip2 is None or not os.path.exists(self.geolite2_city_path):
            return None
        try:
            record = {}
            with geoip2.database.Reader(self.geolite2_city_path) as reader:
                resp = reader.city(ip)
                record.update({
                    "country": resp.country.name,
                    "countryCode": resp.country.iso_code,
                    "city": resp.city.name,
                    "regionName": resp.subdivisions.most_specific.name if resp.subdivisions else None,
                    "lat": float(resp.location.latitude) if resp.location.latitude else None,
                    "lon": float(resp.location.longitude) if resp.location.longitude else None,
                })
            if os.path.exists(self.geolite2_asn_path):
                with geoip2.database.Reader(self.geolite2_asn_path) as reader:
                    asn_resp = reader.asn(ip)
                    record["asname"] = asn_resp.autonomous_system_organization
                    record["isp"] = asn_resp.autonomous_system_organization
                    record["as"] = f"AS{asn_resp.autonomous_system_number} {asn_resp.autonomous_system_organization}"
                    record["asn_number"] = asn_resp.autonomous_system_number
            record["source"] = "geolite2_local_db"
            return record
        except Exception:
            return None

    def enrich(self, ip: str) -> dict:
        if ip in self.cache:
            return self.cache[ip]

        record = None
        if self.offline_mode:
            record = self._lookup_static(ip)
        else:
            record = self._lookup_ip_api(ip)
            if record is None:
                record = self._lookup_geolite2(ip)
            if record is None:
                record = self._lookup_static(ip)

        if record is None:
            record = _synthetic_unknown_for_ip(ip)

        self.cache[ip] = record
        save_json(self.cache_path, self.cache)

        if not self.offline_mode and record.get("source") == "ip-api.com":
            time.sleep(self.rate_limit_delay)  # respect free-tier rate limits

        return record

    def enrich_many(self, ips):
        return {ip: self.enrich(ip) for ip in sorted(set(ips))}


def main():
    parser = argparse.ArgumentParser(description="Enrich a list of IPs (or all IPs found in normalized_events.json) with geolocation/ASN data")
    parser.add_argument("--settings", default=DEFAULT_SETTINGS_PATH)
    parser.add_argument("--ip", action="append", help="Specific IP(s) to enrich. Repeatable.")
    parser.add_argument("--from-normalized", default=None, help="Path to normalized_events.json to pull IPs from")
    args = parser.parse_args()

    settings = load_json(args.settings)
    enricher = GeoEnricher(settings)

    ips = list(args.ip) if args.ip else []
    if args.from_normalized:
        payload = load_json(args.from_normalized)
        ips.extend(s["src_ip"] for s in payload.get("sessions", []))

    if not ips:
        ips = list(enricher.static_fallback.keys())

    results = enricher.enrich_many(ips)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
