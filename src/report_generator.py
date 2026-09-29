"""
report_generator.py
--------------------
Builds an analyst-facing HTML dashboard and a Markdown summary report from
normalized honeypot telemetry (src/log_parser.py output) and geolocation
enrichment (src/geo_enricher.py output).

Charts (brute-force trend over time, top attacker IPs, top credentials)
are rendered with matplotlib and embedded directly into the HTML report
as base64 PNGs, so the report is a single, portable, self-contained file
with no external asset dependencies.
"""

import argparse
import base64
import io
import json
import os
from datetime import datetime, timezone

import matplotlib
matplotlib.use("Agg")  # headless rendering, no display server required
import matplotlib.pyplot as plt

from src.log_parser import run as run_log_parser, DEFAULT_INPUT, DEFAULT_NORMALIZED_OUTPUT, DEFAULT_ELK_OUTPUT
from src.geo_enricher import GeoEnricher, load_json as geo_load_json

DEFAULT_SETTINGS_PATH = os.path.join("config", "settings.json")


# ---------------------------------------------------------------------------
# Chart rendering helpers
# ---------------------------------------------------------------------------
def _fig_to_base64(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=130, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("ascii")


def render_top_ips_chart(top_ips):
    labels = [ip for ip, _ in top_ips]
    values = [count for _, count in top_ips]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.barh(labels[::-1], values[::-1], color="#c0392b")
    ax.set_xlabel("Sessions")
    ax.set_title("Top Attacker Source IPs")
    fig.tight_layout()
    return _fig_to_base64(fig)


def render_top_credentials_chart(top_credential_pairs):
    labels = [pair for pair, _ in top_credential_pairs]
    values = [count for _, count in top_credential_pairs]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.barh(labels[::-1], values[::-1], color="#2980b9")
    ax.set_xlabel("Attempts")
    ax.set_title("Top Targeted Username:Password Pairs")
    fig.tight_layout()
    return _fig_to_base64(fig)


def render_brute_force_trend_chart(hourly_attempts: dict):
    if not hourly_attempts:
        fig, ax = plt.subplots(figsize=(8, 3))
        ax.text(0.5, 0.5, "No login attempt data available", ha="center", va="center")
        ax.axis("off")
        return _fig_to_base64(fig)

    buckets = sorted(hourly_attempts.keys())
    values = [hourly_attempts[b] for b in buckets]
    labels = [b[-2:] + ":00" for b in buckets]  # just the hour portion for compact x-axis
    fig, ax = plt.subplots(figsize=(9, 4))
    ax.plot(labels, values, marker="o", color="#e67e22", linewidth=2)
    ax.fill_between(labels, values, color="#e67e22", alpha=0.15)
    ax.set_ylabel("Login Attempts")
    ax.set_xlabel("Hour (UTC)")
    ax.set_title("Brute-Force Attempt Trend Over Time")
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    fig.tight_layout()
    return _fig_to_base64(fig)


def render_country_heatmap_chart(country_counts: dict):
    if not country_counts:
        fig, ax = plt.subplots(figsize=(8, 3))
        ax.text(0.5, 0.5, "No geolocation data available", ha="center", va="center")
        ax.axis("off")
        return _fig_to_base64(fig)
    items = sorted(country_counts.items(), key=lambda kv: kv[1], reverse=True)
    labels = [c for c, _ in items]
    values = [v for _, v in items]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(labels, values, color="#8e44ad")
    ax.set_ylabel("Sessions")
    ax.set_title("Attacker Sessions by Country (Geolocation Heatmap Summary)")
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right")
    fig.tight_layout()
    return _fig_to_base64(fig)


# ---------------------------------------------------------------------------
# Geo aggregation
# ---------------------------------------------------------------------------
def build_country_counts(sessions, geo_lookup):
    counts = {}
    for s in sessions:
        geo = geo_lookup.get(s["src_ip"], {})
        country = geo.get("country", "Unknown")
        counts[country] = counts.get(country, 0) + 1
    return counts


def build_geo_table_rows(stats, geo_lookup):
    rows = []
    for ip, count in stats["top_source_ips"]:
        geo = geo_lookup.get(ip, {})
        rows.append({
            "ip": ip,
            "sessions": count,
            "country": geo.get("country", "Unknown"),
            "city": geo.get("city", "Unknown"),
            "isp": geo.get("isp", "Unknown"),
            "asn": geo.get("as", "Unknown"),
        })
    return rows


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------
def generate_markdown_report(stats, geo_table_rows, settings, generated_at):
    cfg = settings.get("report_generator", {})
    title = cfg.get("report_title", "Cloud Honeypot & Attack Surface Monitor - Threat Intelligence Report")
    company = cfg.get("company_name", "Security Operations")

    lines = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"**Prepared for:** {company}  ")
    lines.append(f"**Generated:** {generated_at}  ")
    lines.append(f"**Classification:** TLP:AMBER - Internal Threat Intelligence")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Total honeypot sessions observed:** {stats['total_sessions']}")
    lines.append(f"- **Unique attacker source IPs:** {stats['unique_source_ips']}")
    lines.append(f"- **Total credential attempts captured:** {stats['total_login_attempts']}")
    lines.append(f"- **Total post-auth commands captured:** {stats['total_commands_executed']}")
    lines.append("")

    lines.append("## Top 10 Attacker Source IPs")
    lines.append("")
    lines.append("| Rank | Source IP | Sessions | Country | City | ISP / ASN |")
    lines.append("|------|-----------|----------|---------|------|-----------|")
    for i, row in enumerate(geo_table_rows, start=1):
        lines.append(f"| {i} | `{row['ip']}` | {row['sessions']} | {row['country']} | {row['city']} | {row['isp']} ({row['asn']}) |")
    lines.append("")

    lines.append("## Top 10 Targeted Usernames")
    lines.append("")
    lines.append("| Rank | Username | Attempts |")
    lines.append("|------|----------|----------|")
    for i, (user, count) in enumerate(stats["top_usernames"], start=1):
        lines.append(f"| {i} | `{user}` | {count} |")
    lines.append("")

    lines.append("## Top 10 Targeted Passwords")
    lines.append("")
    lines.append("| Rank | Password | Attempts |")
    lines.append("|------|----------|----------|")
    for i, (pw, count) in enumerate(stats["top_passwords"], start=1):
        lines.append(f"| {i} | `{pw}` | {count} |")
    lines.append("")

    lines.append("## Top Username:Password Combinations")
    lines.append("")
    lines.append("| Rank | Credential Pair | Attempts |")
    lines.append("|------|------------------|----------|")
    for i, (pair, count) in enumerate(stats["top_credential_pairs"], start=1):
        lines.append(f"| {i} | `{pair}` | {count} |")
    lines.append("")

    lines.append("## Brute-Force Attempts Over Time (UTC hourly buckets)")
    lines.append("")
    lines.append("| Hour (UTC) | Login Attempts |")
    lines.append("|------------|-----------------|")
    for hour, count in stats["brute_force_attempts_by_hour"].items():
        lines.append(f"| {hour}:00 | {count} |")
    lines.append("")

    lines.append("## Top Commands Executed Post-Authentication")
    lines.append("")
    lines.append("| Rank | Command | Occurrences |")
    lines.append("|------|---------|-------------|")
    for i, (cmd, count) in enumerate(stats["top_commands"], start=1):
        lines.append(f"| {i} | `{cmd}` | {count} |")
    lines.append("")

    lines.append("## Attack Classification Breakdown")
    lines.append("")
    lines.append("| Classification | Sessions |")
    lines.append("|-----------------|----------|")
    for cls, count in stats["attack_classification_breakdown"].items():
        lines.append(f"| {cls.replace('_', ' ').title()} | {count} |")
    lines.append("")

    lines.append("## Protocol Breakdown")
    lines.append("")
    lines.append("| Protocol | Sessions |")
    lines.append("|----------|----------|")
    for proto, count in stats["protocol_breakdown"].items():
        lines.append(f"| {proto.upper()} | {count} |")
    lines.append("")

    lines.append("---")
    lines.append("*Generated automatically by Cloud Honeypot & Attack Surface Monitor - report_generator.py*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
  :root {{
    --bg: #0f1117; --panel: #1a1d29; --accent: #e67e22; --text: #e8e8ec;
    --muted: #9aa0ac; --border: #2a2e3d; --danger: #c0392b; --ok: #27ae60;
  }}
  * {{ box-sizing: border-box; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', Roboto, Arial, sans-serif; margin: 0; padding: 0; }}
  header {{ background: linear-gradient(135deg, #1a1d29, #0f1117); padding: 32px 40px; border-bottom: 3px solid var(--accent); }}
  header h1 {{ margin: 0 0 6px 0; font-size: 26px; }}
  header p {{ margin: 2px 0; color: var(--muted); font-size: 13px; }}
  .container {{ padding: 30px 40px; max-width: 1200px; margin: 0 auto; }}
  .kpi-row {{ display: flex; gap: 18px; flex-wrap: wrap; margin-bottom: 30px; }}
  .kpi {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 18px 22px; flex: 1; min-width: 180px; }}
  .kpi .value {{ font-size: 30px; font-weight: 700; color: var(--accent); }}
  .kpi .label {{ font-size: 12.5px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }}
  section {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 24px; margin-bottom: 26px; }}
  section h2 {{ margin-top: 0; font-size: 18px; border-bottom: 1px solid var(--border); padding-bottom: 10px; color: var(--accent); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13.5px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }}
  th {{ color: var(--muted); text-transform: uppercase; font-size: 11px; letter-spacing: 0.04em; }}
  tr:hover {{ background: rgba(230, 126, 34, 0.06); }}
  code {{ background: #10121a; padding: 2px 6px; border-radius: 4px; color: #f39c12; font-size: 12.5px; }}
  img.chart {{ max-width: 100%; border-radius: 6px; margin-top: 10px; }}
  .badge {{ display: inline-block; padding: 2px 9px; border-radius: 12px; font-size: 11px; font-weight: 600; }}
  .badge-danger {{ background: rgba(192,57,43,0.2); color: #e74c3c; }}
  .badge-warn {{ background: rgba(230,126,34,0.2); color: #e67e22; }}
  .badge-ok {{ background: rgba(39,174,96,0.2); color: #2ecc71; }}
  footer {{ text-align: center; color: var(--muted); font-size: 12px; padding: 24px; }}
  .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
  @media (max-width: 900px) {{ .grid-2 {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<header>
  <h1>{title}</h1>
  <p>Prepared for: {company} &nbsp;|&nbsp; Generated: {generated_at} &nbsp;|&nbsp; Classification: TLP:AMBER</p>
</header>
<div class="container">

  <div class="kpi-row">
    <div class="kpi"><div class="value">{total_sessions}</div><div class="label">Honeypot Sessions</div></div>
    <div class="kpi"><div class="value">{unique_ips}</div><div class="label">Unique Attacker IPs</div></div>
    <div class="kpi"><div class="value">{total_logins}</div><div class="label">Credential Attempts</div></div>
    <div class="kpi"><div class="value">{total_commands}</div><div class="label">Commands Captured</div></div>
  </div>

  <section>
    <h2>Top 10 Attacker Source IPs (Geolocation Enriched)</h2>
    <table>
      <tr><th>#</th><th>Source IP</th><th>Sessions</th><th>Country</th><th>City</th><th>ISP / ASN</th></tr>
      {geo_table_rows_html}
    </table>
    <img class="chart" src="data:image/png;base64,{top_ips_chart}" alt="Top attacker IPs chart"/>
  </section>

  <div class="grid-2">
    <section>
      <h2>Top Targeted Usernames</h2>
      <table>
        <tr><th>#</th><th>Username</th><th>Attempts</th></tr>
        {top_usernames_rows_html}
      </table>
    </section>
    <section>
      <h2>Top Targeted Passwords</h2>
      <table>
        <tr><th>#</th><th>Password</th><th>Attempts</th></tr>
        {top_passwords_rows_html}
      </table>
    </section>
  </div>

  <section>
    <h2>Top Username:Password Combinations</h2>
    <img class="chart" src="data:image/png;base64,{top_creds_chart}" alt="Top credential pairs chart"/>
  </section>

  <section>
    <h2>Brute-Force Trend Over Time</h2>
    <img class="chart" src="data:image/png;base64,{brute_force_chart}" alt="Brute force trend chart"/>
  </section>

  <section>
    <h2>Geolocation Heatmap Summary (Sessions by Country)</h2>
    <img class="chart" src="data:image/png;base64,{country_chart}" alt="Country heatmap chart"/>
  </section>

  <div class="grid-2">
    <section>
      <h2>Attack Classification Breakdown</h2>
      <table>
        <tr><th>Classification</th><th>Sessions</th></tr>
        {classification_rows_html}
      </table>
    </section>
    <section>
      <h2>Top Commands Executed Post-Authentication</h2>
      <table>
        <tr><th>#</th><th>Command</th><th>Occurrences</th></tr>
        {top_commands_rows_html}
      </table>
    </section>
  </div>

</div>
<footer>Generated automatically by Cloud Honeypot &amp; Attack Surface Monitor &mdash; report_generator.py &mdash; For authorized defensive security use only.</footer>
</body>
</html>
"""


def _rows_html(items, formatter):
    return "\n".join(formatter(i, item) for i, item in enumerate(items, start=1))


def generate_html_report(stats, geo_table_rows, settings, generated_at):
    cfg = settings.get("report_generator", {})
    title = cfg.get("report_title", "Cloud Honeypot & Attack Surface Monitor - Threat Intelligence Report")
    company = cfg.get("company_name", "Security Operations")

    country_counts = {}
    for row in geo_table_rows:
        country_counts[row["country"]] = country_counts.get(row["country"], 0) + row["sessions"]

    top_ips_chart = render_top_ips_chart(stats["top_source_ips"])
    top_creds_chart = render_top_credentials_chart(stats["top_credential_pairs"])
    brute_force_chart = render_brute_force_trend_chart(stats["brute_force_attempts_by_hour"])
    country_chart = render_country_heatmap_chart(country_counts)

    geo_rows_html = _rows_html(
        geo_table_rows,
        lambda i, r: f"<tr><td>{i}</td><td><code>{r['ip']}</code></td><td>{r['sessions']}</td>"
                     f"<td>{r['country']}</td><td>{r['city']}</td><td>{r['isp']} ({r['asn']})</td></tr>",
    )
    usernames_rows_html = _rows_html(
        stats["top_usernames"],
        lambda i, item: f"<tr><td>{i}</td><td><code>{item[0]}</code></td><td>{item[1]}</td></tr>",
    )
    passwords_rows_html = _rows_html(
        stats["top_passwords"],
        lambda i, item: f"<tr><td>{i}</td><td><code>{item[0]}</code></td><td>{item[1]}</td></tr>",
    )
    commands_rows_html = _rows_html(
        stats["top_commands"],
        lambda i, item: f"<tr><td>{i}</td><td><code>{item[0]}</code></td><td>{item[1]}</td></tr>",
    )
    classification_rows_html = "\n".join(
        f"<tr><td>{cls.replace('_', ' ').title()}</td><td>{count}</td></tr>"
        for cls, count in stats["attack_classification_breakdown"].items()
    )

    return HTML_TEMPLATE.format(
        title=title,
        company=company,
        generated_at=generated_at,
        total_sessions=stats["total_sessions"],
        unique_ips=stats["unique_source_ips"],
        total_logins=stats["total_login_attempts"],
        total_commands=stats["total_commands_executed"],
        geo_table_rows_html=geo_rows_html,
        top_ips_chart=top_ips_chart,
        top_usernames_rows_html=usernames_rows_html,
        top_passwords_rows_html=passwords_rows_html,
        top_creds_chart=top_creds_chart,
        brute_force_chart=brute_force_chart,
        country_chart=country_chart,
        classification_rows_html=classification_rows_html,
        top_commands_rows_html=commands_rows_html,
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def generate_full_report(settings_path=DEFAULT_SETTINGS_PATH, base_dir="."):
    settings = geo_load_json(os.path.join(base_dir, settings_path))
    lp_cfg = settings.get("log_parser", {})
    rg_cfg = settings.get("report_generator", {})

    input_path = os.path.join(base_dir, lp_cfg.get("input_log_path", DEFAULT_INPUT))
    normalized_output = os.path.join(base_dir, lp_cfg.get("output_normalized_path", DEFAULT_NORMALIZED_OUTPUT))
    elk_output = os.path.join(base_dir, lp_cfg.get("output_elk_path", DEFAULT_ELK_OUTPUT))

    enricher = GeoEnricher(settings, base_dir=base_dir)

    sessions, stats = run_log_parser(
        input_path=input_path,
        normalized_output=normalized_output,
        elk_output=elk_output,
        index_name=settings.get("elk_export", {}).get("index_name", "honeypot-events"),
    )

    all_ips = [s["src_ip"] for s in sessions]
    geo_lookup = enricher.enrich_many(all_ips)

    # Re-export ELK docs now that geo enrichment is available.
    from src.log_parser import build_elk_documents
    elk_docs = build_elk_documents(sessions, geo_lookup=geo_lookup,
                                    index_name=settings.get("elk_export", {}).get("index_name", "honeypot-events"))
    with open(elk_output, "w", encoding="utf-8") as fh:
        json.dump(elk_docs, fh, indent=2, default=str)

    geo_table_rows = build_geo_table_rows(stats, geo_lookup)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    html_report = generate_html_report(stats, geo_table_rows, settings, generated_at)
    markdown_report = generate_markdown_report(stats, geo_table_rows, settings, generated_at)

    html_path = os.path.join(base_dir, rg_cfg.get("output_html_path", "reports/attack_report.html"))
    md_path = os.path.join(base_dir, rg_cfg.get("output_markdown_path", "reports/attack_report.md"))

    os.makedirs(os.path.dirname(html_path) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(md_path) or ".", exist_ok=True)

    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_report)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(markdown_report)

    return {
        "html_path": html_path,
        "markdown_path": md_path,
        "elk_export_path": elk_output,
        "normalized_events_path": normalized_output,
        "stats": stats,
    }


def main():
    parser = argparse.ArgumentParser(description="Generate the Cloud Honeypot Attack Surface Monitor HTML/Markdown report")
    parser.add_argument("--settings", default=DEFAULT_SETTINGS_PATH)
    parser.add_argument("--base-dir", default=".")
    args = parser.parse_args()

    result = generate_full_report(settings_path=args.settings, base_dir=args.base_dir)

    print("Report generation complete.")
    print(f"  HTML report:        {result['html_path']}")
    print(f"  Markdown report:    {result['markdown_path']}")
    print(f"  ELK/Wazuh export:   {result['elk_export_path']}")
    print(f"  Normalized events:  {result['normalized_events_path']}")
    print(f"  Total sessions analyzed: {result['stats']['total_sessions']}")
    print(f"  Unique attacker IPs:     {result['stats']['unique_source_ips']}")


if __name__ == "__main__":
    main()
