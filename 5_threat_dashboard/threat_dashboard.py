"""
Project 5: SOC Threat Intelligence Dashboard
Author: Dimple Goplani
Description: Aggregates findings from all other tools, enriches IPs with
             geolocation/threat intel lookups, and renders a full SOC dashboard
             as a standalone HTML file — no server needed.
Skills demonstrated: Threat intelligence, data aggregation, SOC workflows, visualization
"""

import json
import hashlib
import os
import random
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from typing import Optional


# ─────────────────────────────────────────────
# 1. DATA INGESTION — load outputs from other tools
# ─────────────────────────────────────────────

def load_json_safe(filepath: str) -> dict | list | None:
    if not os.path.exists(filepath):
        return None
    with open(filepath) as f:
        try:
            return json.load(f)
        except Exception:
            return None


def ingest_all_sources() -> dict:
    """
    Load findings from all other portfolio tools.
    Falls back to synthetic demo data if files don't exist.
    """
    sources = {
        "log_analyzer":    load_json_safe("../2_log_analyzer/findings.json"),
        "password_audit":  load_json_safe("../3_password_auditor/password_audit.json"),
        "ids_alerts":      load_json_safe("../4_port_monitor/ids_alerts.json"),
        "scan_results":    load_json_safe("../1_network_scanner/scan_results.json"),
    }

    # Use demo data for any missing source
    for key, val in sources.items():
        if val is None:
            sources[key] = generate_demo_data(key)

    return sources


# ─────────────────────────────────────────────
# 2. DEMO DATA GENERATOR (for standalone use)
# ─────────────────────────────────────────────

def generate_demo_data(source: str) -> dict | list:
    """Generate realistic demo data when real tool output isn't available."""
    random.seed(42)   # reproducible demo

    if source == "log_analyzer":
        return {
            "findings": [
                {"type": "BRUTE_FORCE_SSH",   "severity": "HIGH",     "source_ip": "45.33.32.156",  "description": "7 failed SSH logins targeting root, admin"},
                {"type": "WEB_SQLI_ATTEMPT",  "severity": "HIGH",     "source_ip": "198.51.100.5",  "description": "SQL injection in /index.php?id="},
                {"type": "WEB_TRAVERSAL",     "severity": "HIGH",     "source_ip": "198.51.100.5",  "description": "Directory traversal ../../../../etc/passwd"},
                {"type": "WEB_RECON_404_STORM","severity": "MEDIUM",  "source_ip": "203.0.113.10",  "description": "22 HTTP 404 errors — web scanner behavior"},
                {"type": "PRIVILEGE_ESCALATION","severity": "HIGH",   "source_ip": "localhost",     "description": "sudo chmod 777 /etc/passwd by user dimple"},
            ],
            "iocs": {
                "top_talkers": {"45.33.32.156": 7, "198.51.100.5": 12, "203.0.113.10": 22}
            }
        }

    if source == "ids_alerts":
        return [
            {"type": "PORT_SCAN_DETECTED",  "severity": "HIGH",   "source_ip": "10.0.0.50",    "timestamp": _ago(5),  "description": "Port scan from 10.0.0.50 across 14 ports"},
            {"type": "SUSPICIOUS_PORT",     "severity": "HIGH",   "source_ip": "192.168.1.99", "timestamp": _ago(12), "description": "Connection on port 4444 (Metasploit listener)"},
            {"type": "CONNECTION_SPIKE",    "severity": "MEDIUM", "source_ip": "multiple",     "timestamp": _ago(20), "description": "12 new connections in 5 seconds"},
            {"type": "UNUSUAL_OUTBOUND",    "severity": "LOW",    "source_ip": "192.168.1.10", "timestamp": _ago(30), "description": "Outbound to non-standard port 4567"},
        ]

    if source == "password_audit":
        return {
            "audits": [
                {"password_masked": "p*******d",  "grade": "F", "score": 10, "entropy_bits": 28.0, "crack_time": "Instantly"},
                {"password_masked": "P*******d",  "grade": "C", "score": 55, "entropy_bits": 52.3, "crack_time": "3 days"},
                {"password_masked": "X*************n", "grade": "A", "score": 95, "entropy_bits": 115.4, "crack_time": "Practically uncrackable"},
            ]
        }

    if source == "scan_results":
        return [
            {"ip": "127.0.0.1", "hostname": "localhost", "open_ports": [
                {"port": 22, "service": "SSH", "banner": "SSH-2.0-OpenSSH_8.4"},
                {"port": 80, "service": "HTTP", "banner": "HTTP/1.1 200 OK"},
            ]},
        ]

    return {}


def _ago(minutes: int) -> str:
    return (datetime.now() - timedelta(minutes=minutes)).isoformat()


# ─────────────────────────────────────────────
# 3. THREAT INTELLIGENCE ENRICHMENT
# ─────────────────────────────────────────────

# Simulated threat intel database
# In production: query AbuseIPDB, VirusTotal, Shodan APIs
THREAT_INTEL_DB = {
    "45.33.32.156":  {"reputation": "MALICIOUS", "category": "Brute Force", "country": "US", "asn": "AS63949"},
    "198.51.100.5":  {"reputation": "SUSPICIOUS","category": "Web Scanner", "country": "RU", "asn": "AS12345"},
    "203.0.113.10":  {"reputation": "SUSPICIOUS","category": "Recon",       "country": "CN", "asn": "AS4134"},
    "10.0.0.50":     {"reputation": "UNKNOWN",   "category": "Internal",    "country": "–",  "asn": "–"},
    "192.168.1.99":  {"reputation": "UNKNOWN",   "category": "Internal",    "country": "–",  "asn": "–"},
}

def enrich_ip(ip: str) -> dict:
    """
    Enrich an IP with threat intel.
    Real implementation: call AbuseIPDB / VirusTotal / Shodan here.
    """
    if ip in THREAT_INTEL_DB:
        return THREAT_INTEL_DB[ip]
    if ip.startswith(("192.168.", "10.", "172.")):
        return {"reputation": "INTERNAL", "category": "RFC1918", "country": "–", "asn": "–"}
    return {"reputation": "UNKNOWN", "category": "Unclassified", "country": "–", "asn": "–"}


# ─────────────────────────────────────────────
# 4. DASHBOARD HTML GENERATOR
# ─────────────────────────────────────────────

def build_dashboard(sources: dict, output_file: str = "soc_dashboard.html"):
    """Build a full SOC dashboard HTML from all ingested data."""

    # Aggregate all findings
    all_findings = []
    log_data = sources.get("log_analyzer", {})
    if isinstance(log_data, dict):
        all_findings += log_data.get("findings", [])

    ids_data = sources.get("ids_alerts", [])
    if isinstance(ids_data, list):
        all_findings += ids_data

    # Severity counts
    sev_counts = Counter(f.get("severity", "INFO") for f in all_findings)

    # Unique IPs
    all_ips = list({f.get("source_ip","") for f in all_findings
                    if f.get("source_ip","") not in ("","multiple","localhost")})
    enriched_ips = {ip: enrich_ip(ip) for ip in all_ips}

    # Password audit summary
    pwd_data   = sources.get("password_audit", {})
    pwd_audits = pwd_data.get("audits", []) if isinstance(pwd_data, dict) else []
    grade_counts = Counter(a["grade"] for a in pwd_audits)

    # Scan data
    scan_data  = sources.get("scan_results", [])
    total_open = sum(len(h.get("open_ports", [])) for h in scan_data) if isinstance(scan_data, list) else 0

    # Build findings table rows
    findings_rows = ""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings.sort(key=lambda x: severity_order.get(x.get("severity","LOW"), 9))

    for f in all_findings:
        sev   = f.get("severity","INFO")
        stype = f.get("type","–")
        src   = f.get("source_ip", f.get("user","–"))
        desc  = f.get("description","–")[:90]
        ts    = f.get("timestamp","–")[:19] if "timestamp" in f else "–"
        intel = enriched_ips.get(src, {})
        rep   = intel.get("reputation","–")
        rep_color = {"MALICIOUS":"#dc2626","SUSPICIOUS":"#ea580c","INTERNAL":"#3b82f6"}.get(rep,"#6b7280")

        sev_color = {"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#d97706","LOW":"#65a30d"}.get(sev,"#6b7280")
        findings_rows += f"""
        <tr>
          <td><span style="color:{sev_color};font-weight:700;font-size:.85em">{sev}</span></td>
          <td style="font-size:.85em">{stype}</td>
          <td style="font-family:monospace;font-size:.85em">{src}</td>
          <td style="font-size:.75em;color:{rep_color}">{rep}</td>
          <td style="font-size:.82em">{desc}</td>
          <td style="font-size:.75em;color:#64748b">{ts}</td>
        </tr>"""

    # IP intel rows
    ip_rows = ""
    for ip, intel in enriched_ips.items():
        rep = intel.get("reputation","–")
        rep_color = {"MALICIOUS":"#dc2626","SUSPICIOUS":"#ea580c","INTERNAL":"#3b82f6"}.get(rep,"#6b7280")
        ip_rows += f"""
        <tr>
          <td style="font-family:monospace">{ip}</td>
          <td><span style="color:{rep_color}">{rep}</span></td>
          <td>{intel.get('category','–')}</td>
          <td>{intel.get('country','–')}</td>
          <td>{intel.get('asn','–')}</td>
        </tr>"""

    # Password rows
    pwd_rows = ""
    grade_colors = {"A":"#22c55e","B":"#84cc16","C":"#eab308","D":"#f97316","F":"#dc2626"}
    for a in pwd_audits:
        g  = a.get("grade","–")
        gc = grade_colors.get(g,"#888")
        pwd_rows += f"""
        <tr>
          <td style="font-family:monospace">{a.get('password_masked','–')}</td>
          <td><span style="color:{gc};font-weight:700">{g}</span></td>
          <td>{a.get('score','–')}</td>
          <td>{a.get('entropy_bits','–')}</td>
          <td>{a.get('crack_time','–')}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Threat Intelligence Dashboard</title>
<style>
  :root {{
    --bg:       #0a0f1e;
    --surface:  #111827;
    --border:   #1e2d3d;
    --text:     #e2e8f0;
    --muted:    #64748b;
    --accent:   #38bdf8;
    --critical: #dc2626;
    --high:     #ea580c;
    --medium:   #d97706;
    --low:      #65a30d;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg);
          color: var(--text); min-height: 100vh; }}

  .topbar {{ background: var(--surface); border-bottom: 1px solid var(--border);
             padding: 14px 28px; display: flex; align-items: center; gap: 16px; }}
  .logo   {{ font-size: 1.3em; font-weight: 800; color: var(--accent);
             letter-spacing: -.02em; }}
  .subtitle {{ color: var(--muted); font-size: .85em; }}
  .live-badge {{ margin-left:auto; background:#1a2e1a; color:#22c55e;
                 border:1px solid #22c55e44; border-radius:20px;
                 padding:4px 12px; font-size:.8em; font-weight:600; }}

  .main {{ padding: 24px 28px; }}
  h2    {{ font-size: 1em; color: var(--accent); text-transform: uppercase;
           letter-spacing: .08em; margin: 28px 0 12px; }}

  .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px,1fr)); gap: 14px; }}
  .kpi      {{ background: var(--surface); border: 1px solid var(--border);
               border-radius: 10px; padding: 18px 16px; text-align: center; }}
  .kpi-num  {{ font-size: 2.4em; font-weight: 800; line-height: 1; }}
  .kpi-lbl  {{ font-size: .75em; color: var(--muted); margin-top: 6px; text-transform: uppercase; }}

  .panel    {{ background: var(--surface); border: 1px solid var(--border);
               border-radius: 10px; overflow: hidden; margin-bottom: 24px; }}
  .panel-hdr{{ padding: 12px 18px; border-bottom: 1px solid var(--border);
               font-size: .8em; color: var(--muted); text-transform: uppercase;
               letter-spacing: .06em; display: flex; justify-content: space-between; }}
  table     {{ width: 100%; border-collapse: collapse; }}
  th, td    {{ padding: 10px 18px; text-align: left; border-bottom: 1px solid var(--border)88; }}
  th        {{ font-size: .72em; color: var(--muted); text-transform: uppercase;
               letter-spacing: .06em; background: #0d1424; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover  {{ background: #ffffff06; }}

  .footer {{ padding: 20px 28px; color: var(--muted); font-size: .78em;
             border-top: 1px solid var(--border); text-align: center; }}
</style>
</head>
<body>

<div class="topbar">
  <div>
    <div class="logo">🛡 SOC DASHBOARD</div>
    <div class="subtitle">Threat Intelligence &amp; Security Operations Center</div>
  </div>
  <div class="live-badge">● LIVE</div>
</div>

<div class="main">

  <h2>Overview</h2>
  <div class="kpi-grid">
    <div class="kpi"><div class="kpi-num" style="color:var(--critical)">{sev_counts.get('CRITICAL',0)}</div><div class="kpi-lbl">Critical</div></div>
    <div class="kpi"><div class="kpi-num" style="color:var(--high)">{sev_counts.get('HIGH',0)}</div><div class="kpi-lbl">High</div></div>
    <div class="kpi"><div class="kpi-num" style="color:var(--medium)">{sev_counts.get('MEDIUM',0)}</div><div class="kpi-lbl">Medium</div></div>
    <div class="kpi"><div class="kpi-num" style="color:var(--low)">{sev_counts.get('LOW',0)}</div><div class="kpi-lbl">Low</div></div>
    <div class="kpi"><div class="kpi-num" style="color:var(--accent)">{len(all_findings)}</div><div class="kpi-lbl">Total Findings</div></div>
    <div class="kpi"><div class="kpi-num" style="color:#a78bfa">{len(all_ips)}</div><div class="kpi-lbl">Unique IPs</div></div>
    <div class="kpi"><div class="kpi-num" style="color:#f472b6">{total_open}</div><div class="kpi-lbl">Open Ports</div></div>
    <div class="kpi"><div class="kpi-num" style="color:#fb923c">{len(pwd_audits)}</div><div class="kpi-lbl">Pwd Audited</div></div>
  </div>

  <h2>Security Findings</h2>
  <div class="panel">
    <div class="panel-hdr">
      <span>All Alerts — sorted by severity</span>
      <span>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
    </div>
    <table>
      <tr><th>Severity</th><th>Type</th><th>Source IP</th><th>Intel</th><th>Description</th><th>Time</th></tr>
      {findings_rows or '<tr><td colspan="6" style="color:var(--muted);text-align:center;padding:20px">No findings.</td></tr>'}
    </table>
  </div>

  <h2>IP Threat Intelligence</h2>
  <div class="panel">
    <div class="panel-hdr"><span>Enriched IP Reputation</span><span>Source: Internal TI DB</span></div>
    <table>
      <tr><th>IP Address</th><th>Reputation</th><th>Category</th><th>Country</th><th>ASN</th></tr>
      {ip_rows or '<tr><td colspan="5" style="color:var(--muted);text-align:center;padding:20px">No IPs to enrich.</td></tr>'}
    </table>
  </div>

  <h2>Password Audit Results</h2>
  <div class="panel">
    <div class="panel-hdr"><span>Credential Strength Analysis</span></div>
    <table>
      <tr><th>Password</th><th>Grade</th><th>Score</th><th>Entropy (bits)</th><th>Est. Crack Time</th></tr>
      {pwd_rows or '<tr><td colspan="5" style="color:var(--muted);text-align:center;padding:20px">No data.</td></tr>'}
    </table>
  </div>

</div>

<div class="footer">
  SOC Dashboard — Dimple Goplani | Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
  Data sources: Log Analyzer · IDS Monitor · Password Auditor · Network Scanner
</div>

</body></html>"""

    with open(output_file, "w") as f:
        f.write(html)
    print(f"[*] Dashboard saved: {output_file}")
    return output_file


# ─────────────────────────────────────────────
# 5. MAIN
# ─────────────────────────────────────────────

def main():
    print("="*60)
    print("  SOC THREAT DASHBOARD v1.0 — Dimple Goplani")
    print("="*60)

    print("\n[*] Ingesting data from all tools...")
    sources = ingest_all_sources()

    for name, data in sources.items():
        size = len(data) if isinstance(data, list) else len(data.get("findings", data.get("audits", [])))
        print(f"    {name:<20} → {size} record(s)")

    print("\n[*] Enriching IPs with threat intel...")
    print("[*] Building SOC dashboard...")
    output = build_dashboard(sources, "soc_dashboard.html")

    print(f"\n[✓] Dashboard ready. Open in browser: {output}\n")


if __name__ == "__main__":
    main()
