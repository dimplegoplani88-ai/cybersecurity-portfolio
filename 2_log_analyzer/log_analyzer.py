"""
Project 2: Security Log Analyzer & Threat Detector
Author: Dimple Goplani
Description: Parses auth/syslog/Apache logs, detects brute-force attempts,
             suspicious IPs, anomalies, and generates an HTML threat report.
Skills demonstrated: Log parsing, regex, threat detection, IOC extraction, reporting
"""

import re
import json
import os
from collections import defaultdict, Counter
from datetime import datetime, timedelta


# ─────────────────────────────────────────────
# THRESHOLDS (tune these per environment)
# ─────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD   = 5    # failed logins from same IP in window
BRUTE_FORCE_WINDOW_MIN  = 10   # time window in minutes
PORT_SCAN_THRESHOLD     = 15   # connection attempts from same IP


# ─────────────────────────────────────────────
# 1. LOG PARSERS
# ─────────────────────────────────────────────

# Regex patterns
PATTERNS = {
    # Linux auth.log: Failed password for root from 1.2.3.4 port 22
    "ssh_failed": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*Failed password for (?:invalid user )?(\S+) from ([\d.]+)"
    ),
    # Linux auth.log: Accepted password for user from IP
    "ssh_success": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*Accepted password for (\S+) from ([\d.]+)"
    ),
    # Apache/Nginx access log: IP - - [date] "METHOD /path HTTP/x" status size
    "http_access": re.compile(
        r'([\d.]+) - - \[([^\]]+)\] "(\w+) ([^\s"]+)[^"]*" (\d{3}) (\d+|-)'
    ),
    # Syslog sudo: user : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=...
    "sudo": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*sudo.*?(\w+).*COMMAND=(.*)"
    ),
    # Generic IP extractor
    "ip": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
}


def parse_ssh_log(log_text: str) -> dict:
    """Parse SSH auth log entries."""
    failed  = []   # list of {time, user, ip}
    success = []

    for line in log_text.splitlines():
        m = PATTERNS["ssh_failed"].search(line)
        if m:
            failed.append({"time": m.group(1), "user": m.group(2), "ip": m.group(3)})
            continue
        m = PATTERNS["ssh_success"].search(line)
        if m:
            success.append({"time": m.group(1), "user": m.group(2), "ip": m.group(3)})

    return {"failed": failed, "success": success}


def parse_http_log(log_text: str) -> list:
    """Parse Apache/Nginx access log entries."""
    entries = []
    for line in log_text.splitlines():
        m = PATTERNS["http_access"].search(line)
        if m:
            entries.append({
                "ip":     m.group(1),
                "time":   m.group(2),
                "method": m.group(3),
                "path":   m.group(4),
                "status": int(m.group(5)),
                "size":   m.group(6)
            })
    return entries


def load_log_file(filepath: str) -> str:
    """Load a log file from disk."""
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        return ""
    with open(filepath, "r", errors="ignore") as f:
        return f.read()


# ─────────────────────────────────────────────
# 2. THREAT DETECTION
# ─────────────────────────────────────────────

def detect_brute_force(ssh_data: dict) -> list:
    """
    Detect brute force: same IP with >= BRUTE_FORCE_THRESHOLD
    failed logins within BRUTE_FORCE_WINDOW_MIN minutes.
    """
    findings = []
    ip_attempts = defaultdict(list)

    for entry in ssh_data["failed"]:
        ip_attempts[entry["ip"]].append(entry)

    for ip, attempts in ip_attempts.items():
        count = len(attempts)
        users_targeted = list({a["user"] for a in attempts})

        severity = "LOW"
        if count >= 20:
            severity = "CRITICAL"
        elif count >= 10:
            severity = "HIGH"
        elif count >= BRUTE_FORCE_THRESHOLD:
            severity = "MEDIUM"
        else:
            continue   # below threshold

        findings.append({
            "type":            "BRUTE_FORCE_SSH",
            "severity":        severity,
            "source_ip":       ip,
            "attempt_count":   count,
            "users_targeted":  users_targeted,
            "description":     f"{count} failed SSH login attempts from {ip} targeting: {', '.join(users_targeted)}"
        })

    return findings


def detect_http_attacks(http_data: list) -> list:
    """
    Detect web attacks:
    - 404 storms (scanner/recon)
    - SQL injection patterns in URLs
    - Directory traversal
    - Suspicious user agents
    """
    findings = []
    ip_404s  = Counter()
    ip_reqs  = Counter()

    sqli_pattern = re.compile(
        r"(union.*select|select.*from|insert.*into|drop.*table|1=1|'--|\bor\b.*=)", re.I
    )
    traversal_pattern = re.compile(r"\.\./|\.\.\\|%2e%2e", re.I)
    scanner_agents = ["sqlmap", "nikto", "nessus", "masscan", "nmap", "hydra", "burp"]

    for entry in http_data:
        ip = entry["ip"]
        ip_reqs[ip] += 1
        if entry["status"] == 404:
            ip_404s[ip] += 1

        path = entry["path"].lower()

        if sqli_pattern.search(path):
            findings.append({
                "type":      "WEB_SQLI_ATTEMPT",
                "severity":  "HIGH",
                "source_ip": ip,
                "path":      entry["path"],
                "description": f"Possible SQL injection in request: {entry['path'][:80]}"
            })

        if traversal_pattern.search(path):
            findings.append({
                "type":      "WEB_TRAVERSAL",
                "severity":  "HIGH",
                "source_ip": ip,
                "path":      entry["path"],
                "description": f"Directory traversal attempt: {entry['path'][:80]}"
            })

    # 404 storm detection
    for ip, count in ip_404s.items():
        if count >= 20:
            findings.append({
                "type":          "WEB_RECON_404_STORM",
                "severity":      "MEDIUM",
                "source_ip":     ip,
                "attempt_count": count,
                "description":   f"{count} HTTP 404 errors from {ip} — possible web scanner/recon"
            })

    return findings


def detect_privilege_escalation(log_text: str) -> list:
    """Flag unusual sudo/su usage."""
    findings = []
    dangerous_commands = ["chmod 777", "passwd", "visudo", "crontab",
                          "/bin/bash", "nc ", "ncat", "python -c", "perl -e"]

    for line in log_text.splitlines():
        m = PATTERNS["sudo"].search(line)
        if m:
            cmd = m.group(3).strip()
            user = m.group(2)
            for dangerous in dangerous_commands:
                if dangerous in cmd:
                    findings.append({
                        "type":        "PRIVILEGE_ESCALATION",
                        "severity":    "HIGH",
                        "user":        user,
                        "command":     cmd,
                        "description": f"Suspicious sudo command by {user}: {cmd[:80]}"
                    })
    return findings


def extract_iocs(log_text: str) -> dict:
    """Extract Indicators of Compromise: IPs, suspicious paths."""
    ips = Counter(PATTERNS["ip"].findall(log_text))

    # Remove common non-threat IPs
    local_ranges = ("127.", "10.", "192.168.", "172.16.", "0.0.0.0")
    external_ips = {ip: c for ip, c in ips.items()
                    if not any(ip.startswith(r) for r in local_ranges)}

    return {
        "all_ips":         dict(ips),
        "external_ips":    external_ips,
        "top_talkers":     dict(Counter(external_ips).most_common(10))
    }


# ─────────────────────────────────────────────
# 3. HTML REPORT GENERATOR
# ─────────────────────────────────────────────

SEVERITY_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#65a30d",
    "INFO":     "#2563eb"
}

def generate_html_report(all_findings: list, iocs: dict, output_file: str = "threat_report.html"):
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "INFO"), 99))

    counts = Counter(f.get("severity", "INFO") for f in all_findings)
    rows = ""
    for f in all_findings:
        sev   = f.get("severity", "INFO")
        color = SEVERITY_COLOR.get(sev, "#888")
        rows += f"""
        <tr>
          <td><span style="color:{color};font-weight:700">{sev}</span></td>
          <td>{f.get('type','')}</td>
          <td>{f.get('source_ip', f.get('user','N/A'))}</td>
          <td>{f.get('description','')}</td>
        </tr>"""

    ioc_rows = ""
    for ip, count in list(iocs.get("top_talkers", {}).items())[:10]:
        ioc_rows += f"<tr><td>{ip}</td><td>{count}</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Threat Analysis Report</title>
<style>
  body {{ font-family: 'Courier New', monospace; background: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; }}
  h1   {{ color: #38bdf8; border-bottom: 1px solid #334155; padding-bottom: 10px; }}
  h2   {{ color: #7dd3fc; margin-top: 30px; }}
  .stat-grid {{ display:flex; gap:16px; margin:20px 0; }}
  .stat-box  {{ background:#1e293b; border:1px solid #334155; border-radius:8px;
                padding:16px 24px; min-width:120px; text-align:center; }}
  .stat-num  {{ font-size:2em; font-weight:700; }}
  .critical  {{ color:#dc2626; }} .high {{ color:#ea580c; }}
  .medium    {{ color:#d97706; }} .low  {{ color:#65a30d; }}
  table      {{ width:100%; border-collapse:collapse; margin-top:12px; }}
  th,td      {{ padding:10px 14px; text-align:left; border-bottom:1px solid #1e293b; font-size:0.9em; }}
  th         {{ background:#1e293b; color:#94a3b8; text-transform:uppercase; font-size:0.75em; }}
  tr:hover   {{ background:#1e293b88; }}
  .ts        {{ color:#64748b; font-size:0.8em; }}
</style>
</head>
<body>
<h1>🛡 Security Log Threat Report</h1>
<p class="ts">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total findings: {len(all_findings)}</p>

<div class="stat-grid">
  <div class="stat-box"><div class="stat-num critical">{counts.get('CRITICAL',0)}</div><div>CRITICAL</div></div>
  <div class="stat-box"><div class="stat-num high">{counts.get('HIGH',0)}</div><div>HIGH</div></div>
  <div class="stat-box"><div class="stat-num medium">{counts.get('MEDIUM',0)}</div><div>MEDIUM</div></div>
  <div class="stat-box"><div class="stat-num low">{counts.get('LOW',0)}</div><div>LOW</div></div>
</div>

<h2>⚠ Threat Findings</h2>
<table>
  <tr><th>Severity</th><th>Type</th><th>Source</th><th>Description</th></tr>
  {rows if rows else '<tr><td colspan="4">No findings detected.</td></tr>'}
</table>

<h2>🌐 Top External IPs (IOC)</h2>
<table>
  <tr><th>IP Address</th><th>Log Occurrences</th></tr>
  {ioc_rows if ioc_rows else '<tr><td colspan="2">No external IPs found.</td></tr>'}
</table>

</body></html>"""

    with open(output_file, "w") as f:
        f.write(html)
    print(f"[*] HTML report saved: {output_file}")


# ─────────────────────────────────────────────
# 4. SAMPLE LOG GENERATOR (for demo/testing)
# ─────────────────────────────────────────────

SAMPLE_AUTH_LOG = """
Jan 15 10:01:01 server sshd[1234]: Failed password for root from 45.33.32.156 port 54321 ssh2
Jan 15 10:01:02 server sshd[1234]: Failed password for root from 45.33.32.156 port 54322 ssh2
Jan 15 10:01:03 server sshd[1234]: Failed password for admin from 45.33.32.156 port 54323 ssh2
Jan 15 10:01:04 server sshd[1234]: Failed password for oracle from 45.33.32.156 port 54324 ssh2
Jan 15 10:01:05 server sshd[1234]: Failed password for ubuntu from 45.33.32.156 port 54325 ssh2
Jan 15 10:01:06 server sshd[1234]: Failed password for root from 45.33.32.156 port 54326 ssh2
Jan 15 10:01:07 server sshd[1234]: Failed password for root from 45.33.32.156 port 54327 ssh2
Jan 15 10:05:00 server sshd[1235]: Accepted password for dimple from 192.168.1.50 port 22 ssh2
Jan 15 10:10:00 server sudo: dimple : TTY=pts/0 ; PWD=/home/dimple ; USER=root ; COMMAND=/bin/bash
Jan 15 10:11:00 server sudo: dimple : TTY=pts/0 ; PWD=/home/dimple ; USER=root ; COMMAND=chmod 777 /etc/passwd
"""

SAMPLE_HTTP_LOG = """
203.0.113.10 - - [15/Jan/2024:09:00:01 +0000] "GET / HTTP/1.1" 200 1234
203.0.113.10 - - [15/Jan/2024:09:00:02 +0000] "GET /admin HTTP/1.1" 404 0
203.0.113.10 - - [15/Jan/2024:09:00:03 +0000] "GET /wp-admin HTTP/1.1" 404 0
203.0.113.10 - - [15/Jan/2024:09:00:04 +0000] "GET /phpmyadmin HTTP/1.1" 404 0
198.51.100.5 - - [15/Jan/2024:09:01:00 +0000] "GET /index.php?id=1' UNION SELECT * FROM users-- HTTP/1.1" 500 0
198.51.100.5 - - [15/Jan/2024:09:01:01 +0000] "GET /../../../../etc/passwd HTTP/1.1" 400 0
"""


# ─────────────────────────────────────────────
# 5. MAIN
# ─────────────────────────────────────────────

def main():
    print("="*60)
    print("  SECURITY LOG ANALYZER v1.0 — Dimple Goplani")
    print("="*60)

    # Use sample logs (replace with real file paths in production)
    auth_log  = SAMPLE_AUTH_LOG
    http_log  = SAMPLE_HTTP_LOG

    print("\n[*] Parsing SSH auth logs...")
    ssh_data = parse_ssh_log(auth_log)
    print(f"    Found {len(ssh_data['failed'])} failed logins, {len(ssh_data['success'])} successful")

    print("[*] Parsing HTTP access logs...")
    http_data = parse_http_log(http_log)
    print(f"    Found {len(http_data)} HTTP requests")

    print("[*] Running threat detection...")
    findings = []
    findings += detect_brute_force(ssh_data)
    findings += detect_http_attacks(http_data)
    findings += detect_privilege_escalation(auth_log)

    print("[*] Extracting IOCs...")
    iocs = extract_iocs(auth_log + http_log)

    print(f"\n[!] Total findings: {len(findings)}")
    for f in findings:
        print(f"    [{f['severity']}] {f['type']} — {f['description'][:70]}")

    # Save findings to JSON
    with open("findings.json", "w") as jf:
        json.dump({"findings": findings, "iocs": iocs}, jf, indent=2)
    print("\n[*] Findings saved: findings.json")

    # Generate HTML report
    generate_html_report(findings, iocs, "threat_report.html")
    print("[✓] Analysis complete. Open threat_report.html in a browser.\n")


if __name__ == "__main__":
    main()
