# 📋 Security Log Analyzer & Threat Detector

Parses real SSH auth logs and Apache/Nginx HTTP access logs, detects threats automatically, and generates a dark-themed HTML threat report.

## What it detects
- **SSH Brute Force** — multiple failed logins from same IP (configurable threshold)
- **Web Recon / 404 Storms** — IP flooding with 404s (scanner behavior)
- **SQL Injection attempts** — pattern-matched URLs
- **Directory Traversal** — `../` patterns in HTTP requests
- **Privilege Escalation** — suspicious `sudo` command usage
- **IOC Extraction** — top external IPs across all logs

## Skills demonstrated
`Log parsing` · `Regex` · `Threat detection` · `IOC extraction` · `HTML reporting`

## Setup
```bash
pip install -r requirements.txt
python log_analyzer.py
```

## Usage with real logs
```python
# Point to your actual log files
auth_log = load_log_file("/var/log/auth.log")
http_log = load_log_file("/var/log/apache2/access.log")
```

## Output
- `findings.json` — structured threat findings
- `threat_report.html` — visual dashboard (open in browser)

## Adjusting thresholds
Edit these constants in the script:
```python
BRUTE_FORCE_THRESHOLD  = 5   # failed logins before flagging
BRUTE_FORCE_WINDOW_MIN = 10  # time window in minutes
```
