# 🛡 Cybersecurity Portfolio — Dimple Goplani

A collection of 5 Python cybersecurity tools demonstrating SOC analyst skills:
network recon, log analysis, threat detection, and security reporting.

## Projects

| # | Project | Skills | Run |
|---|---------|--------|-----|
| 1 | **Network Scanner** | Socket programming, threading, banner grabbing, risk assessment | `python network_scanner.py` |
| 2 | **Log Analyzer & Threat Detector** | Log parsing, regex, brute-force/SQLi/traversal detection, HTML report | `python log_analyzer.py` |
| 3 | **Password Auditor** | Entropy, hash analysis, crack-time estimation, secure generation | `python password_auditor.py` |
| 4 | **Real-Time Port Monitor / IDS** | Network monitoring, anomaly detection, real-time alerting | `python port_monitor.py` |
| 5 | **SOC Threat Dashboard** | Threat intel aggregation, IP enrichment, SOC visualization | `python threat_dashboard.py` |

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/cybersecurity-portfolio
cd cybersecurity-portfolio

# No pip install needed — standard library only
# Run any project:
cd 1_network_scanner && python network_scanner.py
cd 2_log_analyzer    && python log_analyzer.py
cd 3_password_auditor && python password_auditor.py
cd 4_port_monitor    && python port_monitor.py
cd 5_threat_dashboard && python threat_dashboard.py
```

## How they connect

```
1_network_scanner  → scan_results.json  ─┐
2_log_analyzer     → findings.json      ─┤→ 5_threat_dashboard → soc_dashboard.html
3_password_auditor → password_audit.json─┤
4_port_monitor     → ids_alerts.json    ─┘
```

Run tools 1–4 first, then run tool 5 to see the unified SOC dashboard.

## Skills demonstrated

- Network reconnaissance & port scanning
- Log analysis (SSH auth, Apache/Nginx)
- Threat detection (brute force, SQLi, traversal, port scan, suspicious ports)
- Password security & cryptography
- Real-time intrusion detection
- Threat intelligence enrichment
- SOC dashboard & reporting

## Legal notice

> These tools are for **authorized use only**. Only scan networks and systems
> you own or have explicit written permission to test.

## Author

**Dimple Goplani** | [LinkedIn](https://www.linkedin.com/in/dimplegoplani-61a9b3315)
BCA – Computational Science | Cygnet.One Data Engineer (2024–2025)
