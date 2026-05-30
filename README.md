# 🛡 Cybersecurity Portfolio — Dimple Goplani

A collection of **9 Python cybersecurity tools** demonstrating SOC analyst skills:
network recon, log analysis, threat detection, cryptography, and security reporting.

## Projects

| # | Project | Skills | Run |
|---|---------|--------|-----|
| 1 | **Network Scanner** | Socket programming, threading, banner grabbing, risk assessment | `python network_scanner.py` |
| 2 | **Log Analyzer & Threat Detector** | Log parsing, regex, brute-force/SQLi/traversal detection, HTML report | `python log_analyzer.py` |
| 3 | **Password Auditor** | Entropy, hash analysis, crack-time estimation, secure generation | `python password_auditor.py` |
| 4 | **Real-Time Port Monitor / IDS** | Network monitoring, anomaly detection, real-time alerting | `python port_monitor.py` |
| 5 | **SOC Threat Dashboard** | Threat intel aggregation, IP enrichment, SOC visualization | `python threat_dashboard.py` |
| 6 | **Hash Identifier** | Hash fingerprinting, prefix/length detection, algorithm identification | `python hash_id.py <hash>` |
| 7 | **Caesar Cipher CLI** | Substitution cipher, brute-force, frequency analysis | `python caesar_cipher.py` |
| 8 | **Educational Keylogger** | Keyboard event capture, threading, defensive awareness | `python keylogger.py` |
| 9 | **Metadata Scrubber** | EXIF removal, privacy protection, image processing | `python metadata_scrubber.py` |

## Quick Start

```bash
git clone https://github.com/dimplegoplani88-ai/cybersecurity-portfolio
cd cybersecurity-portfolio
pip install -r requirements.txt

# Run any project:
cd 1_network_scanner  && python network_scanner.py
cd 2_log_analyzer     && python log_analyzer.py
cd 3_password_auditor && python password_auditor.py
cd 4_port_monitor     && python port_monitor.py
cd 5_threat_dashboard && python threat_dashboard.py
cd 6_hash_identifier  && python hash_id.py <hash>
cd 7_caesar_cipher    && python caesar_cipher.py encrypt "Hello" -s 13
cd 8_keylogger        && python keylogger.py
cd 9_metadata_scrubber && python metadata_scrubber.py photo.jpg --read-only
```

## How They Connect

```
1_network_scanner   → scan_results.json   ─┐
2_log_analyzer      → findings.json       ─┤→ 5_threat_dashboard → soc_dashboard.html
3_password_auditor  → password_audit.json ─┤
4_port_monitor      → ids_alerts.json     ─┘

6_hash_identifier   → pairs with 3_password_auditor (identify hash before cracking)
7_caesar_cipher     → intro to encryption concepts (pairs with cryptography learning)
9_metadata_scrubber → privacy hardening (pairs with recon/OSINT awareness)
```
## Portfolio Highlights

✔ Built 9 cybersecurity tools in Python

✔ Simulated SOC analyst workflows

✔ Automated threat detection and reporting

✔ Implemented network reconnaissance and monitoring

✔ Developed security-focused data analysis tools

✔ Practiced defensive security concepts and incident investigation
## Skills Demonstrated

- Network reconnaissance & port scanning
- Log analysis (SSH auth, Apache/Nginx)
- Threat detection (brute force, SQLi, traversal, port scan)
- Password security & cryptography
- Real-time intrusion detection
- Threat intelligence enrichment
- SOC dashboard & reporting
- Hash fingerprinting & algorithm identification
- Classical cryptography & cipher analysis
- Privacy metadata removal & image forensics
- Keyboard event monitoring (defensive awareness)

## Legal Notice

> These tools are for **authorized use only**. Only scan networks and systems
> you own or have explicit written permission to test. Unauthorized use is illegal.

## Author

**Dimple Goplani** | [LinkedIn](https://www.linkedin.com/in/dimplegoplani-61a9b3315)
BCA – Computational Science | Cygnet.One Data Engineer (2024–2025)
