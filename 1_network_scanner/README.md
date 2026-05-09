# 🔍 Network Scanner & Host Discovery Tool

A Python-based network reconnaissance tool that performs ping sweeps, port scanning, banner grabbing, and risk assessment — then exports results to CSV and JSON.

## What it does
- **Ping sweep** a subnet to find live hosts (multi-threaded)
- **Port scan** common TCP ports with configurable thread count
- **Banner grab** from open services (HTTP headers, SSH version, etc.)
- **Risk assessment** — flags dangerous open ports (Telnet, RDP, SMB, etc.)
- **Export reports** to CSV and JSON

## Skills demonstrated
`Socket programming` · `Multi-threading` · `Network recon` · `Risk assessment` · `Reporting`

## Setup
```bash
pip install -r requirements.txt
python network_scanner.py
```

## Usage
```python
# Scan a single host
result = scan_host("192.168.1.1", ports=COMMON_PORTS)

# Ping sweep a subnet (requires permission!)
live = ping_sweep("192.168.1", start=1, end=254)
results = [scan_host(ip) for ip in live]
```

> ⚠️ Only scan networks you own or have explicit written permission to scan.

## Sample Output
```
[+] Host UP: 192.168.1.1
[+] 192.168.1.1:22/tcp  OPEN  (SSH)   SSH-2.0-OpenSSH_8.4
[+] 192.168.1.1:80/tcp  OPEN  (HTTP)  HTTP/1.1 200 OK

RISK FLAGS:
  192.168.1.1:23 (Telnet) — CRITICAL: sends credentials in plaintext
```
