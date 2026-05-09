"""
Project 1: Network Scanner & Host Discovery Tool
Author: Dimple Goplani
Description: Scans a network range, discovers live hosts, checks open ports,
             grabs service banners, and exports results to CSV/JSON.
Skills demonstrated: Socket programming, threading, network recon, reporting
"""

import socket
import subprocess
import platform
import csv
import json
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                443, 445, 3306, 3389, 5900, 8080, 8443, 9200]

BANNER_TIMEOUT = 2      # seconds to wait for service banner
PING_TIMEOUT   = 1      # seconds for ping
SCAN_THREADS   = 50     # parallel port scan threads


# ─────────────────────────────────────────────
# 1. PING SWEEP — find live hosts
# ─────────────────────────────────────────────
def ping_host(ip: str) -> bool:
    """Returns True if host responds to ping."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_flag = "-w" if platform.system().lower() == "windows" else "-W"
    cmd = ["ping", param, "1", timeout_flag, str(PING_TIMEOUT), ip]
    try:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=3)
        return result.returncode == 0
    except Exception:
        return False


def ping_sweep(base_ip: str, start: int = 1, end: int = 254) -> list:
    """
    Ping sweep a /24 subnet.
    Example: base_ip="192.168.1", start=1, end=10
    """
    print(f"\n[*] Starting ping sweep on {base_ip}.{start} → {base_ip}.{end}")
    live_hosts = []
    lock = threading.Lock()

    def check(i):
        ip = f"{base_ip}.{i}"
        if ping_host(ip):
            with lock:
                live_hosts.append(ip)
            print(f"  [+] Host UP: {ip}")

    with ThreadPoolExecutor(max_workers=30) as ex:
        ex.map(check, range(start, end + 1))

    print(f"[*] Ping sweep complete. {len(live_hosts)} host(s) found.\n")
    return sorted(live_hosts)


# ─────────────────────────────────────────────
# 2. PORT SCANNER
# ─────────────────────────────────────────────
def scan_port(ip: str, port: int) -> dict | None:
    """
    Try to connect to a port. If open, attempt banner grab.
    Returns dict with port info or None if closed.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(BANNER_TIMEOUT)
            if s.connect_ex((ip, port)) == 0:
                # Port is open — try banner grab
                banner = ""
                try:
                    # Send a generic probe for HTTP, grab whatever comes back
                    if port in [80, 8080, 8443]:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode(errors="ignore").strip()
                    banner = banner[:100]   # truncate
                except Exception:
                    pass

                service = get_service_name(port)
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner
                }
    except Exception:
        pass
    return None


def get_service_name(port: int) -> str:
    """Map port number to common service name."""
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
        139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 3389: "RDP", 5900: "VNC",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch"
    }
    try:
        return services.get(port, socket.getservbyport(port))
    except Exception:
        return "Unknown"


def scan_host(ip: str, ports: list = None) -> dict:
    """Scan all given ports on a single host. Returns structured result."""
    if ports is None:
        ports = COMMON_PORTS

    print(f"  [*] Scanning {ip} ({len(ports)} ports)...")
    open_ports = []

    with ThreadPoolExecutor(max_workers=SCAN_THREADS) as ex:
        futures = {ex.submit(scan_port, ip, p): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                print(f"      [+] {ip}:{result['port']}/tcp  OPEN  "
                      f"({result['service']})  {result['banner'][:50]}")

    # Resolve hostname
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = "N/A"

    return {
        "ip": ip,
        "hostname": hostname,
        "open_ports": sorted(open_ports, key=lambda x: x["port"]),
        "scan_time": datetime.now().isoformat()
    }


# ─────────────────────────────────────────────
# 3. RISK ASSESSMENT
# ─────────────────────────────────────────────
RISKY_PORTS = {
    23:   "CRITICAL — Telnet sends credentials in plaintext",
    21:   "HIGH — FTP sends credentials in plaintext",
    445:  "HIGH — SMB; common ransomware vector (EternalBlue)",
    3389: "HIGH — RDP exposed; common brute-force target",
    5900: "HIGH — VNC exposed; often misconfigured",
    135:  "MEDIUM — RPC; Windows exploit surface",
    139:  "MEDIUM — NetBIOS; information leakage risk",
    3306: "MEDIUM — MySQL exposed to network (should be localhost only)",
    9200: "MEDIUM — Elasticsearch exposed; often no auth by default",
}

def assess_risk(scan_results: list) -> list:
    """Tag open ports with risk flags."""
    findings = []
    for host in scan_results:
        for port_info in host["open_ports"]:
            p = port_info["port"]
            if p in RISKY_PORTS:
                findings.append({
                    "ip": host["ip"],
                    "port": p,
                    "service": port_info["service"],
                    "risk": RISKY_PORTS[p]
                })
    return findings


# ─────────────────────────────────────────────
# 4. REPORTING
# ─────────────────────────────────────────────
def export_csv(scan_results: list, filename: str = "scan_results.csv"):
    rows = []
    for host in scan_results:
        if not host["open_ports"]:
            rows.append({
                "ip": host["ip"], "hostname": host["hostname"],
                "port": "", "service": "", "banner": "",
                "scan_time": host["scan_time"]
            })
        for p in host["open_ports"]:
            rows.append({
                "ip": host["ip"], "hostname": host["hostname"],
                "port": p["port"], "service": p["service"],
                "banner": p["banner"], "scan_time": host["scan_time"]
            })

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"[*] CSV report saved: {filename}")


def export_json(scan_results: list, filename: str = "scan_results.json"):
    with open(filename, "w") as f:
        json.dump(scan_results, f, indent=2)
    print(f"[*] JSON report saved: {filename}")


def print_summary(scan_results: list, risk_findings: list):
    print("\n" + "="*60)
    print("  SCAN SUMMARY")
    print("="*60)
    total_open = sum(len(h["open_ports"]) for h in scan_results)
    print(f"  Hosts scanned  : {len(scan_results)}")
    print(f"  Total open ports: {total_open}")
    print(f"  Risk findings  : {len(risk_findings)}")

    if risk_findings:
        print("\n  ⚠  RISK FLAGS:")
        for f in risk_findings:
            print(f"     {f['ip']}:{f['port']} ({f['service']}) — {f['risk']}")
    print("="*60 + "\n")


# ─────────────────────────────────────────────
# 5. MAIN — Demo / Entry point
# ─────────────────────────────────────────────
def main():
    print("="*60)
    print("  NETWORK SCANNER v1.0 — Dimple Goplani")
    print("  For authorized use on networks you own/have permission to scan")
    print("="*60)

    # ── DEMO MODE: scan localhost only ──
    # To scan a real subnet, replace with:
    #   live_hosts = ping_sweep("192.168.1", start=1, end=254)
    #   results = [scan_host(ip) for ip in live_hosts]

    print("\n[*] Demo mode: scanning localhost (127.0.0.1)")
    target_ips = ["127.0.0.1"]

    results = []
    for ip in target_ips:
        result = scan_host(ip, ports=COMMON_PORTS)
        results.append(result)

    risk_findings = assess_risk(results)
    print_summary(results, risk_findings)

    # Export
    export_json(results, "scan_results.json")
    export_csv(results,  "scan_results.csv")

    print("[✓] Scan complete.\n")


if __name__ == "__main__":
    main()
