"""
Project 4: Real-Time Port Monitor & Intrusion Detection System (IDS)
Author: Dimple Goplani
Description: Monitors network connections in real time, detects anomalies,
             alerts on suspicious activity, and logs everything to a timeline.
Skills demonstrated: Network monitoring, anomaly detection, alerting, IDS concepts
"""

import socket
import json
import time
import os
import subprocess
import platform
from datetime import datetime
from collections import defaultdict, deque


# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
MONITOR_INTERVAL_SEC   = 5      # how often to poll connections
ALERT_LOG_FILE         = "ids_alerts.json"
CONNECTION_LOG_FILE    = "connection_log.json"
MAX_HISTORY            = 500    # max events to keep in memory

# Thresholds
CONN_SPIKE_THRESHOLD   = 10     # new connections per interval before alerting
SYN_FLOOD_THRESHOLD    = 20     # SYN_SENT states from one IP

# Known suspicious ports (unauthorized services)
SUSPICIOUS_PORTS = {
    4444:  "Metasploit default listener",
    1337:  "Common backdoor port",
    31337: "Elite/Back Orifice backdoor",
    5555:  "Android ADB / common RAT port",
    6666:  "IRC / common malware C2",
    6667:  "IRC (unencrypted)",
    8888:  "Common C2 / Jupyter (if unexpected)",
    9999:  "Common backdoor port",
    12345: "NetBus RAT",
    27374: "SubSeven RAT",
}

# Legitimate services we don't want to alert on
WHITELIST_PORTS = {80, 443, 22, 53, 123, 8080, 3000, 5000}


# ─────────────────────────────────────────────
# 1. CONNECTION READER
# ─────────────────────────────────────────────

def get_active_connections() -> list:
    """
    Read active TCP connections using netstat.
    Works on Linux, macOS, and Windows.
    Returns list of connection dicts.
    """
    connections = []
    sys = platform.system().lower()

    try:
        if sys == "windows":
            cmd = ["netstat", "-n", "-o"]
        else:
            cmd = ["netstat", "-tn"]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        lines = result.stdout.splitlines()

        for line in lines:
            line = line.strip()
            if not line or line.startswith("Active") or line.startswith("Proto"):
                continue

            parts = line.split()
            if len(parts) < 4:
                continue

            try:
                proto = parts[0].lower()
                local_addr  = parts[1]
                remote_addr = parts[2]
                state       = parts[3] if len(parts) > 3 else "UNKNOWN"

                local_ip,  local_port  = parse_addr(local_addr)
                remote_ip, remote_port = parse_addr(remote_addr)

                connections.append({
                    "proto":       proto,
                    "local_ip":    local_ip,
                    "local_port":  local_port,
                    "remote_ip":   remote_ip,
                    "remote_port": remote_port,
                    "state":       state,
                    "timestamp":   datetime.now().isoformat()
                })
            except Exception:
                continue

    except Exception as e:
        print(f"[!] Error reading connections: {e}")

    return connections


def parse_addr(addr: str) -> tuple:
    """Parse IP:port or [IPv6]:port into (ip, port)."""
    if addr.startswith("["):                  # IPv6
        parts = addr.rsplit(":", 1)
        return parts[0].strip("[]"), int(parts[1]) if parts[1].isdigit() else 0
    elif addr.count(":") == 1:                # IPv4
        ip, port = addr.rsplit(":", 1)
        return ip, int(port) if port.isdigit() else 0
    return addr, 0


# ─────────────────────────────────────────────
# 2. ANOMALY DETECTION ENGINE
# ─────────────────────────────────────────────

class IDSEngine:
    def __init__(self):
        self.prev_connections  = []
        self.alerts            = []
        self.connection_history = deque(maxlen=MAX_HISTORY)
        self.ip_connection_count = defaultdict(int)
        self.scan_counter       = defaultdict(int)  # IP → unique ports contacted

    def analyze(self, current_connections: list) -> list:
        """Compare current snapshot against previous. Return new alerts."""
        new_alerts = []
        current_set = {self._conn_key(c) for c in current_connections}
        prev_set    = {self._conn_key(c) for c in self.prev_connections}

        # New connections since last poll
        new_conn_keys = current_set - prev_set
        new_conns = [c for c in current_connections
                     if self._conn_key(c) in new_conn_keys]

        # --- Rule 1: Suspicious port detection ---
        for conn in new_conns:
            lp = conn["local_port"]
            rp = conn["remote_port"]

            for port in [lp, rp]:
                if port in SUSPICIOUS_PORTS and port not in WHITELIST_PORTS:
                    new_alerts.append(self._make_alert(
                        "SUSPICIOUS_PORT",
                        "HIGH",
                        conn["remote_ip"],
                        f"Connection on known malicious port {port} "
                        f"({SUSPICIOUS_PORTS[port]}) — {conn['remote_ip']}:{port}",
                        conn
                    ))

        # --- Rule 2: SYN flood / port scan detection ---
        remote_ip_ports = defaultdict(set)
        for conn in current_connections:
            if conn["remote_ip"] not in ("0.0.0.0", "127.0.0.1", "::"):
                remote_ip_ports[conn["remote_ip"]].add(conn["remote_port"])

        for ip, ports in remote_ip_ports.items():
            if len(ports) >= 10:   # same IP contacting 10+ different ports
                new_alerts.append(self._make_alert(
                    "PORT_SCAN_DETECTED",
                    "HIGH",
                    ip,
                    f"Possible port scan: {ip} has connections to "
                    f"{len(ports)} different ports: {sorted(ports)[:10]}",
                    {}
                ))

        # --- Rule 3: Connection spike ---
        if len(new_conns) >= CONN_SPIKE_THRESHOLD:
            new_alerts.append(self._make_alert(
                "CONNECTION_SPIKE",
                "MEDIUM",
                "multiple",
                f"Unusual spike: {len(new_conns)} new connections in "
                f"{MONITOR_INTERVAL_SEC}s (threshold: {CONN_SPIKE_THRESHOLD})",
                {}
            ))

        # --- Rule 4: Outbound to non-standard ports ---
        for conn in new_conns:
            rp = conn["remote_port"]
            if (conn["state"] == "ESTABLISHED" and
                    conn["remote_ip"] not in ("0.0.0.0", "127.0.0.1") and
                    rp not in WHITELIST_PORTS and
                    rp > 1024 and rp < 65000 and
                    rp not in SUSPICIOUS_PORTS):
                # Only flag if it looks like unusual outbound
                if rp in range(4000, 5000) or rp in range(8000, 9000):
                    new_alerts.append(self._make_alert(
                        "UNUSUAL_OUTBOUND",
                        "LOW",
                        conn["remote_ip"],
                        f"Outbound connection to non-standard port "
                        f"{conn['remote_ip']}:{rp}",
                        conn
                    ))

        self.prev_connections = current_connections
        self.alerts.extend(new_alerts)
        return new_alerts

    def _conn_key(self, conn: dict) -> str:
        return f"{conn['local_ip']}:{conn['local_port']}-{conn['remote_ip']}:{conn['remote_port']}"

    def _make_alert(self, alert_type: str, severity: str,
                    source_ip: str, description: str, conn: dict) -> dict:
        alert = {
            "id":          len(self.alerts) + 1,
            "timestamp":   datetime.now().isoformat(),
            "type":        alert_type,
            "severity":    severity,
            "source_ip":   source_ip,
            "description": description,
            "connection":  conn
        }
        return alert


# ─────────────────────────────────────────────
# 3. ALERTING
# ─────────────────────────────────────────────

SEVERITY_PREFIX = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH":     "🟠 HIGH    ",
    "MEDIUM":   "🟡 MEDIUM  ",
    "LOW":      "🟢 LOW     ",
}

def print_alert(alert: dict):
    prefix = SEVERITY_PREFIX.get(alert["severity"], "⚪ INFO    ")
    ts     = alert["timestamp"][11:19]   # HH:MM:SS
    print(f"  [{ts}] {prefix} | {alert['type']:<30} | {alert['description'][:60]}")


def save_alerts(alerts: list, filepath: str = ALERT_LOG_FILE):
    """Append alerts to JSON file."""
    existing = []
    if os.path.exists(filepath):
        with open(filepath) as f:
            try:
                existing = json.load(f)
            except Exception:
                existing = []
    existing.extend(alerts)
    with open(filepath, "w") as f:
        json.dump(existing, f, indent=2)


# ─────────────────────────────────────────────
# 4. STATISTICS
# ─────────────────────────────────────────────

def print_connection_stats(connections: list):
    """Print a summary of current connections."""
    state_counts = defaultdict(int)
    remote_ips   = defaultdict(int)

    for conn in connections:
        state_counts[conn["state"]] += 1
        if conn["remote_ip"] not in ("0.0.0.0", "127.0.0.1", "::", ""):
            remote_ips[conn["remote_ip"]] += 1

    print(f"\n  Active connections: {len(connections)}")
    for state, count in sorted(state_counts.items(), key=lambda x: -x[1]):
        print(f"    {state:<20} {count:>4}")

    if remote_ips:
        top = sorted(remote_ips.items(), key=lambda x: -x[1])[:5]
        print(f"\n  Top remote IPs:")
        for ip, count in top:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = ""
            print(f"    {ip:<20} {count:>3} conn  {hostname}")


# ─────────────────────────────────────────────
# 5. MONITOR LOOP
# ─────────────────────────────────────────────

def run_monitor(duration_sec: int = 60, interval: int = MONITOR_INTERVAL_SEC):
    """
    Run the IDS monitor for a given duration.
    Set duration_sec=0 to run indefinitely (Ctrl+C to stop).
    """
    print("="*65)
    print("  REAL-TIME PORT MONITOR & IDS — Dimple Goplani")
    print(f"  Polling every {interval}s | Alerts → {ALERT_LOG_FILE}")
    print("="*65)
    print("  Press Ctrl+C to stop.\n")

    engine      = IDSEngine()
    total_alerts = 0
    iterations  = 0
    start_time  = time.time()

    try:
        while True:
            elapsed = time.time() - start_time
            if duration_sec > 0 and elapsed >= duration_sec:
                break

            iterations += 1
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Poll #{iterations}")

            connections = get_active_connections()
            print_connection_stats(connections)

            alerts = engine.analyze(connections)
            if alerts:
                print(f"\n  ⚠  {len(alerts)} new alert(s):")
                for alert in alerts:
                    print_alert(alert)
                save_alerts(alerts)
                total_alerts += len(alerts)
            else:
                print("  ✓  No anomalies detected.")

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\n[*] Monitor stopped by user.")

    print(f"\n{'='*65}")
    print(f"  Session summary: {iterations} polls, {total_alerts} total alerts")
    print(f"  Alert log: {ALERT_LOG_FILE}")
    print(f"{'='*65}\n")


# ─────────────────────────────────────────────
# 6. MAIN
# ─────────────────────────────────────────────

def main():
    # Run for 30 seconds in demo mode, then exit
    # Change to run_monitor(duration_sec=0) for continuous monitoring
    run_monitor(duration_sec=30, interval=5)


if __name__ == "__main__":
    main()
