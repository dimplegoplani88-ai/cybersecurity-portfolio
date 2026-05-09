# 🔴 Real-Time Port Monitor & Intrusion Detection System

Monitors active TCP connections every N seconds, detects anomalies in real time, fires alerts, and logs everything to JSON.

## What it detects
- **Suspicious ports** — Metasploit (4444), Back Orifice (31337), NetBus (12345), etc.
- **Port scan behavior** — single IP connecting to 10+ different ports
- **Connection spikes** — unusual surge in new connections within polling window
- **Unusual outbound** — ESTABLISHED connections to non-standard high ports

## Skills demonstrated
`Network monitoring` · `Anomaly detection` · `IDS concepts` · `Real-time alerting` · `Threat rules`

## Setup
```bash
python port_monitor.py
```

## Configuration
```python
MONITOR_INTERVAL_SEC  = 5   # polling frequency
CONN_SPIKE_THRESHOLD  = 10  # new conns/interval before alerting
SUSPICIOUS_PORTS = {4444: "Metasploit", ...}  # extend as needed
```

## Running continuously
```python
run_monitor(duration_sec=0)   # runs until Ctrl+C
```

## Output
- Console alerts with severity levels
- `ids_alerts.json` — persistent alert log for dashboard ingestion
