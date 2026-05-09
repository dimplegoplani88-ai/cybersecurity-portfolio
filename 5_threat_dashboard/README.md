# 📊 SOC Threat Intelligence Dashboard

The capstone project. Aggregates output from all 4 other tools, enriches IPs with threat intelligence, and renders a complete SOC analyst dashboard as a standalone HTML file.

## What it does
- **Ingests** findings from all 4 other tools automatically
- **Enriches IPs** with reputation, category, country, ASN (simulated; swap in AbuseIPDB API for real intel)
- **Renders** a dark-themed SOC dashboard with:
  - KPI tiles (Critical/High/Medium/Low/Total/Unique IPs)
  - Full findings table sorted by severity
  - IP threat intelligence table
  - Password audit results

## Skills demonstrated
`Threat intelligence` · `Data aggregation` · `SOC workflow` · `Security visualization` · `API integration (extensible)`

## Setup
```bash
# Run the other 4 tools first to generate real data, then:
python threat_dashboard.py
# Opens soc_dashboard.html — view in any browser
```

## Extending with real threat intel APIs
```python
import requests

def enrich_ip_abuseipdb(ip: str, api_key: str) -> dict:
    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90}
    )
    data = resp.json()["data"]
    return {
        "reputation": "MALICIOUS" if data["abuseConfidenceScore"] > 50 else "CLEAN",
        "category": data["usageType"],
        "country": data["countryCode"],
    }
```
