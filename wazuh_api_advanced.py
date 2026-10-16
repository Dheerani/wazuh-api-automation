#!/usr/bin/env python3
import requests
import urllib3
import csv
from datetime import datetime, timedelta

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_URL = "https://localhost:55000"
USER = "wazuh"
PASSWORD = "wazuh"

# ============================================================
# AUTH
# ============================================================
def get_token():
    r = requests.post(
        f"{API_URL}/security/user/authenticate",
        auth=(USER, PASSWORD), verify=False
    )
    if r.status_code != 200:
        print(f"❌ Auth failed: {r.status_code}")
        return None
    return r.json()["data"]["token"]

def api_get(token, endpoint):
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{API_URL}{endpoint}", headers=headers, verify=False)
    return r.json()

# ============================================================
# FEATURE 1: Fetch alerts (last N days)
# ============================================================
def fetch_alerts(token, days=7, min_level=10, limit=500):
    """Fetch alerts from last N days with min level."""
    endpoint = f"/alerts?limit={limit}&sort=-timestamp&q=rule.level>={min_level}"    
    result = api_get(token, endpoint)
    alerts = result.get("data", {}).get("affected_items", [])
    print(f"📥 Fetched {len(alerts)} alerts (level >= {min_level}, last {days} days)")
    return alerts

# ============================================================
# FEATURE 2: Summarize alerts by rule
# ============================================================
def summarize_alerts(alerts):
    """Count alerts by rule ID."""
    summary = {}
    for a in alerts:
        rule = a.get("rule", {})
        rid = rule.get("id", "unknown")
        desc = rule.get("description", "")
        level = rule.get("level", 0)
        key = (rid, desc, level)
        summary[key] = summary.get(key, 0) + 1
    
    print("\n📊 ALERT SUMMARY BY RULE")
    print("=" * 80)
    for (rid, desc, level), count in sorted(summary.items(), key=lambda x: -x[1]):
        print(f"  Rule {rid:>6} (L{level:>2}) | {count:>4}x | {desc[:50]}")
    
    return summary

# ============================================================
# FEATURE 3: Export to CSV
# ============================================================
def export_csv(alerts, filename="wazuh_alerts.csv"):
    """Export alerts to CSV."""
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "rule_id", "level", "description", 
                         "srcip", "dstuser", "agent"])
        for a in alerts:
            rule = a.get("rule", {})
            data = a.get("data", {})
            writer.writerow([
                a.get("timestamp", ""),
                rule.get("id", ""),
                rule.get("level", ""),
                rule.get("description", ""),
                data.get("srcip", ""),
                data.get("dstuser", ""),
                a.get("agent", {}).get("name", "")
            ])
    print(f"\n💾 Exported {len(alerts)} alerts to {filename}")

# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    token = get_token()
    if not token:
        exit(1)
    print("✅ Authenticated\n")
    
    # Fetch alerts
    alerts = fetch_alerts(token, days=7, min_level=10)
    
    if alerts:
        summarize_alerts(alerts)
        export_csv(alerts)
    else:
        print("\n⚠️  No alerts found. Generate some activity first.")
        print("   Try: SSH brute force simulation")
