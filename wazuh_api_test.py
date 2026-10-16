#!/usr/bin/env python3
import requests
import urllib3
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# CONFIG
# ============================================================
API_URL = "https://localhost:55000"
USER = "wazuh"
PASSWORD = "wazuh"   # apna password daalo agar change kiya hai

# ============================================================
# STEP 1: Get JWT token
# ============================================================
def get_token():
    """Authenticate and return JWT token."""
    url = f"{API_URL}/security/user/authenticate"
    response = requests.post(url, auth=(USER, PASSWORD), verify=False)
    
    if response.status_code != 200:
        print(f"❌ Auth failed: {response.status_code}")
        print(response.text)
        return None
    
    token = response.json()["data"]["token"]
    print(f"✅ Token received: {token[:40]}...")
    return token

# ============================================================
# STEP 2: API call helper
# ============================================================
def api_get(token, endpoint):
    """Make authenticated GET request."""
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{API_URL}{endpoint}"
    response = requests.get(url, headers=headers, verify=False)
    return response.json()

# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    token = get_token()
    if not token:
        exit(1)
    
    # --- Manager info ---
    print("\n📊 MANAGER INFO")
    print("=" * 50)
    info = api_get(token, "/manager/info")
    data = info.get("data", {}).get("affected_items", [{}])[0]
    print(f"Version:     {data.get('version')}")
    print(f"Type:        {data.get('type')}")
    print(f"Max agents:  {data.get('max_agents')}")
    print(f"Hostname:    {data.get('name')}")
    
    # --- Agents ---
    print("\n🖥️  AGENTS")
    print("=" * 50)
    agents = api_get(token, "/agents")
    agent_list = agents.get("data", {}).get("affected_items", [])
    for agent in agent_list:
        print(f"  ID: {agent.get('id')} | Name: {agent.get('name')} | "
              f"Status: {agent.get('status')} | IP: {agent.get('ip')}")
    
    # --- Last 24h alerts ---
    print("\n🚨 ALERTS (last 10)")
    print("=" * 50)
    alerts = api_get(token, "/alerts?limit=10&sort=-timestamp")
    alert_list = alerts.get("data", {}).get("affected_items", [])
    if not alert_list:
        print("  (No alerts found)")
    for alert in alert_list:
        rule = alert.get("rule", {})
        print(f"  [{alert.get('timestamp', '')[:19]}] "
              f"Rule {rule.get('id')} (level {rule.get('level')}): "
              f"{rule.get('description')}")
