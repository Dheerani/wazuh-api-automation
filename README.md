# Wazuh API Automation

Python automation for Wazuh SIEM — authentication, agent management, and alert parsing.

## Features

- JWT authentication with Wazuh API
- Manager info retrieval
- Agent listing and status
- Alert parsing from `/var/ossec/logs/alerts/alerts.log`
- CSV export with level filtering
- Alert summarization by rule

## Scripts

| Script | Purpose |
|--------|---------|
| `wazuh_api_test.py` | Basic API test — auth + manager info + agents |
| `wazuh_api_advanced.py` | Advanced API — agent listing, alert fetch |
| `wazuh_alerts_parser.py` | Parse `alerts.log` → CSV export |

## Usage

### 1. Basic API test
```bash
python3 wazuh_api_test.py
