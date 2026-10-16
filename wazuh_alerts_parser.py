#!/usr/bin/env python3
import re
from collections import Counter
import csv
from datetime import datetime

LOG_FILE = "/tmp/wazuh_alerts.log"
OUTPUT_CSV = "wazuh_alerts.csv"

def parse_alerts(log_file):
    """Parse Wazuh alerts.log and extract rule info."""
    alerts = []
    current = {}
    
    with open(log_file, 'r', errors='ignore') as f:
        for line in f:
            line = line.rstrip('\n')
            
            # New alert starts
            if line.startswith("** Alert"):
                if current and "rule_id" in current:
                    alerts.append(current)
                current = {"alert_id": line.split()[2].rstrip(":") if len(line.split()) > 2 else ""}
            
            # Rule line
            elif line.startswith("Rule:"):
                m = re.match(r"Rule: (\d+) \(level (\d+)\) -> '(.+)'", line)
                if m:
                    current["rule_id"] = m.group(1)
                    current["level"] = int(m.group(2))
                    current["description"] = m.group(3)
            
            # Src IP
            elif line.startswith("Src IP:"):
                current["srcip"] = line.split(":", 1)[1].strip()
            
            # User
            elif line.startswith("User:"):
                current["user"] = line.split(":", 1)[1].strip()
            
            # Timestamp (line starting with year)
            elif re.match(r"\d{4} \w{3} \d{2}", line):
                current.setdefault("timestamp", line[:19])
    
    if current and "rule_id" in current:
        alerts.append(current)
    
    return alerts

def summarize(alerts):
    """Count by rule."""
    counter = Counter()
    for a in alerts:
        key = (a.get("rule_id"), a.get("level"), a.get("description"))
        counter[key] += 1
    
    print("\n📊 ALERT SUMMARY")
    print("=" * 90)
    for (rid, level, desc), count in sorted(counter.items(), key=lambda x: -x[1]):
        print(f"  Rule {rid:>6} (L{level:>2}) | {count:>4}x | {desc[:55]}")

def export_csv(alerts, filename):
    """Export to CSV."""
    fieldnames = ["alert_id", "rule_id", "level", "description", "srcip", "user", "timestamp"]
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for a in alerts:
            writer.writerow({k: a.get(k, "") for k in fieldnames})
    print(f"\n💾 Exported {len(alerts)} alerts to {filename}")

if __name__ == "__main__":
    alerts = parse_alerts(LOG_FILE)
    print(f"📥 Parsed {len(alerts)} alerts from {LOG_FILE}")
    summarize(alerts)
    if alerts:
        export_csv(alerts, OUTPUT_CSV)
