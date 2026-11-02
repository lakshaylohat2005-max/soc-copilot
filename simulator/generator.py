import argparse
import json
import time
import urllib.request
from datetime import datetime

SCENARIOS = {
    "brute_force": [
        {"source": "auth", "event_type": "login_failed", "source_ip": "198.51.100.42", "username": "admin", "severity": "MEDIUM", "raw_message": "Failed password for admin from 198.51.100.42 port 48291 ssh2"},
        {"source": "auth", "event_type": "login_failed", "source_ip": "198.51.100.42", "username": "admin", "severity": "MEDIUM", "raw_message": "Failed password for admin from 198.51.100.42 port 48292 ssh2"},
        {"source": "auth", "event_type": "login_failed", "source_ip": "198.51.100.42", "username": "root",  "severity": "MEDIUM", "raw_message": "Failed password for root from 198.51.100.42 port 48293 ssh2"},
        {"source": "auth", "event_type": "login_failed", "source_ip": "198.51.100.42", "username": "admin", "severity": "MEDIUM", "raw_message": "Failed password for admin from 198.51.100.42 port 48294 ssh2"},
        {"source": "auth", "event_type": "login_failed", "source_ip": "198.51.100.42", "username": "admin", "severity": "MEDIUM", "raw_message": "Failed password for admin from 198.51.100.42 port 48295 ssh2"},
        {"source": "auth", "event_type": "login_success", "source_ip": "198.51.100.42", "username": "admin", "severity": "HIGH", "raw_message": "Accepted password for admin from 198.51.100.42 port 48296 ssh2"},
    ],
    "sql_injection": [
        {"source": "nginx", "event_type": "http_request", "source_ip": "203.0.113.15", "severity": "HIGH", "raw_message": "GET /api/users?id=1%27%20OR%20%271%27=%271 HTTP/1.1 500"},
        {"source": "nginx", "event_type": "http_request", "source_ip": "203.0.113.15", "severity": "CRITICAL", "raw_message": "GET /api/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1 200"}
    ]
}

def send_log(log_payload, target_url):
    data = json.dumps(log_payload).encode("utf-8")
    req = urllib.request.Request(target_url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            print(f"[+] Sent log: {log_payload['event_type']} -> Response: {resp.status}")
    except Exception as e:
        print(f"[-] Failed to send log: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC Copilot Attack Log Generator")
    parser.add_argument("--scenario", choices=list(SCENARIOS.keys()), default="brute_force")
    parser.add_argument("--target", default="http://localhost:8000/api/logs/ingest")
    parser.add_argument("--delay", type=float, default=1.0)
    args = parser.parse_args()

    print(f"[*] Simulating scenario: {args.scenario} targeting {args.target}")
    events = SCENARIOS[args.scenario]
    for event in events:
        event["timestamp"] = datetime.utcnow().isoformat()
        send_log(event, args.target)
        time.sleep(args.delay)

