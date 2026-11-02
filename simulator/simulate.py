#!/usr/bin/env python3
"""
SOC Copilot - Synthetic Security Log Simulator
==============================================
Generates realistic, synthetic enterprise security telemetry across three log sources:
1. SSH Auth Logs (/var/log/auth.log format)
2. Web Server Access Logs (Nginx combined format)
3. Firewall Event Logs (Perimeter CEF/KV format)

Supports multi-stage attack scenarios, background enterprise noise, variable playback
speeds, and batch ingestion into the SOC Copilot backend (POST /api/ingest).

NOTE: All logs and IP addresses are completely synthetic and never touch real external systems.
"""

import argparse
import datetime
import random
import sys
import time
from typing import Any, Dict, List, Optional
import requests

# ---------------------------------------------------------------------------
# Realistic Synthetic Pools (IPs, Hosts, Users, Endpoints)
# ---------------------------------------------------------------------------
ATTACKER_IPS = [
    "185.220.101.5",     # Tor exit / Netherlands
    "194.26.29.112",     # Bulletproof VPS / Russia
    "103.203.57.18",     # High-risk subnet / Singapore
    "45.154.255.89",     # Hostinger VPS / Romania
    "193.106.191.66",    # Known scanning network / Germany
    "177.54.148.12",     # Compromised residential / Brazil
    "203.0.113.195",     # RFC 5737 Test Net
    "198.51.100.42",     # RFC 5737 Test Net
]

LEGIT_INTERNAL_IPS = [
    "10.0.1.15", "10.0.1.22", "10.0.1.45", "10.0.1.88",
    "10.0.2.10", "10.0.2.14", "10.0.3.50", "192.168.1.105"
]

LEGIT_EXTERNAL_IPS = [
    "8.8.8.8", "1.1.1.1", "142.250.190.46", "13.107.42.14", "52.96.166.130"
]

TARGET_SERVER_IP = "10.0.0.15"
TARGET_HOSTNAME = "soc-prod-srv01"

COMMON_USERS = [
    "admin", "root", "ubuntu", "deploy", "postgres", "test",
    "developer", "service", "oracle", "guest", "git", "support",
    "jenkins", "backup", "operator", "sysadmin", "analyst"
]

LEGIT_USERS = ["alice", "bob", "carol", "david", "elena", "frank"]

SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "' OR '1'='1",
    "admin' --",
    "1' UNION SELECT null, username, password FROM users --",
    "1 UNION SELECT 1, version(), user() --",
    "1' AND 1=CONVERT(int, (SELECT @@version)) --",
    "'; EXEC xp_cmdshell('whoami');--",
    "1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), 0x3a, FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a) --",
    "1' OR SLEEP(5) --",
    "1' ORDER BY 1,2,3,4,5 --"
]

WEB_ENDPOINTS = [
    "/", "/login", "/dashboard", "/api/v1/users", "/api/v1/auth/token",
    "/products", "/search", "/checkout", "/settings", "/profile",
    "/static/css/app.css", "/static/js/bundle.js", "/health"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15",
]

ATTACK_USER_AGENTS = [
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "Mozilla/5.0 (Hydra)",
    "python-requests/2.31.0",
    "curl/8.4.0",
    "masscan/1.3.2"
]

SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 389, 443, 445,
    587, 993, 995, 1433, 1521, 2049, 2082, 2083, 3306, 3389, 5432, 5900,
    6379, 7001, 8000, 8080, 8443, 8888, 9000, 9200, 11211, 27017, 50000
]


# ---------------------------------------------------------------------------
# Synthetic Log Generators (SSH, Web, Firewall)
# ---------------------------------------------------------------------------
def get_iso_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def generate_ssh_log(
    status: str = "failed",
    user: Optional[str] = None,
    src_ip: Optional[str] = None,
    port: Optional[int] = None,
    timestamp: Optional[datetime.datetime] = None
) -> str:
    """Generate realistic /var/log/auth.log entry."""
    dt = timestamp or datetime.datetime.now(datetime.timezone.utc)
    ts_str = dt.strftime("%b %d %H:%M:%S")
    user = user or random.choice(COMMON_USERS)
    src_ip = src_ip or random.choice(ATTACKER_IPS)
    port = port or random.randint(32000, 65000)
    pid = random.randint(10000, 32000)

    if status == "failed":
        if random.random() < 0.35:
            return f"{ts_str} {TARGET_HOSTNAME} sshd[{pid}]: Failed password for invalid user {user} from {src_ip} port {port} ssh2"
        return f"{ts_str} {TARGET_HOSTNAME} sshd[{pid}]: Failed password for {user} from {src_ip} port {port} ssh2"
    elif status == "accepted":
        return f"{ts_str} {TARGET_HOSTNAME} sshd[{pid}]: Accepted password for {user} from {src_ip} port {port} ssh2"
    elif status == "session_opened":
        return f"{ts_str} {TARGET_HOSTNAME} sshd[{pid}]: pam_unix(sshd:session): session opened for user {user} by (uid=0)"
    elif status == "session_closed":
        return f"{ts_str} {TARGET_HOSTNAME} sshd[{pid}]: pam_unix(sshd:session): session closed for user {user}"
    else:
        return f"{ts_str} {TARGET_HOSTNAME} sshd[{pid}]: Connection closed by authenticating user {user} {src_ip} port {port} [preauth]"


def generate_web_log(
    method: str = "GET",
    endpoint: Optional[str] = None,
    status_code: int = 200,
    src_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    bytes_sent: Optional[int] = None,
    timestamp: Optional[datetime.datetime] = None
) -> str:
    """Generate Nginx combined log format."""
    dt = timestamp or datetime.datetime.now(datetime.timezone.utc)
    ts_str = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
    src_ip = src_ip or random.choice(LEGIT_INTERNAL_IPS + LEGIT_EXTERNAL_IPS)
    endpoint = endpoint or random.choice(WEB_ENDPOINTS)
    user_agent = user_agent or random.choice(USER_AGENTS)
    bytes_sent = bytes_sent or random.randint(250, 15000)
    referer = "-" if random.random() < 0.6 else "https://corp.internal/dashboard"

    return f'{src_ip} - - [{ts_str}] "{method} {endpoint} HTTP/1.1" {status_code} {bytes_sent} "{referer}" "{user_agent}"'


def generate_firewall_log(
    action: str = "allow",
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    dst_port: Optional[int] = None,
    byte_count: Optional[int] = None,
    proto: str = "tcp",
    timestamp: Optional[datetime.datetime] = None
) -> str:
    """Generate Perimeter Firewall KV log format."""
    dt = timestamp or datetime.datetime.now(datetime.timezone.utc)
    ts_str = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    src_ip = src_ip or random.choice(LEGIT_INTERNAL_IPS)
    dst_ip = dst_ip or TARGET_SERVER_IP
    src_port = random.randint(32000, 65000)
    dst_port = dst_port or random.choice([80, 443, 22, 53])
    byte_count = byte_count if byte_count is not None else random.randint(64, 45000)
    msg = "Inbound connection allowed" if action == "allow" else "Packet dropped by default perimeter policy"

    return (
        f'timestamp={ts_str} devname="FW-CORE-01" action="{action}" '
        f'srcip={src_ip} dstip={dst_ip} srcport={src_port} dstport={dst_port} '
        f'proto={proto} bytes={byte_count} msg="{msg}"'
    )


# ---------------------------------------------------------------------------
# Background Noise Generator (Legitimate User Activity)
# ---------------------------------------------------------------------------
def generate_normal_event() -> Dict[str, Any]:
    """Generates a routine legitimate enterprise event."""
    choice = random.random()
    now_iso = get_iso_now()

    if choice < 0.50:
        # Normal web browsing
        method = "POST" if random.random() < 0.2 else "GET"
        endpoint = random.choice(WEB_ENDPOINTS)
        status_code = random.choice([200, 200, 200, 304, 302, 404])
        return {
            "source": "web",
            "raw": generate_web_log(method=method, endpoint=endpoint, status_code=status_code),
            "timestamp": now_iso
        }
    elif choice < 0.80:
        # Normal firewall traffic
        action = "allow" if random.random() < 0.85 else "deny"
        src_ip = random.choice(LEGIT_INTERNAL_IPS)
        dst_port = random.choice([443, 80, 53, 123])
        return {
            "source": "firewall",
            "raw": generate_firewall_log(action=action, src_ip=src_ip, dst_port=dst_port),
            "timestamp": now_iso
        }
    else:
        # Legitimate admin SSH login
        legit_user = random.choice(LEGIT_USERS)
        src_ip = random.choice(["10.8.0.5", "10.8.0.12", "10.8.0.25"])
        status = "accepted" if random.random() < 0.9 else "failed"
        return {
            "source": "ssh",
            "raw": generate_ssh_log(status=status, user=legit_user, src_ip=src_ip),
            "timestamp": now_iso
        }


# ---------------------------------------------------------------------------
# Scenario Builders
# ---------------------------------------------------------------------------
def build_normal_scenario(count: int = 50) -> List[Dict[str, Any]]:
    return [generate_normal_event() for _ in range(count)]


def build_ssh_bruteforce_scenario(attacker_ip: Optional[str] = None) -> List[Dict[str, Any]]:
    attacker_ip = attacker_ip or random.choice(ATTACKER_IPS)
    events = []

    # 45+ failed attempts across multiple usernames
    users_to_try = [
        "admin", "root", "ubuntu", "admin", "test", "postgres",
        "deploy", "root", "oracle", "admin", "service", "guest",
        "root", "developer", "operator", "admin", "jenkins"
    ]
    # Expand to 45 attempts
    while len(users_to_try) < 45:
        users_to_try.append(random.choice(COMMON_USERS))

    for user in users_to_try:
        events.append({
            "source": "ssh",
            "raw": generate_ssh_log(status="failed", user=user, src_ip=attacker_ip),
            "timestamp": get_iso_now()
        })
        # Mix in background normal activity
        if random.random() < 0.35:
            events.append(generate_normal_event())

    return events


def build_sql_injection_scenario(attacker_ip: Optional[str] = None) -> List[Dict[str, Any]]:
    attacker_ip = attacker_ip or random.choice(ATTACKER_IPS)
    events = []

    target_endpoints = ["/api/v1/users?id=", "/products?cat=", "/search?q=", "/login?user="]
    user_agent = random.choice(ATTACK_USER_AGENTS)

    for payload in SQLI_PAYLOADS:
        ep = random.choice(target_endpoints) + requests.utils.quote(payload)
        status_code = random.choice([500, 200, 400, 403])
        events.append({
            "source": "web",
            "raw": generate_web_log(
                method="GET",
                endpoint=ep,
                status_code=status_code,
                src_ip=attacker_ip,
                user_agent=user_agent
            ),
            "timestamp": get_iso_now()
        })
        if random.random() < 0.4:
            events.append(generate_normal_event())

    return events


def build_port_scan_scenario(attacker_ip: Optional[str] = None) -> List[Dict[str, Any]]:
    attacker_ip = attacker_ip or random.choice(ATTACKER_IPS)
    events = []

    # Rapid scan hitting 100+ ports
    ports_to_scan = list(SCAN_PORTS)
    while len(ports_to_scan) < 110:
        p = random.randint(1024, 65000)
        if p not in ports_to_scan:
            ports_to_scan.append(p)
    random.shuffle(ports_to_scan)

    for port in ports_to_scan:
        action = "deny" if port not in [80, 443, 22] else "allow"
        events.append({
            "source": "firewall",
            "raw": generate_firewall_log(
                action=action,
                src_ip=attacker_ip,
                dst_ip=TARGET_SERVER_IP,
                dst_port=port,
                byte_count=60
            ),
            "timestamp": get_iso_now()
        })
        if random.random() < 0.15:
            events.append(generate_normal_event())

    return events


def build_credential_stuffing_then_login_scenario(attacker_ip: Optional[str] = None) -> List[Dict[str, Any]]:
    attacker_ip = attacker_ip or random.choice(ATTACKER_IPS)
    events = []

    # 1. Series of failed logins
    for user in ["admin", "root", "ubuntu", "admin", "admin"]:
        for _ in range(3):
            events.append({
                "source": "ssh",
                "raw": generate_ssh_log(status="failed", user=user, src_ip=attacker_ip),
                "timestamp": get_iso_now()
            })

    # 2. Finally, a successful password login for admin
    events.append({
        "source": "ssh",
        "raw": generate_ssh_log(status="accepted", user="admin", src_ip=attacker_ip),
        "timestamp": get_iso_now()
    })
    events.append({
        "source": "ssh",
        "raw": generate_ssh_log(status="session_opened", user="admin", src_ip=attacker_ip),
        "timestamp": get_iso_now()
    })

    return events


def build_data_exfil_scenario(attacker_ip: Optional[str] = None) -> List[Dict[str, Any]]:
    attacker_ip = attacker_ip or random.choice(ATTACKER_IPS)
    events = []

    # Compromised session active, followed by multiple massive outbound transfers
    exfil_sizes = [
        45 * 1024 * 1024,    # 45 MB
        128 * 1024 * 1024,   # 128 MB
        350 * 1024 * 1024,   # 350 MB
        85 * 1024 * 1024     # 85 MB
    ]

    for size in exfil_sizes:
        events.append({
            "source": "firewall",
            "raw": generate_firewall_log(
                action="allow",
                src_ip=TARGET_SERVER_IP,
                dst_ip=attacker_ip,
                dst_port=random.choice([443, 8443, 2222]),
                byte_count=size
            ),
            "timestamp": get_iso_now()
        })
        # Add normal event
        events.append(generate_normal_event())

    return events


def build_full_attack_chain_scenario(attacker_ip: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Multi-stage attack chain from the SAME attacker IP:
    1. Reconnaissance: Port scanning (firewall drops on multiple ports)
    2. Exploitation / Credential Access: SSH brute force (failed logins)
    3. Initial Access / Privilege: Successful login for 'admin'
    4. Exfiltration: Massive outbound byte transfer from target to attacker
    """
    attacker_ip = attacker_ip or random.choice(ATTACKER_IPS)
    chain = []

    # --- Phase 1: Reconnaissance (Port Scan) ---
    for port in random.sample(SCAN_PORTS, 25):
        chain.append({
            "source": "firewall",
            "raw": generate_firewall_log(action="deny", src_ip=attacker_ip, dst_ip=TARGET_SERVER_IP, dst_port=port, byte_count=60),
            "timestamp": get_iso_now(),
            "_stage": "Phase 1: Reconnaissance (Port Scan)"
        })
        if random.random() < 0.2:
            chain.append(generate_normal_event())

    # --- Phase 2: Credential Access (SSH Brute Force) ---
    brute_users = ["root", "admin", "ubuntu", "test", "deploy", "postgres", "admin", "root", "admin", "admin"]
    for user in brute_users * 3:
        chain.append({
            "source": "ssh",
            "raw": generate_ssh_log(status="failed", user=user, src_ip=attacker_ip),
            "timestamp": get_iso_now(),
            "_stage": "Phase 2: Credential Access (Brute Force)"
        })
        if random.random() < 0.25:
            chain.append(generate_normal_event())

    # --- Phase 3: Initial Access (Successful Compromise) ---
    chain.append({
        "source": "ssh",
        "raw": generate_ssh_log(status="accepted", user="admin", src_ip=attacker_ip),
        "timestamp": get_iso_now(),
        "_stage": "Phase 3: Initial Access (Accepted Login)"
    })
    chain.append({
        "source": "ssh",
        "raw": generate_ssh_log(status="session_opened", user="admin", src_ip=attacker_ip),
        "timestamp": get_iso_now(),
        "_stage": "Phase 3: Initial Access (Session Opened)"
    })

    # --- Phase 4: Exfiltration (Large Outbound File Transfer) ---
    for exfil_bytes in [52428800, 157286400, 314572800]: # 50MB, 150MB, 300MB
        chain.append({
            "source": "firewall",
            "raw": generate_firewall_log(action="allow", src_ip=TARGET_SERVER_IP, dst_ip=attacker_ip, dst_port=443, byte_count=exfil_bytes),
            "timestamp": get_iso_now(),
            "_stage": "Phase 4: Exfiltration (Large Data Transfer)"
        })
        chain.append(generate_normal_event())

    return chain


# ---------------------------------------------------------------------------
# Ingestion Sender & Execution Engine
# ---------------------------------------------------------------------------
def post_batch(target_url: str, batch: List[Dict[str, Any]], dry_run: bool = False) -> bool:
    """Sends a batch of logs to the ingestion endpoint."""
    # Clean internal metadata flags like '_stage' before sending
    cleaned_batch = [
        {"source": item["source"], "raw": item["raw"], "timestamp": item["timestamp"]}
        for item in batch
    ]
    payload = {"logs": cleaned_batch}

    if dry_run:
        print(f"[DRY-RUN] Prepared batch of {len(batch)} logs for {target_url}")
        return True

    try:
        resp = requests.post(
            target_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=5.0
        )
        if resp.status_code in [200, 201, 202]:
            return True
        else:
            print(f"[-] Ingest warning: HTTP {resp.status_code} - {resp.text[:120]}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"[-] Connection failed to {target_url}: {e}")
        return False


def run_scenario(
    scenario_name: str,
    target_url: str,
    speed: float = 1.0,
    batch_size: int = 5,
    attacker_ip: Optional[str] = None,
    dry_run: bool = False,
    continuous: bool = False
):
    print("=" * 70)
    print("  SOC COPILOT - SYNTHETIC ATTACK LOG SIMULATOR")
    print("=" * 70)
    print(f"[*] Scenario   : {scenario_name}")
    print(f"[*] Target URL : {target_url} {'(DRY RUN)' if dry_run else ''}")
    print(f"[*] Speed Rate : {speed}x")
    print(f"[*] Batch Size : {batch_size}")
    if attacker_ip:
        print(f"[*] Target IP  : {attacker_ip}")
    print("-" * 70)

    # Calculate delay: base delay between batches is ~1.0s / speed
    batch_delay = max(0.05, 1.0 / speed)

    scenario_map = {
        "normal": lambda: build_normal_scenario(count=60),
        "ssh_bruteforce": lambda: build_ssh_bruteforce_scenario(attacker_ip),
        "sql_injection": lambda: build_sql_injection_scenario(attacker_ip),
        "port_scan": lambda: build_port_scan_scenario(attacker_ip),
        "credential_stuffing_then_login": lambda: build_credential_stuffing_then_login_scenario(attacker_ip),
        "data_exfil": lambda: build_data_exfil_scenario(attacker_ip),
        "full_attack_chain": lambda: build_full_attack_chain_scenario(attacker_ip)
    }

    if scenario_name not in scenario_map:
        print(f"[!] Unknown scenario: {scenario_name}")
        sys.exit(1)

    round_num = 1
    total_sent = 0

    try:
        while True:
            events = scenario_map[scenario_name]()
            current_stage = None

            print(f"\n[+] Starting playback: {scenario_name} (Round {round_num}, {len(events)} events)")

            # Process in batches
            for i in range(0, len(events), batch_size):
                batch = events[i : i + batch_size]

                # Log stage transition if applicable
                for item in batch:
                    stage = item.get("_stage")
                    if stage and stage != current_stage:
                        current_stage = stage
                        print(f"\n>>> [ATTACK STAGE] {current_stage}")

                # Print sample from batch
                sample = batch[0]
                sample_preview = sample["raw"][:85] + ("..." if len(sample["raw"]) > 85 else "")
                print(f"    [{sample['source'].upper():<8}] {sample_preview}")

                success = post_batch(target_url, batch, dry_run=dry_run)
                if success:
                    total_sent += len(batch)

                time.sleep(batch_delay)

            print(f"\n[v] Completed round {round_num}. Total logs dispatched: {total_sent}")

            if not continuous:
                break
            round_num += 1
            print("[*] Continuous mode active. Pausing 5s before next iteration...")
            time.sleep(5.0 / speed)

    except KeyboardInterrupt:
        print(f"\n[!] Simulation interrupted by user. Total logs dispatched: {total_sent}")


# ---------------------------------------------------------------------------
# CLI Argument Parser
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="SOC Copilot Realistic Synthetic Log Simulator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--scenario",
        choices=[
            "normal",
            "ssh_bruteforce",
            "sql_injection",
            "port_scan",
            "credential_stuffing_then_login",
            "data_exfil",
            "full_attack_chain"
        ],
        default="full_attack_chain",
        help="Attack scenario or traffic profile to simulate"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000/api/ingest",
        help="Backend ingestion endpoint URL"
    )
    parser.add_argument(
        "--speed",
        type=float,
        default=1.0,
        help="Playback speed multiplier (e.g. 2.0 = 2x speed, 5.0 = 5x speed)"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=5,
        help="Number of log records sent in each POST request"
    )
    parser.add_argument(
        "--attacker-ip",
        type=str,
        default=None,
        help="Specific IP to use as the attacker (defaults to a random realistic external IP)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate and preview logs on console without sending HTTP requests"
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Loop continuously (useful for long demo sessions)"
    )

    args = parser.parse_args()

    run_scenario(
        scenario_name=args.scenario,
        target_url=args.target,
        speed=args.speed,
        batch_size=args.batch_size,
        attacker_ip=args.attacker_ip,
        dry_run=args.dry_run,
        continuous=args.loop
    )


if __name__ == "__main__":
    main()

