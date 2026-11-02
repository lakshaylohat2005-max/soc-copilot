# SOC Copilot Architecture Specification

## 1. Overview & Data Pipeline

SOC Copilot processes incoming event telemetry through six pipeline stages:

```
+-------------+      +-------------------+      +------------------+
| Event Logs  | ---> | Parser/Normalizer | ---> | Detection Engine |
+-------------+      +-------------------+      +------------------+
                                                          |
                                                          v
+------------------+      +----------------+      +------------------+
|  Live Dashboard  | <--- |   LLM Triage   | <--- |   Correlation    |
| (React + WS)     |      |    (Gemini)    |      |      Engine      |
+------------------+      +----------------+      +------------------+
        |
        v
+------------------+
| Response Actions |
| (Block/Disable)  |
+------------------+
```

### Stage 1: Ingestion & Normalization
- Receives raw telemetry via `POST /api/logs/ingest` or syslog receivers.
- Normalizes disparate schemas into Elastic Common Schema (ECS) standard fields: `timestamp`, `source_ip`, `destination_ip`, `username`, `event_type`, `severity`, `raw_message`, `metadata_json`.

### Stage 2: Detection Engine
- Evaluates incoming normalized logs against YAML-based detection rules in `/rules`.
- Matches threshold conditions (e.g. >= 5 failed logins within 60s from single IP).
- Tags alerts with MITRE ATT&CK metadata (`tactic`, `technique_id`, `technique_name`).

### Stage 3: Correlation Engine
- Aggregates atomic alerts into multi-stage **Incidents**.
- Groups by common pivots: Source IP, Targeted Host, or Compromised User within a sliding temporal window (e.g. 15 minutes).
- Elevates severity when multiple MITRE tactics are traversed (e.g. Initial Access -> Execution -> Privilege Escalation).

### Stage 4: LLM Triage (Gemini)
- Ingests the incident graph and associated telemetry into Google Gemini.
- Generates:
  1. Executive Summary & Root Cause Analysis.
  2. Attack Timeline & MITRE ATT&CK Matrix mapping.
  3. Recommended Containment Playbook (ordered step-by-step actions).
  4. Suggested One-Click Remediation payloads.

### Stage 5: Response Actions (Active Containment)
- Provides immediate remediation endpoints:
  - `block_ip`: Adds firewall/iptables block rule or mock null route.
  - `disable_user`: Revokes Active Directory / IAM token or account status.
  - `create_ticket`: Emits an external webhook or Jira/Linear issue payload.
- All actions require operator confirmation with full audit logging in the database.

### Stage 6: Live Dashboard & WebSockets
- WebSocket endpoint (`/ws`) broadcasts real-time log counts, alert triggers, incident formations, and action execution states to the React client.

