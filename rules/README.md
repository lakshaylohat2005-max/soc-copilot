# Detection Rules

Detection rules are authored in YAML and mapped directly to the **MITRE ATT&CK Enterprise Matrix**.

### Rule Schema
```yaml
id: RULE-AUTH-001
name: Rule Title
description: Detailed description of what the rule flags
severity: LOW | MEDIUM | HIGH | CRITICAL
mitre:
  tactic: Credential Access
  technique_id: T1110.001
  technique_name: "Brute Force: Password Guessing"
criteria:
  source: auth
  event_type: login_failed
  threshold: 5
  time_window_seconds: 60
  group_by: source_ip
action_recommendations:
  - action_type: block_ip
    description: Recommended automated or 1-click action
```

