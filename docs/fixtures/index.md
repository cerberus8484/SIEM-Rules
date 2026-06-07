# Detection Examples — Overview

Fixtures are synthetic test events that prove detection rules work correctly.
Each fixture is a JSON file representing either a **True Positive** (the rule should fire)
or a **False Positive** (the rule should NOT fire).

---

## Why Fixtures Matter

A rule that fires on every event is not a detection — it's noise.
A rule that never fires is not a safety net — it's false confidence.

Fixtures enforce both sides:

- **True Positive fixtures** prove the rule catches real attacks
- **False Positive fixtures** prove the rule does not fire on legitimate activity

Every detection shipped in this pack has at least one TP and one FP fixture.

---

## Fixture Format

```json
{
  "_comment": "TRUE POSITIVE — SP-XXXXXX: Rule name and scenario",
  "rule_id": "SP-XXXXXX",
  "expected_result": "ALERT",
  "severity": "HIGH",
  "confidence": 82,
  "scenario": "One sentence describing what the attacker is doing",
  "mitre": "T1234.001",
  "event": {
    "sourcetype": "WinEventLog:Security",
    "EventCode": "4688",
    "CommandLine": "cmd.exe /c powershell -enc ...",
    "host": "workstation-01",
    "user": "jsmith"
  },
  "why_tp": [
    "Reason 1: what makes this clearly malicious",
    "Reason 2: why other detections might miss it",
    "Reason 3: why confidence is set to X"
  ],
  "analyst_action": [
    "IMMEDIATELY: What to do first",
    "Check: What to investigate next",
    "Escalate: When to involve IR"
  ]
}
```

For False Positive fixtures:

```json
{
  "_comment": "FALSE POSITIVE — SP-XXXXXX: Legitimate scenario",
  "rule_id": "SP-XXXXXX",
  "expected_result": "NO_ALERT",
  "scenario": "Why this event looks suspicious but is legitimate",
  "event": { ... },
  "why_fp": [
    "What makes this look like the attack pattern",
    "Why it is actually legitimate",
    "What distinguishes it from a real attack"
  ],
  "tuning_recommendation": [
    "How to suppress this FP without weakening the rule",
    "Specific field/value to scope the suppression"
  ]
}
```

---

## Fixture Categories

| Category | Fixtures | Page |
|---|---|---|
| Identity & IAM | 4 | [Identity & IAM](identity.md) |
| Backup & Ransomware | 4 | [Backup & Ransomware](backup-ransomware.md) |
| Deception / Canary | 2 | [Deception](deception.md) |
| Correlation Chains | 4 | [Correlation Chains](correlation.md) |
| Execution | 2 | — |
| Persistence | 1 | — |
| Credential Access | 2 | — |
| Lateral Movement | 1 | — |
| Impact (Ransomware) | 1 | — |
| Cloud | 2 | — |
| Email | 2 | — |
| C2 | 1 | — |
| Defense Evasion | 1 | — |
| Database | 1 | — |
| VPN | 1 | — |
| DevOps | 2 | — |

---

## Running the Fixture Validator

```bash
python tools/fixture_validator.py
python tools/fixture_validator.py --verbose
```

The validator checks:

1. Required fields are present (context-sensitive: TP vs FP)
2. `rule_id` values exist in the actual rule files
3. `expected_result` is one of `ALERT` / `NO_ALERT`
4. `severity` and `confidence` values are in valid ranges
5. `mitre` field follows `T\d{4}(\.\d{3})?` pattern (TP only)
