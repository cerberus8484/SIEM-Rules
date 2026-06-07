# Testing Rules

Every rule must have at least one True Positive fixture and one False Positive fixture
before being promoted to `stable` status. This page covers how to write them.

---

## Fixture Directory Layout

```
tests/
└── fixtures/
    ├── splunk/
    │   ├── identity/
    │   │   ├── tp_aws_root_login.json
    │   │   └── fp_service_account_login.json
    │   ├── backup/
    │   │   ├── tp_vss_deletion.json
    │   │   └── fp_legitimate_vss_cleanup.json
    │   ├── deception/
    │   │   └── tp_canary_doc_opened.json
    │   └── ...
    ├── wazuh/
    │   ├── identity/
    │   │   ├── tp_aws_root_login.json
    │   │   └── tp_okta_admin_role_granted.json
    │   └── ...
    └── README.md
```

Fixture files are platform-specific because different platforms use different field
names for the same event data.

---

## Writing a True Positive Fixture

A TP fixture proves the rule fires on a real attack scenario.

```json
{
  "_comment": "TRUE POSITIVE — SP-XXXXXX: What the attacker is doing",
  "rule_id": "SP-XXXXXX",
  "expected_result": "ALERT",
  "severity": "HIGH",
  "confidence": 82,
  "scenario": "One sentence: what is the attacker doing, what makes it malicious",
  "mitre": "T1234.001",
  "event": {
    "sourcetype": "WinEventLog:Security",
    "EventCode": "4688",
    "CommandLine": "the exact command that should trigger the rule",
    "host": "victim-host",
    "user": "DOMAIN\\attacker"
  },
  "why_tp": [
    "What specific field value makes this clearly malicious",
    "Why other defenses would miss this",
    "Why the confidence score is set to X"
  ],
  "analyst_action": [
    "IMMEDIATELY: First action to take",
    "Check: What to investigate next",
    "Escalate: When and to whom"
  ]
}
```

### Tips for TP Fixtures

- Use realistic but fictional hostnames and usernames (`workstation-01`, `jsmith`)
- Never use real IP addresses from threat intelligence (fixture files are public)
- Include the exact `CommandLine` or field value that triggers the rule
- The `event` object should contain only the fields actually checked by the rule
- `analyst_action` is what a Level 1 analyst should do first — make it concrete

---

## Writing a False Positive Fixture

A FP fixture proves the rule does NOT fire on legitimate activity.

```json
{
  "_comment": "FALSE POSITIVE — SP-XXXXXX: The legitimate scenario",
  "rule_id": "SP-XXXXXX",
  "expected_result": "NO_ALERT",
  "scenario": "What legitimate activity looks suspicious enough to be relevant",
  "event": {
    "sourcetype": "WinEventLog:Security",
    "CommandLine": "the legitimate command that looks like the attack",
    "host": "legitimate-host",
    "user": "DOMAIN\\svc_backup"
  },
  "why_fp": [
    "What makes this look like the attack pattern",
    "What specifically makes it legitimate",
    "What differentiates it from the TP"
  ],
  "tuning_recommendation": [
    "How to suppress this FP: scope the suppression tightly",
    "What field/value to use for the suppression filter"
  ]
}
```

### Tips for FP Fixtures

- The FP scenario should be something you have actually seen in production
- The `why_fp` must explain why the RULE should not fire — not just why it is legitimate
- The `tuning_recommendation` must be specific: `user=svc_backup AND host=backupserver-01`
  is good; `exclude backup activity` is not

---

## Correlation Fixtures (Multi-Rule)

Correlation rules fire on multiple events across time. Use `rule_ids` (plural) and
an `events` array:

```json
{
  "_comment": "TRUE POSITIVE — SP-810001: Multi-stage ATO chain",
  "rule_ids": ["SP-810001"],
  "expected_result": "ALERT",
  "severity": "CRITICAL",
  "confidence": 85,
  "scenario": "3-stage ATO: auth failures + MFA enrollment + cloud recon",
  "mitre": "T1078",
  "events": [
    { "stage": "auth_failure", ... },
    { "stage": "mfa_change", ... },
    { "stage": "aws_recon", ... }
  ],
  "why_tp": [ ... ],
  "analyst_action": [ ... ]
}
```

---

## Running Fixture Validation

```bash
# Validate all fixtures
python tools/fixture_validator.py

# Verbose: show each fixture result
python tools/fixture_validator.py --verbose

# Expected output (clean):
# Scanning fixtures... 30 fixtures in 16 directories
# PASS  30/30 fixtures valid — 0 errors
```

---

## CI Integration

The fixture validator runs automatically on every push. If a fixture references a
`rule_id` that does not exist in any rule file, CI fails:

```
ERROR tests/fixtures/splunk/identity/tp_aws_root_login.json:
  rule_id "SP-700099" not found in any rule file
```

This ensures fixtures stay synchronized with the actual rule library.

---

## Deception Rules: TP Only

Deception rules (SP-800xxx) have no FP fixtures. Any access to a deception resource
is a true positive by design. If a deception rule fires and you think it is a false
positive, the issue is with the placement of the deception resource, not the rule.
