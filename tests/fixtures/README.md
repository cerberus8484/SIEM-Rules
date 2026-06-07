# Synthetic Test Fixtures — Enterprise Hunt Pack

Sample log events for validating hunt rules as True Positives (TP) or False Positives (FP).

## Structure

```
fixtures/
├── splunk/
│   ├── identity/
│   │   ├── tp_entra_global_admin.json        — SP-700001: Direct Global Admin assignment
│   │   ├── fp_pim_activation.json            — SP-700001: Legitimate PIM activation (suppress)
│   │   └── tp_mfa_push_bombing.json          — SP-700020: MFA Fatigue attack
│   ├── backup/
│   │   ├── tp_vss_ransomware_chain.json      — SP-730010: VSS + Service Stop + Process Kill
│   │   └── fp_scheduled_backup_job.json      — SP-730001: Legitimate maintenance window
│   ├── container/
│   │   ├── tp_privileged_pod.json            — SP-710001: Privileged pod in production namespace
│   │   └── fp_approved_debug_pod.json        — SP-710001: Approved debug pod in dev namespace
│   ├── correlation/
│   │   ├── tp_ato_chain.json                 — SP-810001: Full ATO Kill Chain (3 stages, 30 min)
│   │   └── tp_ransomware_kill_chain.json     — SP-810003 + SP-810020: Full Ransomware Kill Chain
│   └── deception/
│       ├── tp_canary_file_opened.json        — SP-800001: Honeypot document accessed
│       └── tp_honey_credential_used.json     — SP-800002: Honey credential used
└── wazuh/
    └── identity/
        ├── tp_aws_root_login.json            — WZ-701001: AWS root account login
        └── tp_okta_admin_role_granted.json   — WZ-702001: Okta Super Admin granted
```

## Fixture Format

Every fixture is a JSON file with these fields:

| Field | Required | Description |
|---|---|---|
| `_comment` | ✅ | Human-readable description: `TRUE/FALSE POSITIVE — RULE_ID: short title` |
| `rule_id` / `rule_ids` | ✅ | The rule(s) this fixture tests |
| `expected_result` | ✅ | `ALERT` for TP, `NO_ALERT` for FP |
| `severity` | ✅ | Expected alert severity |
| `confidence` | ✅ | Expected confidence score |
| `scenario` | ✅ | Plain English description of the attack scenario |
| `mitre` | ✅ | ATT&CK technique(s) covered |
| `event` / `events` / `chain_events` | ✅ | The raw log event(s) that trigger the rule |
| `why_tp` / `why_fp` | ✅ | Why this IS or IS NOT a true positive |
| `analyst_action` | TP only | Recommended response steps |
| `tuning_recommendation` | FP only | How to tune the rule to suppress this FP |

## Usage

These fixtures document expected behavior — they are not executed automatically.
Use them to:
1. **Validate rules** during SIEM onboarding by replaying events
2. **Document FP scenarios** so analysts don't re-investigate the same benign pattern
3. **Train new analysts** on what constitutes a true positive for each rule
4. **Regression test** after rule modifications

## Adding New Fixtures

1. Name format: `tp_<short_description>.json` or `fp_<short_description>.json`
2. Place in the matching `splunk/<pack>/` or `wazuh/<pack>/` directory
3. Follow the fixture format above
4. Include at least 1 TP and 1 FP per rule for rules with known FP patterns
