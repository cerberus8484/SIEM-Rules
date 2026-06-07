# Contribution Guide

The Enterprise Hunt Pack welcomes contributions. This guide explains how to add
new rules, fix existing ones, and get a PR merged.

---

## Before You Start

1. Check the [existing packs](../packs/index.md) — your rule may already exist
2. Read [Rule Format](rule-format.md) and [Metadata Reference](metadata.md)
3. Read the [Severity & Confidence Guide](severity-confidence.md) — miscalibrated
   severity/confidence is the most common reason PRs are returned for revision

---

## Contribution Workflow

```
1. Fork the repository
2. Create a feature branch: git checkout -b add-rule/SP-720021-new-rule
3. Write the rule(s)
4. Write fixtures (TP + FP, minimum one each)
5. Run the linter and fixture validator locally
6. Regenerate the coverage matrix
7. Open a Pull Request against main
8. CI runs automatically — all gates must be green
```

---

## Setting Up Locally

```bash
git clone https://github.com/YOUR_FORK/SIEM-Rules.git
cd SIEM-Rules
pip install -r tools/requirements.txt

# Validate everything is clean before you start
python tools/rule_linter.py --strict
python tools/fixture_validator.py
```

---

## Writing Your Rule

1. Assign the next available ID in the correct namespace (see [Pack Overview](../packs/index.md#id-namespace-reference))
2. Place the rule in the correct platform directory and pack sub-directory
3. Follow the [Rule Format](rule-format.md) exactly — the linter enforces it
4. Include all required metadata fields

```bash
# Check your new rule passes the linter
python tools/rule_linter.py --platform splunk --pack identity --strict
```

---

## Writing Fixtures

Every new rule needs:
- At least **one TP fixture** proving the rule fires on an attack scenario
- At least **one FP fixture** proving the rule does NOT fire on legitimate activity

Exception: Deception rules (SP-800xxx) need only TP fixtures.

```bash
# Validate your fixtures
python tools/fixture_validator.py --verbose
```

---

## Updating the Coverage Matrix

After adding rules, regenerate the coverage matrix:

```bash
python tools/coverage_matrix.py
git add COVERAGE.md coverage.json
```

CI checks that the committed matrix matches the actual rules. If you forget to
regenerate, CI will catch it with a diff error.

---

## PR Checklist

Before opening a PR:

```
□ All linter errors resolved (python tools/rule_linter.py --strict → 0 errors, 0 warnings)
□ All fixtures valid (python tools/fixture_validator.py → 0 errors)
□ Coverage matrix regenerated and committed
□ Rule ID is unique (linter would catch this, but double-check)
□ Severity and confidence are calibrated (read severity-confidence.md)
□ No secrets, IPs, or PII in rule files or fixtures
□ rule_id in comment block matches eval rule_id line
□ status=experimental for new rules (promoted to stable after validation)
```

---

## What Gets Rejected

| Issue | Reason |
|---|---|
| Rule with no TP fixture | Cannot verify the rule works |
| Rule with no FP fixture | Cannot verify the rule doesn't create noise |
| `confidence="HIGH"` string | Must be numeric integer |
| `rule_id` collision | ID uniqueness is enforced globally |
| CRITICAL severity for common admin patterns | Would create false confidence |
| Hardcoded external IPs in rule logic | Changes over time, creates brittle rules |
| PII in fixture event data | Public repo — no real usernames/IPs |

---

## Security Pack Specific Notes

For rules involving authentication, credential access, or network connections —
review the rule through the lens of OWASP Top 10 and consider:

- Could this rule be gamed by an attacker who knows it exists? (Yes — all rules
  can be evaded. The goal is raising attacker cost, not perfect coverage.)
- Does the rule expose information about internal network topology in its log output?
- Are there DSGVO/GDPR implications for what fields are logged? (User behavior data)

---

## Getting Help

Open a GitHub Discussion (not a GitHub Issue) for questions about:
- Which pack a new rule belongs to
- Severity/confidence calibration
- Platform-specific detection challenges

Open a GitHub Issue for:
- False positive reports with specific reproducible events
- Rule bugs (wrong field name, regex error)
- Missing fixtures for existing rules
