# Quality Standards

The Enterprise Hunt Pack enforces quality automatically on every push through a
GitHub Actions CI pipeline. This page describes the standards, tools, and CI gates.

---

## Quality Metrics (v0.2.0)

| Metric | Value | How Enforced |
|---|---|---|
| Linter Errors | **0** | `--strict` mode: CI fails on any error |
| Linter Warnings | **0** | `--strict` mode: CI fails on any warning |
| Rules with confidence score | **1029 / 1029** | Metadata normalizer + linter |
| Rules with MITRE technique | **1029 / 1029** | Linter required field |
| Rules with severity | **1029 / 1029** | Linter required field |
| Test Fixtures | **30** | Fixture validator in CI |
| CI Gate | **Global strict** | All platforms, all packs |

---

## The Rule Linter

`tools/rule_linter.py` validates every rule file on every push.

### Required Fields (Error if missing)

| Field | Format | Example |
|---|---|---|
| `rule_id` | `{SP\|QR\|GS\|WZ}-\d{6}` | `SP-700021` |
| `tactic` | Free text | `Initial Access` |
| `technique` | `T\d{4}(\.\d{3})?` | `T1078.004` |
| `severity` | `CRITICAL\|HIGH\|MEDIUM\|LOW\|INFO` | `HIGH` |
| `eval rule_id` | Matches comment block ID | `\| eval rule_id="SP-700021"` |

### Warnings (Enforced in strict mode)

| Warning | Condition |
|---|---|
| Missing confidence eval | No `eval confidence=<N>` in rule block |
| Confidence out of range | Value outside 0–100 |
| Duplicate rule_id | Same ID appears in two files |
| Bug placeholder left | `TODO`, `FIXME`, `YOUR_`, `EXAMPLE_` in rule text |

### Linter CLI

```bash
# Standard run (shows errors + warnings)
python tools/rule_linter.py

# Strict mode (exit 1 if any error or warning)
python tools/rule_linter.py --strict

# Single platform
python tools/rule_linter.py --platform splunk --strict

# Single pack
python tools/rule_linter.py --platform splunk --pack identity --strict

# JSON output (for CI integration or scripting)
python tools/rule_linter.py --json --strict
```

---

## The Fixture Validator

`tools/fixture_validator.py` validates all test fixtures on every push.

### What It Checks

1. **Required fields** — context-sensitive (TP vs FP fixtures have different requirements)
2. **rule_id references** — every fixture's `rule_id` must exist in an actual rule file
3. **expected_result** — must be `ALERT` or `NO_ALERT`
4. **severity** — must be `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`
5. **confidence** — must be 0–100 integer
6. **mitre** — must match `T\d{4}(\.\d{3})?` (TP fixtures only)

### Field Requirements by Fixture Type

| Field | TP Fixture | FP Fixture |
|---|---|---|
| `expected_result` | Required | Required |
| `scenario` | Required | Required |
| `severity` | Required | Not required |
| `confidence` | Required | Not required |
| `mitre` | Required | Not required |
| `why_tp` | Required | — |
| `why_fp` | — | Required |
| `analyst_action` | Recommended | — |
| `tuning_recommendation` | — | Recommended |

---

## The Coverage Matrix

`tools/coverage_matrix.py` generates `COVERAGE.md` and `coverage.json` on every push.

The CI job checks that the generated file matches what is committed:

```bash
python tools/coverage_matrix.py
git diff --exit-code COVERAGE.md coverage.json
```

If a rule is added or modified, the developer must regenerate and commit the coverage
files — CI will catch any discrepancy.

---

## CI Pipeline

```yaml
# .github/workflows/ci.yml
on:
  push:
    branches: [main, develop]
    paths: ["splunk/**", "qradar/**", "secops/**", "wazuh/**"]

jobs:
  lint:
    - python tools/rule_linter.py --json --strict   # 0 errors, 0 warnings

  validate-fixtures:
    - python tools/fixture_validator.py             # all fixtures valid

  coverage-matrix:
    - python tools/coverage_matrix.py
    - git diff --exit-code COVERAGE.md              # committed coverage is current

  summary:
    needs: [lint, validate-fixtures, coverage-matrix]
    - echo "All gates passed"
```

---

## Release Gate

Releases are only created when the full CI suite passes + platform packages build
successfully. The release workflow runs `tools/release_package.py` to create
per-platform ZIP archives with SHA-256 checksums.

```bash
python tools/release_package.py --tag v0.2.0
# Outputs: dist/huntingthreats-splunk-v0.2.0.zip + .sha256
#          dist/huntingthreats-qradar-v0.2.0.zip + .sha256
#          dist/huntingthreats-secops-v0.2.0.zip + .sha256
#          dist/huntingthreats-wazuh-v0.2.0.zip  + .sha256
#          dist/huntingthreats-all-v0.2.0.zip    + .sha256
```

---

## Rule Status Lifecycle

| Status | Meaning | CI enforcement |
|---|---|---|
| `experimental` | New rule, not yet tuned | Warnings allowed |
| `testing` | In validation, FP rate being measured | Strict |
| `stable` | Production-ready, FP rate < 5% | Strict |
| `deprecated` | No longer maintained | Excluded from coverage |

All rules in the current pack are `stable`.
