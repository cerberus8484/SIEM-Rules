# Getting Started

This guide covers everything needed to start using the Enterprise Hunt Pack in your SIEM
environment: repository layout, rule format, deployment, and the quality framework.

---

## Prerequisites

- Python 3.10+ (for the rule linter and tooling)
- Your SIEM platform: Splunk Enterprise/Cloud, QRadar, Google SecOps, or Wazuh
- `git` for cloning and staying up to date

```bash
git clone https://github.com/cerberus8484/SIEM-Rules.git
cd SIEM-Rules
pip install -r tools/requirements.txt
```

---

## Repository Layout

```
SIEM-Rules/
├── splunk/           # Splunk SPL detection rules (.spl)
│   ├── execution/
│   ├── persistence/
│   ├── credential_access/
│   ├── lateral_movement/
│   ├── cloud/
│   ├── identity/
│   ├── container/
│   ├── devops/
│   ├── backup/
│   ├── hypervisor/
│   ├── email/
│   ├── database/
│   ├── vpn/
│   ├── macos/
│   ├── dlp/
│   ├── deception/
│   └── correlation/
│
├── qradar/           # QRadar AQL rules (.aql)
├── secops/           # Google SecOps UDM rules (.udm)
├── wazuh/            # Wazuh KQL rules (.kql)
│
├── tests/
│   └── fixtures/     # Synthetic test events (TP + FP)
│
├── tools/
│   ├── rule_linter.py         # Validates rule metadata
│   ├── fixture_validator.py   # Validates fixture format
│   ├── coverage_matrix.py     # Generates COVERAGE.md + coverage.json
│   ├── metadata_normalizer.py # Backfills/normalizes confidence scores
│   └── release_package.py     # Builds per-platform ZIP archives
│
├── schema/
│   └── rule_metadata.yaml     # Canonical metadata schema
│
├── .github/
│   ├── workflows/ci.yml       # Rule QA CI pipeline
│   └── workflows/release.yml  # Release packaging pipeline
│
├── COVERAGE.md        # Auto-generated coverage matrix
├── CHANGELOG.md
└── README.md
```

---

## Rule Format at a Glance

Each rule file contains one or more detection rules with a structured metadata header.

=== "Splunk SPL"

    ```splunk-spl
    `comment("
    SP-100001 | Suspicious PowerShell Encoded Command
    tactic=Execution | technique=T1059.001
    severity=HIGH | confidence=82
    platform=splunk | status=stable | version=1.0
    ")`
    index=windows sourcetype=WinEventLog:Security EventCode=4688
    | where match(CommandLine, "(?i)-enc|-encodedcommand")
    | eval rule_id="SP-100001"
    | eval tactic="Execution", technique="T1059.001"
    | eval severity="HIGH", confidence=82
    | table _time host user CommandLine rule_id severity confidence
    ```

=== "QRadar AQL"

    ```sql
    /* QR-700001 | AWS Root Account Console Login
       tactic=Initial Access | technique=T1078.004
       severity=CRITICAL | confidence=95
       platform=qradar | status=stable | version=1.0 */
    SELECT
        DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS event_time,
        sourceip, username, devicetype
    FROM events
    WHERE qid = 29034512
        AND username = 'root'
    LAST 24 HOURS
    ```

=== "Google SecOps UDM"

    ```yaml
    rule gs_aws_root_login {
      meta:
        id = "GS-700001"
        severity = "CRITICAL"
        technique = "T1078.004"
        confidence = 95

      events:
        $e.metadata.product_name = "AWS CloudTrail"
        $e.target.user.userid = "root"
        $e.metadata.event_type = "USER_LOGIN"

      condition:
        $e
    }
    ```

=== "Wazuh KQL"

    ```
    /* WZ-700001 | AWS IAM Root Login
       tactic=Initial Access | technique=T1078.004
       severity=CRITICAL | confidence=95
       platform=wazuh | status=stable | version=1.0 */
    rule.groups: aws AND data.aws.userIdentity.type: Root
    AND data.aws.eventName: ConsoleLogin
    AND rule.level >= 12
    ```

---

## Running the Rule Linter

The linter validates all rules against the [metadata schema](authoring/metadata.md).
Run it before every commit:

```bash
# Validate all rules (strict mode — 0 errors, 0 warnings required)
python tools/rule_linter.py --strict

# Validate a single platform
python tools/rule_linter.py --platform splunk --strict

# Output as JSON (for CI integration)
python tools/rule_linter.py --json --strict

# Validate a specific pack
python tools/rule_linter.py --platform splunk --pack identity --strict
```

A clean run looks like:

```
Scanning splunk/ ... 987 rules in 62 files
Scanning qradar/ ... 200 rules in 12 files
Scanning secops/ ... 100 rules in 7 files
Scanning wazuh/  ... 200 rules in 14 files

PASS  1487 rules validated — 0 errors, 0 warnings
```

---

## Deploying Rules to Splunk

1. Download the latest Splunk ZIP from [Releases](releases.md):

    ```bash
    wget https://github.com/cerberus8484/SIEM-Rules/releases/latest/download/huntingthreats-splunk-v0.2.0.zip
    sha256sum -c huntingthreats-splunk-v0.2.0.zip.sha256
    ```

2. Extract and copy `.spl` files to your Splunk app `savedsearches.conf` or use the
   Splunk REST API to import as saved searches.

3. See the full [Splunk Integration Guide](platforms/splunk.md) for scheduling,
   suppression, and alert output configuration.

---

## Deploying Rules to QRadar

See the [QRadar Integration Guide](platforms/qradar.md) for AQL custom rules setup.

---

## Running Fixture Tests

Fixtures are synthetic event records that verify a rule fires (TP) or suppresses (FP)
correctly. Validate them with:

```bash
python tools/fixture_validator.py
python tools/fixture_validator.py --verbose   # show fixture details
```

See [Testing Rules](authoring/testing.md) for the fixture format specification.

---

## Generating the Coverage Matrix

```bash
python tools/coverage_matrix.py          # writes COVERAGE.md + coverage.json
python tools/coverage_matrix.py --stdout # print to console
```

---

## Next Steps

- [Rule Packs](packs/index.md) — browse rules by domain
- [Platform Guides](platforms/splunk.md) — platform-specific deployment instructions
- [Authoring Rules](authoring/rule-format.md) — write and contribute new rules
- [Quality Standards](quality.md) — understand the CI gates
