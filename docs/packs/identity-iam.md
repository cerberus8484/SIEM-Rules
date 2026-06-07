# Identity / IAM Pack

**75 rules across 4 platforms — Splunk, QRadar, Google SecOps, Wazuh**

The Identity / IAM pack is the most comprehensive multi-platform pack in the library.
It covers Entra ID (Azure AD), AWS IAM, Okta, and generic identity provider events.

---

## Pack Summary

| Property | Value |
|---|---|
| Pack Directory | `identity/` |
| ID Range | SP-700001 – SP-700075 (Splunk) / QR-700001+ / GS-700001+ / WZ-700001+ |
| Platforms | Splunk, QRadar, Google SecOps, Wazuh |
| Rules | 75 (20 Entra ID + 20 AWS IAM + 20 Okta + 15 Generic IdP) |
| MITRE Tactics | Initial Access, Persistence, Privilege Escalation, Credential Access |
| Min Confidence | 70 |

---

## Sub-Domains

### Entra ID / Azure AD (SP-700001 – SP-700020)

Covers Azure Active Directory and Microsoft Entra ID signals including conditional
access failures, MFA manipulation, global admin assignment, and risky sign-in events.

| Rule ID | Name | Severity | Confidence | Technique |
|---|---|---|---|---|
| SP-700001 | Global Admin Role Assigned | CRITICAL | 92 | T1098 |
| SP-700002 | MFA Registration for New Device | HIGH | 82 | T1078 |
| SP-700003 | Conditional Access Policy Disabled | CRITICAL | 90 | T1556 |
| SP-700004 | Entra ID Risky Sign-In | HIGH | 80 | T1078 |
| SP-700005 | Service Principal Secret Added | HIGH | 85 | T1098.001 |

### AWS IAM (SP-700021 – SP-700040)

CloudTrail-based IAM detection: root login, policy changes, access key abuse,
privilege escalation via AssumeRole, and credential exfiltration.

| Rule ID | Name | Severity | Confidence | Technique |
|---|---|---|---|---|
| SP-700021 | AWS Root Account Console Login | CRITICAL | 95 | T1078.004 |
| SP-700022 | IAM Policy Attached to User Directly | HIGH | 78 | T1098.001 |
| SP-700023 | AssumeRole Cross-Account (Unknown) | HIGH | 82 | T1550.001 |
| SP-700024 | AWS Access Key Created for Root | CRITICAL | 95 | T1078.004 |
| SP-700025 | CloudTrail Logging Disabled | CRITICAL | 93 | T1562.008 |

### Okta (SP-700041 – SP-700060)

Okta system log detection: admin role granted, MFA factor enrollment, suspicious
login patterns, and Okta API token abuse.

| Rule ID | Name | Severity | Confidence | Technique |
|---|---|---|---|---|
| SP-700041 | Okta Admin Role Granted | CRITICAL | 90 | T1098 |
| SP-700042 | Okta MFA Factor Enrolled (New Device) | HIGH | 80 | T1078 |
| SP-700043 | Okta Multiple Failed Logins | MEDIUM | 65 | T1110 |
| SP-700044 | Okta API Token Created | HIGH | 82 | T1528 |
| SP-700045 | Okta Session Hijacking Indicator | HIGH | 85 | T1563 |

### Generic IdP (SP-700061 – SP-700075)

Platform-agnostic identity rules that work across custom IdPs and log sources
with normalized event fields.

---

## Splunk SPL Example

```splunk-spl
`comment("
SP-700021 | AWS Root Account Console Login
tactic=Initial Access | technique=T1078.004
severity=CRITICAL | confidence=95
platform=splunk | status=stable | version=1.0
")`
index=aws sourcetype=aws:cloudtrail eventName=ConsoleLogin
| spath userIdentity.type | where 'userIdentity.type'="Root"
| eval rule_id="SP-700021"
| eval tactic="Initial Access", technique="T1078.004"
| eval severity="CRITICAL", confidence=95
| table _time awsRegion userIdentity.type sourceIPAddress errorMessage rule_id severity confidence
```

## Wazuh KQL Example

```
/* WZ-700006 | AWS IAM Root Login
   tactic=Initial Access | technique=T1078.004
   severity=CRITICAL | confidence=95
   platform=wazuh | status=stable | version=1.0 */
rule.groups: aws AND data.aws.userIdentity.type: Root
AND data.aws.eventName: ConsoleLogin
AND rule.level >= 12
```

---

## Test Fixtures

| Fixture | Type | Scenario |
|---|---|---|
| `tp_aws_root_login.json` | TRUE POSITIVE | Root console login from unknown IP |
| `tp_okta_admin_role_granted.json` | TRUE POSITIVE | Admin role granted to non-admin user |
| `fp_legitimate_admin_grant.json` | FALSE POSITIVE | Scheduled admin provisioning via ITSM |
| `fp_service_account_login.json` | FALSE POSITIVE | Monitoring service login from known IP range |

---

## Tuning Recommendations

!!! tip "Reduce false positives"
    - Allowlist known break-glass accounts for root login alerts
    - Add approved IP ranges for Okta admin operations (e.g., corporate VPN egress)
    - For MFA enrollment, correlate with ITSM ticket open in same 1h window

!!! warning "High-confidence rules — never suppress without review"
    Rules with confidence >= 90 (e.g., SP-700021, SP-700003, SP-700041) should
    not be suppressed globally. If they fire for a legitimate process, update the
    suppression to be scoped to a specific named account or IP range.
