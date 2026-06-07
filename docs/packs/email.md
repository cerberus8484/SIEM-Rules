# Email Security Pack

**20 rules — Splunk — BEC, phishing, and DMARC**

The Email pack detects Business Email Compromise (BEC), phishing campaigns, lookalike
domains, QR code quishing, and email infrastructure attacks.

---

## Pack Summary

| Property | Value |
|---|---|
| Pack Directory | `email/` |
| ID Range | SP-750001 – SP-750020 |
| Platforms | Splunk |
| Rules | 20 |
| Key Sources | o365:management:activity, proofpoint:email, mimecast:logs |
| MITRE Tactics | Initial Access, Collection |

---

## Rule Inventory

| Rule ID | Name | Severity | Confidence | Technique |
|---|---|---|---|---|
| SP-750001 | DMARC/SPF Fail from Exec Domain | HIGH | 82 | T1566.001 |
| SP-750002 | Executive Impersonation (Lookalike Domain) | CRITICAL | 90 | T1566.001 |
| SP-750003 | Macro-Enabled Attachment Opened | HIGH | 82 | T1204.002 |
| SP-750004 | QR Code in Email Attachment (Quishing) | HIGH | 80 | T1566.001 |
| SP-750005 | Mailbox Forward Rule Created (External) | CRITICAL | 92 | T1114.003 |
| SP-750006 | Mass Email Sent from Internal Account | HIGH | 78 | T1534 |
| SP-750007 | Email Reply Chain Hijacking Indicator | HIGH | 82 | T1534 |
| SP-750008 | O365 Anti-Spam Policy Disabled | CRITICAL | 90 | T1562 |
| SP-750009 | Suspicious Attachment Extension (.iso, .lnk, .vhd) | HIGH | 80 | T1566.001 |
| SP-750010 | Finance-Themed Email with External Sender | MEDIUM | 68 | T1566.001 |
| SP-750011 | BEC Chain: Mailbox + Finance + External Forward | CRITICAL | 88 | T1114.003 |
| SP-750012 | Email Thread with Base64 Encoded URLs | HIGH | 78 | T1566.001 |
| SP-750013 | Phishing Simulation Domain in Production Log | INFO | 35 | — |
| SP-750014 | SMTP Relay Misconfiguration Exploited | HIGH | 82 | T1566.001 |
| SP-750015 | Sender Score Below Threshold | MEDIUM | 62 | T1566.001 |
| SP-750016 | HTML Email with Obfuscated Link | HIGH | 78 | T1566.001 |
| SP-750017 | O365 Audit Log Mailbox Search by Admin | HIGH | 75 | T1114 |
| SP-750018 | Email Bomb (High Volume Incoming) | MEDIUM | 65 | T1498 |
| SP-750019 | Credential Phishing Page URL in Email | CRITICAL | 90 | T1566.002 |
| SP-750020 | BEC — Invoice Modification Indicator | CRITICAL | 88 | T1534 |

---

## Test Fixtures

| Fixture | Type | Scenario |
|---|---|---|
| `tp_executive_impersonation.json` | TRUE POSITIVE | CEO lookalike domain with SPF fail targeting finance team |
| `fp_newsletter_lookalike.json` | FALSE POSITIVE | Marketing newsletter from subdomain matching lookalike pattern |
