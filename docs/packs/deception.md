# Deception / Canary Pack

**15 rules — Splunk + Wazuh — confidence 97–98**

The Deception pack is unique: **any alert from these rules is high-fidelity by design.**
Canary resources exist only to detect access — there is no legitimate reason to access
a honey credential, open a canary document, or trigger a honeypot endpoint.

---

## Pack Summary

| Property | Value |
|---|---|
| Pack Directory | `deception/` |
| ID Range | SP-800001 – SP-800015 |
| Platforms | Splunk, Wazuh |
| Rules | 15 |
| MITRE Tactics | Collection, Credential Access |
| Min Confidence | 97 |
| False Positive Rate | Near-zero (by design) |

---

## Design Principle

> A canary that fires 5% of the time on legitimate activity is not a canary — it's
> just another noisy rule. Every rule in this pack targets a resource that **only
> an attacker would access**.

This means:

- Canary documents are stored in locations that normal users have no reason to browse
- Honey credentials are injected in formats that only credential-dumping tools read
- AWS honey tokens are not linked from any legitimate application
- Honeypot services listen on ports not used by any production service

---

## Rule Inventory

| Rule ID | Name | Severity | Confidence | Technique |
|---|---|---|---|---|
| SP-800001 | Canary Document Opened | CRITICAL | 98 | T1083 |
| SP-800002 | Honey Credential Used (Windows) | CRITICAL | 98 | T1078 |
| SP-800003 | AWS Honey Token Access (CloudTrail) | CRITICAL | 97 | T1528 |
| SP-800004 | Honeypot RDP Connection Attempt | HIGH | 97 | T1021.001 |
| SP-800005 | Honeypot SSH Connection Attempt | HIGH | 97 | T1021.004 |
| SP-800006 | Canary Database Query Detected | CRITICAL | 98 | T1213 |
| SP-800007 | Honey DNS Record Resolved | HIGH | 97 | T1071.004 |
| SP-800008 | Honey Share Accessed | CRITICAL | 98 | T1039 |
| SP-800009 | Canary API Key Used | CRITICAL | 98 | T1528 |
| SP-800010 | Honey Email Inbox Accessed | HIGH | 97 | T1114 |
| SP-800011 | Canary File Hash in Process | CRITICAL | 97 | T1059 |
| SP-800012 | Honeypot Web Endpoint Hit | MEDIUM | 97 | T1190 |
| SP-800013 | Honey AD Account Login | CRITICAL | 98 | T1078 |
| SP-800014 | Canary Certificate Used | HIGH | 97 | T1552 |
| SP-800015 | Honey Token in Memory (Proc Dump) | CRITICAL | 98 | T1003 |

---

## Splunk SPL Example

```splunk-spl
`comment("
SP-800001 | Canary Document Opened
tactic=Collection | technique=T1083
severity=CRITICAL | confidence=98
platform=splunk | status=stable | version=1.0
")`
index=windows sourcetype=WinEventLog:Security EventCode=4663
| where match(ObjectName, "(?i)canary|honeydoc|_decoy|\\~bait")
| eval rule_id="SP-800001"
| eval tactic="Collection", technique="T1083"
| eval severity="CRITICAL", confidence=98
| table _time host user ObjectName ProcessName rule_id severity confidence
```

---

## Wazuh KQL Example

```
/* WZ-800001 | Canary Document Opened
   tactic=Collection | technique=T1083
   severity=CRITICAL | confidence=98
   platform=wazuh | status=stable | version=1.0 */
rule.groups: syscheck AND data.path: (*canary* OR *honeydoc* OR *_decoy*)
AND rule.level >= 10
```

---

## Deployment Requirements

### Canary Document Setup

1. Create realistic-looking documents (`.docx`, `.xlsx`, `.pdf`) with names like
   `Q4_2024_Board_Presentation.docx` or `Employee_Salaries_2024.xlsx`
2. Store them in locations that are browseable but not part of normal workflows:
   - `\\fileserver\hr_archive\legacy\`
   - `C:\Users\Administrator\Desktop\`
3. Enable file access auditing on those paths (Windows Security Event 4663)
4. Add the file path pattern to the SPL rule's `ObjectName` filter

### AWS Honey Token Setup

1. Create an IAM user with no permissions, generate an access key
2. Place the key in realistic locations attackers look for:
   - Commit to a private test repo with a pattern that looks like an accident
   - Place in a `.env.example` file with a realistic-looking format
3. Configure a CloudTrail alert on `GetCallerIdentity` / any API call from that key

---

## Test Fixtures

| Fixture | Type | Scenario |
|---|---|---|
| `tp_canary_doc_opened.json` | TRUE POSITIVE | Canary XLSX opened from unknown host |
| `tp_honey_credential_used.json` | TRUE POSITIVE | Honey AD account login from unexpected IP |

!!! note "No false positive fixtures for deception rules"
    By design, deception rules have no legitimate use case. If a rule fires, it **is**
    a true positive. The fixture suite only contains TP scenarios.
