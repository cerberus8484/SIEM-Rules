# Detection Examples — Deception / Canary

Two True Positive fixtures for canary resources. Deception rules have no False
Positive fixtures by design — any access to a canary resource is a true positive.

---

## TP: Canary Document Opened

**Rule:** SP-800001  
**Expected:** ALERT  
**Severity:** CRITICAL | Confidence: 98  
**MITRE:** T1083

**Scenario:** An attacker browsing a file share opens a canary XLSX file while
performing internal reconnaissance. The file has no business use — any access is
evidence of unauthorized browsing.

```json
{
  "_comment": "TRUE POSITIVE — SP-800001: Canary document opened by unexpected user",
  "rule_id": "SP-800001",
  "expected_result": "ALERT",
  "severity": "CRITICAL",
  "confidence": 98,
  "scenario": "Attacker browsing HR share opens canary XLSX 'Employee_Salaries_2024.xlsx' — no user has a legitimate reason to open this file",
  "mitre": "T1083",
  "event": {
    "sourcetype": "WinEventLog:Security",
    "EventCode": "4663",
    "host": "fileserver-01",
    "ObjectType": "File",
    "ObjectName": "\\\\fileserver-01\\HR_Archive\\Legacy\\Employee_Salaries_2024.xlsx",
    "SubjectUserName": "jsmith",
    "SubjectDomainName": "CORP",
    "ProcessName": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
    "AccessMask": "0x1",
    "time": "2024-01-15T14:33:21Z"
  },
  "why_tp": [
    "File path contains 'canary' or matches the known canary document list",
    "No user has a business reason to open this specific file — it is a honey document",
    "Access via Excel directly — user was browsing the share and opened it",
    "Confidence 98: Near-zero false positive rate by design"
  ],
  "analyst_action": [
    "IMMEDIATELY: Determine what jsmith has been accessing in the last 1 hour",
    "Check: Has jsmith accessed other sensitive directories (Finance, HR, Executive)?",
    "Check: Are there network connections from jsmith's workstation to external IPs?",
    "Check: Correlate with authentication logs — is this the real jsmith or a compromised account?",
    "Escalate: All canary alerts are high-priority — investigate within 15 minutes"
  ]
}
```

---

## TP: Honey Credential Used (Windows Authentication)

**Rule:** SP-800002  
**Expected:** ALERT  
**Severity:** CRITICAL | Confidence: 98  
**MITRE:** T1078

**Scenario:** An attacker dumps credentials from LSASS and finds a honey credential
injected by the deception platform. When they attempt to use it, the authentication
fires the alert.

```json
{
  "_comment": "TRUE POSITIVE — SP-800002: Honey AD credential used for authentication",
  "rule_id": "SP-800002",
  "expected_result": "ALERT",
  "severity": "CRITICAL",
  "confidence": 98,
  "scenario": "Honey credential 'svc_honey_db01' used for network logon — this account exists only in LSASS memory as a deception token",
  "mitre": "T1078",
  "event": {
    "sourcetype": "WinEventLog:Security",
    "EventCode": "4624",
    "host": "dc01.corp.local",
    "TargetUserName": "svc_honey_db01",
    "TargetDomainName": "CORP",
    "LogonType": "3",
    "IpAddress": "10.0.1.45",
    "WorkstationName": "workstation-22",
    "AuthenticationPackageName": "NTLM",
    "time": "2024-01-15T02:51:00Z"
  },
  "why_tp": [
    "svc_honey_db01 is a honey account — it is never used by any legitimate service",
    "Logon Type 3 (Network) means the credential was used remotely — not local process",
    "NTLM authentication at 02:51 — classic post-LSASS dump reuse pattern",
    "Source is workstation-22 — not the server where svc_honey_db01 would legitimately run",
    "Confidence 98: This account cannot be used legitimately"
  ],
  "analyst_action": [
    "IMMEDIATELY: Isolate workstation-22 — it is the source of credential use",
    "IMMEDIATELY: Check workstation-22 for LSASS dump tools (Mimikatz, procdump, etc.)",
    "Check: When was the last legitimate login on workstation-22?",
    "Check: What other accounts were used from workstation-22 in the last 2 hours?",
    "Preserve: Memory image of workstation-22 before any changes"
  ]
}
```

---

!!! info "No False Positive Fixtures for Deception Rules"

    Deception rules are architected to have zero false positives. A honey credential
    is never used legitimately. A canary document is never opened in the normal course
    of business. If you see a canary alert that appears to be a false positive, the
    deception resource was not properly isolated — fix the canary, not the rule.

    **The correct response to a canary alert is always: investigate.**
