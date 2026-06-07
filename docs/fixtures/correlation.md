# Detection Examples — Correlation Chains

Four fixtures covering multi-stage attack chains and their legitimate counterparts.

---

## TP: Account Takeover Chain (3 Stages)

**Rule:** SP-810001  
**Expected:** ALERT  
**Severity:** CRITICAL | Confidence: dynamic (risk-score derived)  
**MITRE:** T1078

**Scenario:** Attacker compromises an Okta account: multiple auth failures followed by
MFA factor enrollment (on attacker's device) followed by AWS API reconnaissance.

```json
{
  "_comment": "TRUE POSITIVE — SP-810001: Account Takeover Chain (auth_failure + mfa_change + aws_recon)",
  "rule_ids": ["SP-810001"],
  "expected_result": "ALERT",
  "severity": "CRITICAL",
  "confidence": 85,
  "scenario": "3-stage ATO chain: 12 Okta login failures, then MFA factor enrolled on new device, then GetCallerIdentity from same source IP — all within 90 minutes",
  "mitre": "T1078",
  "events": [
    {
      "stage": "auth_failure",
      "sourcetype": "okta:system:log",
      "eventType": "user.session.start",
      "outcome.result": "FAILURE",
      "actor.alternateId": "alice@corp.local",
      "client.ipAddress": "203.0.113.55",
      "count": 12,
      "time": "2024-01-15T13:00:00Z"
    },
    {
      "stage": "mfa_change",
      "sourcetype": "okta:system:log",
      "eventType": "user.mfa.factor.activate",
      "actor.alternateId": "alice@corp.local",
      "client.ipAddress": "203.0.113.55",
      "target[0].displayName": "Google Authenticator (new device)",
      "time": "2024-01-15T13:47:00Z"
    },
    {
      "stage": "aws_recon",
      "sourcetype": "aws:cloudtrail",
      "eventName": "GetCallerIdentity",
      "userIdentity.sessionContext.sessionIssuer.userName": "alice",
      "sourceIPAddress": "203.0.113.55",
      "time": "2024-01-15T14:28:00Z"
    }
  ],
  "why_tp": [
    "3 distinct attack stages within 90 minutes — exceeds minimum chain threshold",
    "Same source IP 203.0.113.55 across all stages — single actor confirmed",
    "MFA enrollment on a new device following auth failures — credential stuffing + MFA addition",
    "AWS GetCallerIdentity immediately after MFA add — privilege verification after takeover"
  ],
  "analyst_action": [
    "IMMEDIATELY: Suspend alice@corp.local in Okta",
    "IMMEDIATELY: Revoke all active Okta sessions for alice",
    "Check: What AWS actions were performed after GetCallerIdentity?",
    "Check: Were any IAM roles assumed or users created?",
    "Contact: Notify alice via alternative channel — her account is compromised"
  ]
}
```

---

## FP: Legitimate IT Admin Batch Operations

**Rule:** SP-810001  
**Expected:** NO_ALERT

```json
{
  "_comment": "FALSE POSITIVE — SP-810001: IT helpdesk MFA reset + admin re-auth + AWS audit",
  "rule_ids": ["SP-810001"],
  "expected_result": "NO_ALERT",
  "scenario": "IT admin resets a user's MFA, then re-authenticates themselves, then runs an AWS cost audit — three stages that look like ATO chain but are unrelated",
  "events": [
    {
      "stage": "mfa_change",
      "sourcetype": "okta:system:log",
      "eventType": "user.mfa.factor.activate",
      "actor.alternateId": "it.helpdesk@corp.local",
      "actor.type": "SystemPrincipal",
      "target[0].displayName": "bob@corp.local",
      "client.ipAddress": "10.0.1.20"
    },
    {
      "stage": "auth_success",
      "sourcetype": "okta:system:log",
      "eventType": "user.session.start",
      "outcome.result": "SUCCESS",
      "actor.alternateId": "it.helpdesk@corp.local",
      "client.ipAddress": "10.0.1.20"
    },
    {
      "stage": "aws_recon",
      "sourcetype": "aws:cloudtrail",
      "eventName": "GetCallerIdentity",
      "userIdentity.arn": "arn:aws:iam::123456789012:role/FinanceAuditRole",
      "sourceIPAddress": "10.0.1.20"
    }
  ],
  "why_fp": [
    "All events originate from 10.0.1.20 — the known IT helpdesk workstation IP",
    "Actor is it.helpdesk SystemPrincipal for MFA operation — automated provisioning system",
    "Auth stage shows SUCCESS, not failure — no credential stuffing pattern",
    "MFA change target is a different user (bob) — not self-enrollment by attacker",
    "AWS role is FinanceAuditRole — pre-approved access, not opportunistic recon"
  ],
  "tuning_recommendation": [
    "Exclude events where source IP is in the corporate IT admin range (10.0.1.0/24)",
    "Require auth_failure stage — SUCCESS does not indicate account takeover",
    "Require MFA change to be self-enrollment (actor == target) for ATO relevance"
  ]
}
```

---

## TP: Ransomware Prep Chain

**Rule:** SP-810019  
**Expected:** ALERT  
**Severity:** CRITICAL | Confidence: 92  
**MITRE:** T1490/T1489/T1486

```json
{
  "_comment": "TRUE POSITIVE — SP-810019: Backup Wiper Chain (VSS + service kill + file rename)",
  "rule_ids": ["SP-810019"],
  "expected_result": "ALERT",
  "severity": "CRITICAL",
  "confidence": 92,
  "scenario": "Three backup wiper steps within 4 minutes: backup service stopped, VSS shadows deleted, then mass file rename with .locked extension",
  "mitre": "T1490",
  "events": [
    {
      "rule_id": "SP-730002",
      "stage": "backup_service_kill",
      "host": "fileserver-01",
      "user": "CORP\\jdoe",
      "CommandLine": "sc stop VeeamBackupSvc",
      "time": "2024-01-15T03:13:55Z"
    },
    {
      "rule_id": "SP-730001",
      "stage": "vss_deletion",
      "host": "fileserver-01",
      "user": "CORP\\jdoe",
      "CommandLine": "vssadmin delete shadows /all /quiet",
      "time": "2024-01-15T03:14:01Z"
    },
    {
      "rule_id": "SP-730010",
      "stage": "mass_rename",
      "host": "fileserver-01",
      "file_renames": 2847,
      "new_extension": ".locked",
      "time": "2024-01-15T03:17:44Z"
    }
  ],
  "why_tp": [
    "Three-stage chain completed in under 4 minutes — automated ransomware execution",
    "All stages on same host (fileserver-01) and same user (jdoe) — single actor",
    "File rename count 2847 in 3 minutes — not human-speed, ransomware loop",
    "Extension '.locked' matches known ransomware family signatures"
  ],
  "analyst_action": [
    "IMMEDIATELY: Cut network access to fileserver-01 — encryption in progress",
    "IMMEDIATELY: Alert all users to stop working on network shares",
    "Check: Has the ransomware spread laterally (other hosts showing SP-730001)?",
    "Preserve: Do NOT turn off the server — suspend VM if possible for forensics",
    "Recovery: Restore from offline/immutable backup — do NOT pay ransom without CISO approval"
  ]
}
```

---

## FP: Authorized Red Team Exercise

**Rule:** SP-810001  
**Expected:** NO_ALERT

```json
{
  "_comment": "FALSE POSITIVE — SP-810001: Authorized penetration test creating correlation chain",
  "rule_ids": ["SP-810001"],
  "expected_result": "NO_ALERT",
  "scenario": "Authorized red team running account takeover simulation with pre-approved test account rt_test_user@corp.local",
  "event": {
    "sourcetype": "okta:system:log",
    "eventType": "user.session.start",
    "outcome.result": "FAILURE",
    "actor.alternateId": "rt_test_user@corp.local",
    "client.ipAddress": "10.10.10.100",
    "time": "2024-01-15T10:00:00Z"
  },
  "why_fp": [
    "Account rt_test_user is in the pre-approved red team test account list",
    "Source IP 10.10.10.100 is the registered red team engagement IP range",
    "Red team schedule in change management system covers this date/time window",
    "Engagement letter and SOC notification exist for this test"
  ],
  "tuning_recommendation": [
    "Maintain a lookup of authorized red team accounts and IPs",
    "Suppress correlation rules (not atomic rules) for accounts in the pentest allowlist",
    "Require SOC-acknowledged change ticket before adding to allowlist"
  ]
}
```
