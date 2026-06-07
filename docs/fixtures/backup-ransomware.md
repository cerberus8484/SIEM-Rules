# Detection Examples — Backup & Ransomware

Four fixtures covering VSS deletion, backup service termination, and their legitimate
administrative counterparts.

---

## TP: VSS Shadow Copy Deleted

**Rule:** SP-730001  
**Expected:** ALERT  
**Severity:** CRITICAL | Confidence: 93  
**MITRE:** T1490

**Scenario:** Ransomware operator deletes all VSS shadow copies before encrypting —
the most common ransomware preparatory action.

```json
{
  "_comment": "TRUE POSITIVE — SP-730001: VSS shadow copy deleted by non-admin process",
  "rule_id": "SP-730001",
  "expected_result": "ALERT",
  "severity": "CRITICAL",
  "confidence": 93,
  "scenario": "vssadmin delete shadows /all /quiet executed from a non-system context — classic ransomware preparatory step",
  "mitre": "T1490",
  "event": {
    "sourcetype": "WinEventLog:Security",
    "EventCode": "4688",
    "host": "fileserver-01",
    "user": "CORP\\jdoe",
    "NewProcessName": "C:\\Windows\\System32\\vssadmin.exe",
    "CommandLine": "vssadmin delete shadows /all /quiet",
    "ParentProcessName": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\update.exe",
    "time": "2024-01-15T03:14:00Z"
  },
  "why_tp": [
    "vssadmin delete shadows /all is the single most common pre-encryption step for ransomware",
    "Parent process is update.exe in user's Temp folder — not a legitimate backup tool",
    "User jdoe is a regular domain user, not a backup admin",
    "Executed at 03:14 — outside business hours, no maintenance window active"
  ],
  "analyst_action": [
    "IMMEDIATELY: Isolate fileserver-01 from the network",
    "Check: Are any files being renamed with unusual extensions? (SP-730010)",
    "Check: Has the backup service been stopped? (SP-730002)",
    "Preserve: Take a memory image of fileserver-01 before shutdown",
    "Escalate: Activate IR plan — ransomware precursor confirmed"
  ]
}
```

---

## FP: Scheduled Weekly VSS Cleanup

**Rule:** SP-730001  
**Expected:** NO_ALERT

```json
{
  "_comment": "FALSE POSITIVE — SP-730001: Scheduled VSS cleanup by approved backup software",
  "rule_id": "SP-730001",
  "expected_result": "NO_ALERT",
  "scenario": "Veeam backup job deletes old shadow copies as part of scheduled maintenance every Sunday 02:00",
  "event": {
    "sourcetype": "WinEventLog:Security",
    "EventCode": "4688",
    "host": "backupserver-01",
    "user": "CORP\\svc_veeam",
    "NewProcessName": "C:\\Windows\\System32\\vssadmin.exe",
    "CommandLine": "vssadmin delete shadows /all /quiet",
    "ParentProcessName": "C:\\Program Files\\Veeam\\Backup and Replication\\Veeam.Backup.Service.exe",
    "time": "2024-01-14T02:00:05Z"
  },
  "why_fp": [
    "Parent process is Veeam.Backup.Service.exe — the approved backup software",
    "User is svc_veeam — the dedicated backup service account",
    "Host is backupserver-01 — the backup infrastructure server",
    "Execution at exactly 02:00 matches the configured weekly maintenance window"
  ],
  "tuning_recommendation": [
    "Suppress for user=svc_veeam AND host=backupserver-01 AND ParentProcess contains 'Veeam'",
    "Do NOT suppress broadly for all vssadmin calls — scope tightly to backup service account and host"
  ]
}
```

---

## TP: Backup Service Killed via sc.exe

**Rule:** SP-730002  
**Expected:** ALERT  
**Severity:** CRITICAL | Confidence: 90  
**MITRE:** T1489

```json
{
  "_comment": "TRUE POSITIVE — SP-730002: Backup service stopped by unexpected user",
  "rule_id": "SP-730002",
  "expected_result": "ALERT",
  "severity": "CRITICAL",
  "confidence": 90,
  "scenario": "VSSService and Veeam services stopped via sc.exe by a non-admin user account — ransomware disabling backup before encryption",
  "mitre": "T1489",
  "event": {
    "sourcetype": "WinEventLog:System",
    "EventCode": "7036",
    "host": "fileserver-01",
    "user": "CORP\\jdoe",
    "param1": "Veeam Backup Service",
    "param2": "stopped",
    "CommandLine": "sc stop VeeamBackupSvc && sc stop VSS",
    "time": "2024-01-15T03:13:55Z"
  },
  "why_tp": [
    "Backup service stopped 5 seconds before VSS shadow copies deleted (correlated with SP-730001)",
    "User jdoe has no authorization to stop backup services",
    "Double service stop (VSS + Veeam) in one command — ransomware playbook",
    "Confirms active ransomware attack in progress alongside SP-730001"
  ],
  "analyst_action": [
    "Correlate with SP-730001 event from same host and user — ransomware confirmed",
    "IMMEDIATELY: Network isolate the host",
    "Do NOT restart services — preserve forensic state",
    "Activate IR plan"
  ]
}
```

---

## FP: Storage Lifecycle Rule Matching Alert Pattern

**Rule:** SP-730018 (Immutable Bucket Policy Changed)  
**Expected:** NO_ALERT

```json
{
  "_comment": "FALSE POSITIVE — SP-730018: S3 lifecycle rule update matching immutability pattern",
  "rule_id": "SP-730018",
  "expected_result": "NO_ALERT",
  "scenario": "DevOps team updates S3 bucket lifecycle rule — policy change looks like Object Lock modification but is only expiry rule",
  "event": {
    "sourcetype": "aws:cloudtrail",
    "eventName": "PutBucketLifecycleConfiguration",
    "requestParameters.bucketName": "prod-logs-archive",
    "userIdentity.arn": "arn:aws:iam::123456789012:role/DevOpsRole",
    "userIdentity.sessionContext.sessionIssuer.userName": "DevOpsRole",
    "sourceIPAddress": "10.0.0.50",
    "time": "2024-01-15T10:00:00Z"
  },
  "why_fp": [
    "PutBucketLifecycleConfiguration modifies expiry rules, not Object Lock settings",
    "Object Lock is controlled by PutObjectLockConfiguration — different API call",
    "Source is an internal DevOps role from corporate IP — authorized actor",
    "Bucket is a logs archive, not the primary backup target"
  ],
  "tuning_recommendation": [
    "Scope rule to PutObjectLockConfiguration specifically, not lifecycle rules",
    "Add filter: requestParameters must contain 'ObjectLockEnabled' key"
  ]
}
```
