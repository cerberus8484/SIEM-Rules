# Backup / Resilience Pack

**20 rules — Splunk — Impact tactic**

The Backup pack detects ransomware preparatory actions targeting backup infrastructure.
Rules fire on VSS deletion, backup service termination, immutable storage bypass attempts,
and multi-signal ransomware readiness chains.

---

## Pack Summary

| Property | Value |
|---|---|
| Pack Directory | `backup/` |
| ID Range | SP-730001 – SP-730020 |
| Platforms | Splunk |
| Rules | 20 |
| MITRE Tactic | Impact (T1490, T1489, T1486, T1529) |
| Min Confidence | 78 |

---

## Threat Model

Ransomware actors consistently follow the same playbook before encrypting:

1. **Discovery** — enumerate backup software, list shadow copies
2. **Disable backups** — `vssadmin delete shadows`, stop backup services
3. **Bypass immutability** — disable Object Lock, modify retention policies
4. **Encrypt** — mass file rename, encrypt-in-place

This pack covers steps 1–3 plus indicators of step 4.

---

## Rule Inventory

| Rule ID | Name | Severity | Confidence | Technique |
|---|---|---|---|---|
| SP-730001 | VSS Shadow Copy Deleted | CRITICAL | 93 | T1490 |
| SP-730002 | Backup Service Killed | CRITICAL | 90 | T1489 |
| SP-730003 | Veeam Agent Disabled | HIGH | 85 | T1489 |
| SP-730004 | S3 Object Lock Disabled | CRITICAL | 92 | T1490 |
| SP-730005 | Azure Backup Soft Delete Disabled | CRITICAL | 90 | T1490 |
| SP-730006 | Backup Job Schedule Deleted | HIGH | 82 | T1490 |
| SP-730007 | Restic Repo Key Rotated Unexpectedly | HIGH | 78 | T1490 |
| SP-730008 | Offsite Replication Target Removed | CRITICAL | 88 | T1490 |
| SP-730009 | Backup Log Files Cleared | HIGH | 85 | T1070 |
| SP-730010 | Mass File Rename (Ransomware Pattern) | CRITICAL | 92 | T1486 |
| SP-730011 | Encryption Utility Executed | HIGH | 82 | T1486 |
| SP-730012 | Backup Admin Account Created | HIGH | 80 | T1136 |
| SP-730013 | Backup Network Share Unmounted | HIGH | 82 | T1490 |
| SP-730014 | Cloud Snapshot Deleted | CRITICAL | 90 | T1490 |
| SP-730015 | Windows Backup Configuration Wiped | CRITICAL | 93 | T1490 |
| SP-730016 | Tape Library SNMP Disabled | MEDIUM | 70 | T1562 |
| SP-730017 | Backup Policy Tampered | HIGH | 85 | T1490 |
| SP-730018 | Immutable Bucket Policy Changed | CRITICAL | 92 | T1490 |
| SP-730019 | Backup Test Job Never Ran (Anomaly) | MEDIUM | 65 | T1490 |
| SP-730020 | Ransomware Readiness Score | CRITICAL | 90 | T1490/T1489/T1486 |

---

## Splunk SPL Example

```splunk-spl
`comment("
SP-730001 | VSS Shadow Copy Deleted
tactic=Impact | technique=T1490
severity=CRITICAL | confidence=93
platform=splunk | status=stable | version=1.0
")`
index=windows (sourcetype=WinEventLog:System OR sourcetype=WinEventLog:Security)
    (EventCode=524 OR EventCode=7036 OR EventCode=4688)
| where (match(CommandLine,"(?i)vssadmin.*delete.*shadows") OR
         match(CommandLine,"(?i)wmic.*shadowcopy.*delete") OR
         match(CommandLine,"(?i)bcdedit.*recoveryenabled.*no"))
| eval rule_id="SP-730001"
| eval tactic="Impact", technique="T1490"
| eval severity="CRITICAL", confidence=93
| table _time host user CommandLine ParentCommandLine rule_id severity confidence
```

---

## Test Fixtures

| Fixture | Type | Scenario |
|---|---|---|
| `tp_vss_deletion.json` | TRUE POSITIVE | `vssadmin delete shadows /all` from non-admin user |
| `tp_backup_service_killed.json` | TRUE POSITIVE | Veeam service STOP via sc.exe |
| `fp_legitimate_vss_cleanup.json` | FALSE POSITIVE | Scheduled weekly VSS cleanup by backup admin |
| `fp_storage_maintenance.json` | FALSE POSITIVE | S3 lifecycle rule expiry matching alert pattern |

---

## Tuning Recommendations

!!! warning "VSS deletion is almost never legitimate outside a defined maintenance window"
    SP-730001 should fire on any process other than your approved backup software.
    Add a suppression only for the specific service account and host running scheduled
    VSS management — never suppress broadly.

!!! tip "Correlate with SP-810019 (Backup Wiper Chain)"
    Individual backup events might be legitimate. Chain them: if SP-730001 + SP-730002
    fire within 30 minutes on the same host, escalate immediately regardless of
    any individual suppression.
