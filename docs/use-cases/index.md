# Use Case Catalog

Detection use cases for Splunk and IBM QRadar, mapped to the 28 SIEM-Rules rule packs.
Each use case includes threat description, data sources, platform-specific queries, MITRE
ATT&CK mapping, severity, and response actions.

---

## Summary

| Metric | Value |
|---|---|
| Total use cases | 46 |
| Splunk SPL queries | 46 |
| QRadar AQL queries | 46 |
| MITRE techniques covered | 38 |
| MITRE tactics covered | 11 |
| Rule packs covered | 28 |

---

## Full Use Case Table

| ID | Title | Category | MITRE | Severity | Splunk | QRadar |
|---|---|---|---|---|---|---|
| [UC-001](ransomware.md#uc-001) | VSS Shadow Copy Deletion | Ransomware | T1490 | Critical | ✅ | ✅ |
| [UC-002](ransomware.md#uc-002) | Backup Service Kill Chain | Ransomware | T1489 | Critical | ✅ | ✅ |
| [UC-003](ransomware.md#uc-003) | Boot Recovery Disabled via BCDEdit | Ransomware | T1490 | Critical | ✅ | ✅ |
| [UC-004](ransomware.md#uc-004) | Ransom Note File Drop | Ransomware | T1486 | Critical | ✅ | ✅ |
| [UC-005](ransomware.md#uc-005) | Ransomware Precursor Kill Chain (Correlation) | Ransomware | T1490+T1489 | Critical | ✅ | ✅ |
| [UC-006](credential-theft.md#uc-006) | LSASS Memory Dump via ProcDump | Credential Theft | T1003.001 | Critical | ✅ | ✅ |
| [UC-007](credential-theft.md#uc-007) | Mimikatz Execution | Credential Theft | T1003 | Critical | ✅ | ✅ |
| [UC-008](credential-theft.md#uc-008) | DCSync Attack | Credential Theft | T1003.006 | Critical | ✅ | ✅ |
| [UC-009](credential-theft.md#uc-009) | Kerberoasting — GetUserSPNs | Credential Theft | T1558.003 | High | ✅ | ✅ |
| [UC-010](credential-theft.md#uc-010) | NTDS.dit Extraction | Credential Theft | T1003.003 | Critical | ✅ | ✅ |
| [UC-011](credential-theft.md#uc-011) | SAM/SECURITY Hive Dump via Reg | Credential Theft | T1003.002 | Critical | ✅ | ✅ |
| [UC-012](lateral-movement.md#uc-012) | PsExec Lateral Movement | Lateral Movement | T1570 | High | ✅ | ✅ |
| [UC-013](lateral-movement.md#uc-013) | WMI Remote Execution | Lateral Movement | T1047 | High | ✅ | ✅ |
| [UC-014](lateral-movement.md#uc-014) | RDP Lateral Movement | Lateral Movement | T1021.001 | High | ✅ | ✅ |
| [UC-015](lateral-movement.md#uc-015) | WinRM / PowerShell Remoting | Lateral Movement | T1021.006 | High | ✅ | ✅ |
| [UC-016](lateral-movement.md#uc-016) | Pass-the-Hash / Pass-the-Ticket | Lateral Movement | T1550 | Critical | ✅ | ✅ |
| [UC-017](initial-access-execution.md#uc-017) | Office Macro Spawning Shell | Initial Access | T1566 / T1204 | High | ✅ | ✅ |
| [UC-018](initial-access-execution.md#uc-018) | Encoded PowerShell Execution | Execution | T1059.001 | High | ✅ | ✅ |
| [UC-019](initial-access-execution.md#uc-019) | certutil Download Cradle | Execution | T1105 | High | ✅ | ✅ |
| [UC-020](initial-access-execution.md#uc-020) | mshta / regsvr32 LOLBin Execution | Execution | T1218 | High | ✅ | ✅ |
| [UC-021](initial-access-execution.md#uc-021) | WMIC Process Create Remote | Execution | T1047 | High | ✅ | ✅ |
| [UC-022](initial-access-execution.md#uc-022) | Malicious Email Attachment Execution | Initial Access | T1566.001 | High | ✅ | ✅ |
| [UC-023](persistence.md#uc-023) | Registry Run Key Persistence | Persistence | T1547.001 | Medium | ✅ | ✅ |
| [UC-024](persistence.md#uc-024) | WMI Event Subscription Persistence | Persistence | T1546.003 | High | ✅ | ✅ |
| [UC-025](persistence.md#uc-025) | Scheduled Task Created by Script | Persistence | T1053.005 | Medium | ✅ | ✅ |
| [UC-026](persistence.md#uc-026) | New Service Installation | Persistence | T1543.003 | Medium | ✅ | ✅ |
| [UC-027](c2-beaconing.md#uc-027) | C2 Beaconing — Periodic Outbound | C2 | T1071 | High | ✅ | ✅ |
| [UC-028](c2-beaconing.md#uc-028) | DNS Tunneling | C2 | T1071.004 | High | ✅ | ✅ |
| [UC-029](c2-beaconing.md#uc-029) | Cobalt Strike Named Pipe | C2 | T1090 | Critical | ✅ | ✅ |
| [UC-030](c2-beaconing.md#uc-030) | Known C2 Port Outbound | C2 | T1571 | High | ✅ | ✅ |
| [UC-031](identity-iam.md#uc-031) | AWS Root Account Login | Identity/IAM | T1078.004 | Critical | ✅ | ✅ |
| [UC-032](identity-iam.md#uc-032) | Privileged Account Login from New Location | Identity/IAM | T1078 | High | ✅ | ✅ |
| [UC-033](identity-iam.md#uc-033) | MFA Bypass / Impossible Travel | Identity/IAM | T1078 | Critical | ✅ | ✅ |
| [UC-034](identity-iam.md#uc-034) | Okta Admin Role Granted | Identity/IAM | T1098 | High | ✅ | ✅ |
| [UC-035](identity-iam.md#uc-035) | Entra ID — Bulk User Deletion | Identity/IAM | T1531 | Critical | ✅ | ✅ |
| [UC-036](cloud.md#uc-036) | AWS CloudTrail Disabled | Cloud | T1562.008 | Critical | ✅ | ✅ |
| [UC-037](cloud.md#uc-037) | S3 Bucket Public Access Granted | Cloud | T1530 | High | ✅ | ✅ |
| [UC-038](cloud.md#uc-038) | Azure — New Owner Role Assignment | Cloud | T1098.003 | High | ✅ | ✅ |
| [UC-039](cloud.md#uc-039) | GCP — Service Account Key Created | Cloud | T1552.001 | Medium | ✅ | ✅ |
| [UC-040](cloud.md#uc-040) | Kubernetes — Privileged Pod Launched | Cloud/Container | T1610 | Critical | ✅ | ✅ |
| [UC-041](linux-macos.md#uc-041) | Linux — Crontab Persistence | Linux | T1053.003 | Medium | ✅ | ✅ |
| [UC-042](linux-macos.md#uc-042) | Linux — SUID Binary Created | Linux | T1548.001 | High | ✅ | ✅ |
| [UC-043](linux-macos.md#uc-043) | macOS — LaunchAgent Persistence | macOS | T1543.001 | Medium | ✅ | ✅ |
| [UC-044](email-database.md#uc-044) | Email — Mass Internal Forwarding Rule | Email | T1114.003 | High | ✅ | ✅ |
| [UC-045](email-database.md#uc-045) | Database — Privileged Bulk Export | Database | T1005 | High | ✅ | ✅ |
| [UC-046](deception-correlation.md#uc-046) | Canary Document Accessed | Deception | T1083 | Critical | ✅ | ✅ |

---

## Coverage by MITRE Tactic

| Tactic | Use Cases |
|---|---|
| Initial Access | UC-017, UC-022 |
| Execution | UC-017, UC-018, UC-019, UC-020, UC-021, UC-013 |
| Persistence | UC-023, UC-024, UC-025, UC-026, UC-041, UC-042, UC-043 |
| Privilege Escalation | UC-042 |
| Defense Evasion | UC-003, UC-020, UC-036 |
| Credential Access | UC-006, UC-007, UC-008, UC-009, UC-010, UC-011 |
| Discovery | UC-046 |
| Lateral Movement | UC-012, UC-013, UC-014, UC-015, UC-016 |
| Collection | UC-044, UC-045 |
| Command & Control | UC-027, UC-028, UC-029, UC-030 |
| Impact | UC-001, UC-002, UC-003, UC-004, UC-005 |

---

## Data Sources Required

| Platform | Required Data Source | Covers |
|---|---|---|
| **Splunk** | `index=windows` — Windows Security/System/Sysmon | UC-001 to UC-030 |
| **Splunk** | `index=linux` / `index=syslog` | UC-041, UC-042 |
| **Splunk** | `index=aws` / `sourcetype=aws:cloudtrail` | UC-031, UC-036, UC-037 |
| **Splunk** | `index=azure` / `sourcetype=azure:audit` | UC-033, UC-035, UC-038 |
| **Splunk** | `index=okta` / `sourcetype=okta:system` | UC-034 |
| **Splunk** | `index=email` / `sourcetype=o365:management` | UC-022, UC-044 |
| **QRadar** | `Log Source: Windows Security Event Log` | UC-001 to UC-030 |
| **QRadar** | `Log Source: Amazon AWS CloudTrail` | UC-031, UC-036, UC-037 |
| **QRadar** | `Log Source: Microsoft Azure` | UC-033, UC-035, UC-038 |
| **QRadar** | `Log Source: Okta` | UC-034 |
| **QRadar** | `Log Source: Microsoft Office 365` | UC-022, UC-044 |

---

## Downloads

- [use-cases.csv](../data/use-cases.csv) — Full catalog as CSV
- [SIEM-Rules GitHub](https://github.com/cerberus8484/SIEM-Rules) — Rule source
