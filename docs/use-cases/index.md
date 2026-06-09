# Use Case Catalog — 200 Detection Use Cases

This catalog covers all **200 production-ready detection use cases** across Splunk SPL and QRadar AQL.
Each use case includes a MITRE ATT&CK mapping, severity rating, confidence score, and full query implementations.

---

## Quick Stats

| Metric | Value |
|---|---|
| **Total Use Cases** | 200 |
| **Splunk SPL Coverage** | 200 / 200 |
| **QRadar AQL Coverage** | 200 / 200 |
| **MITRE Tactics Covered** | 14 |
| **MITRE Techniques Covered** | 85+ |
| **Critical Severity** | 78 |
| **High Severity** | 99 |
| **Medium / Low Severity** | 23 |

---

## Category Overview

| Category | UC Range | Count | File |
|---|---|---|---|
| Ransomware | UC-001–005 | 5 | [ransomware.md](ransomware.md) |
| Credential Theft | UC-006–011 | 6 | [credential-theft.md](credential-theft.md) |
| Lateral Movement | UC-012–016 | 5 | [lateral-movement.md](lateral-movement.md) |
| Initial Access & Execution | UC-017–022 | 6 | [initial-access-execution.md](initial-access-execution.md) |
| Persistence | UC-023–026 | 4 | [persistence.md](persistence.md) |
| C2 & Beaconing | UC-027–030 | 4 | [c2-beaconing.md](c2-beaconing.md) |
| Identity & IAM | UC-031–035 | 5 | [identity-iam.md](identity-iam.md) |
| Cloud & Container | UC-036–040 | 5 | [cloud.md](cloud.md) |
| Linux & macOS | UC-041–043 | 3 | [linux-macos.md](linux-macos.md) |
| Email & Database | UC-044–045 | 2 | [email-database.md](email-database.md) |
| Deception & Correlation | UC-046 | 1 | [deception-correlation.md](deception-correlation.md) |
| Defense Evasion | UC-047–060 | 14 | [defense-evasion.md](defense-evasion.md) |
| Discovery & Recon | UC-061–070 | 10 | [discovery.md](discovery.md) |
| Privilege Escalation | UC-071–078 | 8 | [privilege-escalation.md](privilege-escalation.md) |
| Exfiltration & DLP | UC-079–088 | 10 | [exfiltration.md](exfiltration.md) |
| VPN & Remote Access | UC-089–096 | 8 | [vpn-remote-access.md](vpn-remote-access.md) |
| Email Extended | UC-097–102 | 6 | [more-email.md](more-email.md) |
| Database Extended | UC-103–109 | 7 | [more-database.md](more-database.md) |
| Cloud Extended | UC-110–120 | 11 | [more-cloud.md](more-cloud.md) |
| Linux & macOS Extended | UC-121–130 | 10 | [more-linux-macos.md](more-linux-macos.md) |
| DevOps & CI/CD | UC-131–138 | 8 | [devops-cicd.md](devops-cicd.md) |
| C2 Extended | UC-139–142 | 4 | [more-c2.md](more-c2.md) |
| Lateral Movement Extended | UC-143–148 | 6 | [more-lateral-movement.md](more-lateral-movement.md) |
| Credential Theft Extended | UC-149–155 | 7 | [more-credential-theft.md](more-credential-theft.md) |
| Correlation Extended | UC-156–163 | 8 | [more-correlation.md](more-correlation.md) |
| Ransomware Extended | UC-164–167 | 4 | [more-ransomware.md](more-ransomware.md) |
| Identity & IAM Extended | UC-168–175 | 8 | [more-identity-iam.md](more-identity-iam.md) |
| Persistence Extended | UC-176–181 | 6 | [more-persistence.md](more-persistence.md) |
| Initial Access Extended | UC-182–187 | 6 | [more-initial-access.md](more-initial-access.md) |
| Deception Extended | UC-188–200 | 13 | [more-deception.md](more-deception.md) |

---

## Full Master Catalog

| ID | Title | Category | MITRE | Severity |
|---|---|---|---|---|
| [UC-001](ransomware.md#uc-001) | VSS Shadow Copy Deletion | Ransomware | T1490 | 🔴 Critical |
| [UC-002](ransomware.md#uc-002) | Backup Service Kill Chain | Ransomware | T1489 | 🔴 Critical |
| [UC-003](ransomware.md#uc-003) | Boot Recovery Disabled via BCDEdit | Ransomware | T1490 | 🔴 Critical |
| [UC-004](ransomware.md#uc-004) | Ransom Note File Drop | Ransomware | T1486 | 🔴 Critical |
| [UC-005](ransomware.md#uc-005) | Ransomware Precursor Kill Chain (Correlation) | Ransomware | T1490+T1489 | 🔴 Critical |
| [UC-006](credential-theft.md#uc-006) | LSASS Memory Dump via ProcDump | Credential Theft | T1003.001 | 🔴 Critical |
| [UC-007](credential-theft.md#uc-007) | Mimikatz Execution | Credential Theft | T1003 | 🔴 Critical |
| [UC-008](credential-theft.md#uc-008) | DCSync Attack | Credential Theft | T1003.006 | 🔴 Critical |
| [UC-009](credential-theft.md#uc-009) | Kerberoasting — GetUserSPNs | Credential Theft | T1558.003 | 🟠 High |
| [UC-010](credential-theft.md#uc-010) | NTDS.dit Extraction | Credential Theft | T1003.003 | 🔴 Critical |
| [UC-011](credential-theft.md#uc-011) | SAM/SECURITY Hive Dump via Reg | Credential Theft | T1003.002 | 🔴 Critical |
| [UC-012](lateral-movement.md#uc-012) | PsExec Lateral Movement | Lateral Movement | T1570 | 🟠 High |
| [UC-013](lateral-movement.md#uc-013) | WMI Remote Execution | Lateral Movement | T1047 | 🟠 High |
| [UC-014](lateral-movement.md#uc-014) | RDP Lateral Movement | Lateral Movement | T1021.001 | 🟠 High |
| [UC-015](lateral-movement.md#uc-015) | WinRM / PowerShell Remoting | Lateral Movement | T1021.006 | 🟠 High |
| [UC-016](lateral-movement.md#uc-016) | Pass-the-Hash / Pass-the-Ticket | Lateral Movement | T1550 | 🔴 Critical |
| [UC-017](initial-access-execution.md#uc-017) | Office Macro Spawning Shell | Initial Access | T1566.001 | 🟠 High |
| [UC-018](initial-access-execution.md#uc-018) | Encoded PowerShell Execution | Execution | T1059.001 | 🟠 High |
| [UC-019](initial-access-execution.md#uc-019) | certutil Download Cradle | Execution | T1105 | 🟠 High |
| [UC-020](initial-access-execution.md#uc-020) | mshta / regsvr32 LOLBin Execution | Execution | T1218 | 🟠 High |
| [UC-021](initial-access-execution.md#uc-021) | WMIC Process Create Remote | Execution | T1047 | 🟠 High |
| [UC-022](initial-access-execution.md#uc-022) | Malicious Email Attachment Execution | Initial Access | T1566.001 | 🟠 High |
| [UC-023](persistence.md#uc-023) | Registry Run Key Persistence | Persistence | T1547.001 | 🟡 Medium |
| [UC-024](persistence.md#uc-024) | WMI Event Subscription Persistence | Persistence | T1546.003 | 🟠 High |
| [UC-025](persistence.md#uc-025) | Scheduled Task Created by Script | Persistence | T1053.005 | 🟡 Medium |
| [UC-026](persistence.md#uc-026) | New Service Installation | Persistence | T1543.003 | 🟡 Medium |
| [UC-027](c2-beaconing.md#uc-027) | C2 Beaconing — Periodic Outbound | C2 | T1071 | 🟠 High |
| [UC-028](c2-beaconing.md#uc-028) | DNS Tunneling | C2 | T1071.004 | 🟠 High |
| [UC-029](c2-beaconing.md#uc-029) | Cobalt Strike Named Pipe | C2 | T1090 | 🔴 Critical |
| [UC-030](c2-beaconing.md#uc-030) | Known C2 Port Outbound | C2 | T1571 | 🟠 High |
| [UC-031](identity-iam.md#uc-031) | AWS Root Account Login | Identity/IAM | T1078.004 | 🔴 Critical |
| [UC-032](identity-iam.md#uc-032) | Privileged Account Login from New Location | Identity/IAM | T1078 | 🟠 High |
| [UC-033](identity-iam.md#uc-033) | MFA Bypass / Impossible Travel | Identity/IAM | T1078 | 🔴 Critical |
| [UC-034](identity-iam.md#uc-034) | Okta Admin Role Granted | Identity/IAM | T1098 | 🟠 High |
| [UC-035](identity-iam.md#uc-035) | Entra ID — Bulk User Deletion | Identity/IAM | T1531 | 🔴 Critical |
| [UC-036](cloud.md#uc-036) | AWS CloudTrail Disabled | Cloud | T1562.008 | 🔴 Critical |
| [UC-037](cloud.md#uc-037) | S3 Bucket Public Access Granted | Cloud | T1530 | 🟠 High |
| [UC-038](cloud.md#uc-038) | Azure — New Owner Role Assignment | Cloud | T1098.003 | 🟠 High |
| [UC-039](cloud.md#uc-039) | GCP — Service Account Key Created | Cloud | T1552.001 | 🟡 Medium |
| [UC-040](cloud.md#uc-040) | Kubernetes — Privileged Pod Launched | Cloud/Container | T1610 | 🔴 Critical |
| [UC-041](linux-macos.md#uc-041) | Linux — Crontab Persistence | Linux | T1053.003 | 🟡 Medium |
| [UC-042](linux-macos.md#uc-042) | Linux — SUID Binary Created | Linux | T1548.001 | 🟠 High |
| [UC-043](linux-macos.md#uc-043) | macOS — LaunchAgent Persistence | macOS | T1543.001 | 🟡 Medium |
| [UC-044](email-database.md#uc-044) | Email — Mass Internal Forwarding Rule | Email | T1114.003 | 🟠 High |
| [UC-045](email-database.md#uc-045) | Database — Privileged Bulk Export | Database | T1005 | 🟠 High |
| [UC-046](deception-correlation.md#uc-046) | Canary Document Accessed | Deception | T1083 | 🔴 Critical |
| [UC-047](defense-evasion.md#uc-047) | AMSI Bypass | Defense Evasion | T1562.001 | 🟠 High |
| [UC-048](defense-evasion.md#uc-048) | ETW Patch / Event Tracing Disabled | Defense Evasion | T1562.006 | 🟠 High |
| [UC-049](defense-evasion.md#uc-049) | Event Log Cleared | Defense Evasion | T1070.001 | 🟠 High |
| [UC-050](defense-evasion.md#uc-050) | Sysmon Driver Unloaded / Service Stopped | Defense Evasion | T1562.001 | 🔴 Critical |
| [UC-051](defense-evasion.md#uc-051) | Timestomping | Defense Evasion | T1070.006 | 🟡 Medium |
| [UC-052](defense-evasion.md#uc-052) | Process Hollowing / Injection | Defense Evasion | T1055.012 | 🔴 Critical |
| [UC-053](defense-evasion.md#uc-053) | Parent PID Spoofing | Defense Evasion | T1134.004 | 🟠 High |
| [UC-054](defense-evasion.md#uc-054) | Windows Defender Disabled | Defense Evasion | T1562.001 | 🟠 High |
| [UC-055](defense-evasion.md#uc-055) | Audit Policy Changed | Defense Evasion | T1562.002 | 🟠 High |
| [UC-056](defense-evasion.md#uc-056) | Signed Binary DLL Sideloading | Defense Evasion | T1574.002 | 🟠 High |
| [UC-057](defense-evasion.md#uc-057) | Binary Masquerading (Renamed Tool) | Defense Evasion | T1036.003 | 🟠 High |
| [UC-058](defense-evasion.md#uc-058) | Indicator Removal — Malicious File Deleted | Defense Evasion | T1070.004 | 🟡 Medium |
| [UC-059](defense-evasion.md#uc-059) | Firewall Rule Added to Allow Inbound | Defense Evasion | T1562.004 | 🟠 High |
| [UC-060](defense-evasion.md#uc-060) | Execution from Unusual Location | Defense Evasion | T1036.005 | 🟡 Medium |
| [UC-061](discovery.md#uc-061) | BloodHound / SharpHound AD Enumeration | Discovery | T1087.002 | 🟠 High |
| [UC-062](discovery.md#uc-062) | Port Scan from Internal Host | Discovery | T1046 | 🟠 High |
| [UC-063](discovery.md#uc-063) | LDAP Enumeration for Domain Admins | Discovery | T1069.002 | 🟡 Medium |
| [UC-064](discovery.md#uc-064) | Local Admin Discovery via net Commands | Discovery | T1087.001 | 🟡 Medium |
| [UC-065](discovery.md#uc-065) | Domain Controller Discovery | Discovery | T1018 | 🟠 High |
| [UC-066](discovery.md#uc-066) | SMB Share Enumeration | Discovery | T1135 | 🟡 Medium |
| [UC-067](discovery.md#uc-067) | Security Software Discovery | Discovery | T1518.001 | 🟡 Medium |
| [UC-068](discovery.md#uc-068) | SystemInfo / OS Recon | Discovery | T1082 | 🔵 Low |
| [UC-069](discovery.md#uc-069) | Active Directory ACL Abuse Discovery | Discovery | T1069.002 | 🟠 High |
| [UC-070](discovery.md#uc-070) | Browser History / Credential Discovery | Discovery | T1555.003 | 🟠 High |
| [UC-071](privilege-escalation.md#uc-071) | UAC Bypass | Privilege Escalation | T1548.002 | 🟠 High |
| [UC-072](privilege-escalation.md#uc-072) | Token Impersonation (SeImpersonatePrivilege) | Privilege Escalation | T1134.001 | 🔴 Critical |
| [UC-073](privilege-escalation.md#uc-073) | Kernel Exploit Indicators | Privilege Escalation | T1068 | 🔴 Critical |
| [UC-074](privilege-escalation.md#uc-074) | Always Install Elevated Abuse | Privilege Escalation | T1548.002 | 🟠 High |
| [UC-075](privilege-escalation.md#uc-075) | Sudo Abuse on Linux | Privilege Escalation | T1548.003 | 🟠 High |
| [UC-076](privilege-escalation.md#uc-076) | Shadow Credentials (Windows) | Privilege Escalation | T1556.006 | 🔴 Critical |
| [UC-077](privilege-escalation.md#uc-077) | DLL Search Order Hijacking | Privilege Escalation | T1574.001 | 🟠 High |
| [UC-078](privilege-escalation.md#uc-078) | ACL-Based Privilege Escalation (AD Object) | Privilege Escalation | T1098 | 🔴 Critical |
| [UC-079](exfiltration.md#uc-079) | Large Outbound Data Transfer | Exfiltration | T1048 | 🟠 High |
| [UC-080](exfiltration.md#uc-080) | Cloud Storage Upload (Suspicious) | Exfiltration | T1567.002 | 🟠 High |
| [UC-081](exfiltration.md#uc-081) | USB Mass Storage Device Connected | Exfiltration | T1052.001 | 🟡 Medium |
| [UC-082](exfiltration.md#uc-082) | Data Archiving Before Exfiltration | Exfiltration | T1560.001 | 🟠 High |
| [UC-083](exfiltration.md#uc-083) | Screen Capture / Keylogger Indicators | Exfiltration | T1113+T1056 | 🟠 High |
| [UC-084](exfiltration.md#uc-084) | Git Clone / Code Repository Exfiltration | Exfiltration | T1213 | 🟠 High |
| [UC-085](exfiltration.md#uc-085) | FTP / SCP / rsync Exfiltration | Exfiltration | T1048.003 | 🟠 High |
| [UC-086](exfiltration.md#uc-086) | ICMP Tunneling | Exfiltration | T1095 | 🟠 High |
| [UC-087](exfiltration.md#uc-087) | Clipboard Data Access | Exfiltration | T1115 | 🟡 Medium |
| [UC-088](exfiltration.md#uc-088) | Mass File Access on File Server | Exfiltration | T1005 | 🟠 High |
| [UC-089](vpn-remote-access.md#uc-089) | VPN Brute Force | VPN/Remote Access | T1110.001 | 🟠 High |
| [UC-090](vpn-remote-access.md#uc-090) | New User First VPN Login | VPN/Remote Access | T1078 | 🟡 Medium |
| [UC-091](vpn-remote-access.md#uc-091) | VPN Login Outside Business Hours | VPN/Remote Access | T1078 | 🟡 Medium |
| [UC-092](vpn-remote-access.md#uc-092) | VPN Login from Tor or Known VPS | VPN/Remote Access | T1090.003 | 🟠 High |
| [UC-093](vpn-remote-access.md#uc-093) | Concurrent VPN Sessions (Same User) | VPN/Remote Access | T1078 | 🟠 High |
| [UC-094](vpn-remote-access.md#uc-094) | VPN Access to Sensitive Admin Systems | VPN/Remote Access | T1021.001 | 🟠 High |
| [UC-095](vpn-remote-access.md#uc-095) | Admin Account VPN Login (Non-PAW) | VPN/Remote Access | T1078.002 | 🟠 High |
| [UC-096](vpn-remote-access.md#uc-096) | VPN Split Tunnel Bypass | VPN/Remote Access | T1599 | 🟡 Medium |
| [UC-097](more-email.md#uc-097) | BEC / CEO Impersonation Email | Email | T1566.002 | 🔴 Critical |
| [UC-098](more-email.md#uc-098) | Inbox Rule Deleting Security Alerts | Email | T1564.008 | 🟠 High |
| [UC-099](more-email.md#uc-099) | Domain Lookalike Registration Alert | Email | T1566 | 🟠 High |
| [UC-100](more-email.md#uc-100) | External Sender with Internal Display Name | Email | T1566.001 | 🟠 High |
| [UC-101](more-email.md#uc-101) | Executable Attachment Delivered | Email | T1566.001 | 🟠 High |
| [UC-102](more-email.md#uc-102) | Phishing Link Clicked (Internal Alert) | Email | T1566.002 | 🟠 High |
| [UC-103](more-database.md#uc-103) | xp_cmdshell Enabled or Called | Database | T1059.003 | 🔴 Critical |
| [UC-104](more-database.md#uc-104) | Database Admin Account Created via SQL | Database | T1136 | 🔴 Critical |
| [UC-105](more-database.md#uc-105) | SQL Injection Burst | Database | T1190 | 🟠 High |
| [UC-106](more-database.md#uc-106) | Database Backup Exported to External Share | Database | T1005 | 🟠 High |
| [UC-107](more-database.md#uc-107) | Linked Server Used for Lateral Movement | Database | T1021 | 🟠 High |
| [UC-108](more-database.md#uc-108) | Database Brute Force Login | Database | T1110.001 | 🟠 High |
| [UC-109](more-database.md#uc-109) | Sensitive Table Queried by New Account | Database | T1078 | 🟠 High |
| [UC-110](more-cloud.md#uc-110) | AWS IAM User Created Outside Terraform | Cloud/AWS | T1136.003 | 🟠 High |
| [UC-111](more-cloud.md#uc-111) | AWS Security Group Opened to 0.0.0.0/0 | Cloud/AWS | T1562.004 | 🟠 High |
| [UC-112](more-cloud.md#uc-112) | AWS KMS Key Scheduled for Deletion | Cloud/AWS | T1485 | 🔴 Critical |
| [UC-113](more-cloud.md#uc-113) | AWS GuardDuty Disabled | Cloud/AWS | T1562.008 | 🔴 Critical |
| [UC-114](more-cloud.md#uc-114) | Lambda Function with Admin IAM Role | Cloud/AWS | T1578.002 | 🟠 High |
| [UC-115](more-cloud.md#uc-115) | EC2 IMDSv1 Access (Credential Theft Vector) | Cloud/AWS | T1552.005 | 🟠 High |
| [UC-116](more-cloud.md#uc-116) | Azure Conditional Access Policy Disabled | Cloud/Azure | T1562.001 | 🔴 Critical |
| [UC-117](more-cloud.md#uc-117) | Azure PIM Role Activation Outside Hours | Cloud/Azure | T1078.004 | 🟠 High |
| [UC-118](more-cloud.md#uc-118) | Kubernetes kubectl exec into Production Pod | Cloud/K8s | T1609 | 🟠 High |
| [UC-119](more-cloud.md#uc-119) | Kubernetes Secret Enumeration | Cloud/K8s | T1552.007 | 🟠 High |
| [UC-120](more-cloud.md#uc-120) | Kubernetes DaemonSet with hostPID | Cloud/K8s | T1611 | 🔴 Critical |
| [UC-121](more-linux-macos.md#uc-121) | Sudoers File Modified | Linux | T1548.003 | 🔴 Critical |
| [UC-122](more-linux-macos.md#uc-122) | SSH Authorized Keys Modified | Linux | T1098.004 | 🔴 Critical |
| [UC-123](more-linux-macos.md#uc-123) | LD_PRELOAD Injection | Linux | T1574.006 | 🟠 High |
| [UC-124](more-linux-macos.md#uc-124) | /etc/passwd or /etc/shadow Modified | Linux | T1136.001 | 🔴 Critical |
| [UC-125](more-linux-macos.md#uc-125) | Potential Rootkit Indicators on Linux | Linux | T1014 | 🔴 Critical |
| [UC-126](more-linux-macos.md#uc-126) | macOS TCC Database Modified | macOS | T1548 | 🟠 High |
| [UC-127](more-linux-macos.md#uc-127) | macOS Login Items / LaunchAgent Added | macOS | T1543.001 | 🟡 Medium |
| [UC-128](more-linux-macos.md#uc-128) | Gatekeeper Disabled on macOS | macOS | T1553.001 | 🟠 High |
| [UC-129](more-linux-macos.md#uc-129) | Linux Reverse Shell via Bash/Python/Perl | Linux | T1059.004 | 🔴 Critical |
| [UC-130](more-linux-macos.md#uc-130) | Cron Job Added as Root on Linux | Linux | T1053.003 | 🟠 High |
| [UC-131](devops-cicd.md#uc-131) | Hardcoded Secret Pushed to Git Repository | DevOps/CI-CD | T1552.001 | 🔴 Critical |
| [UC-132](devops-cicd.md#uc-132) | Malicious Package Installed via npm/pip | DevOps/CI-CD | T1195.001 | 🟠 High |
| [UC-133](devops-cicd.md#uc-133) | GitHub Actions Secret Exfiltration | DevOps/CI-CD | T1552 | 🔴 Critical |
| [UC-134](devops-cicd.md#uc-134) | Pipeline Injection via Untrusted Input | DevOps/CI-CD | T1059 | 🟠 High |
| [UC-135](devops-cicd.md#uc-135) | Unverified Docker Image in Production Build | DevOps/CI-CD | T1195.002 | 🟠 High |
| [UC-136](devops-cicd.md#uc-136) | Terraform Destroy Run Against Production | DevOps/CI-CD | T1485 | 🔴 Critical |
| [UC-137](devops-cicd.md#uc-137) | CI Runner Privilege Escalation | DevOps/CI-CD | T1611 | 🔴 Critical |
| [UC-138](devops-cicd.md#uc-138) | Dependency Confusion Attack Vector | DevOps/CI-CD | T1195.001 | 🔴 Critical |
| [UC-139](more-c2.md#uc-139) | C2 via Living-Off-the-Land Binary | C2 | T1218 | 🟠 High |
| [UC-140](more-c2.md#uc-140) | C2 via Cloud Storage API | C2 | T1102 | 🟠 High |
| [UC-141](more-c2.md#uc-141) | Domain Fronting via CDN | C2 | T1090.004 | 🟠 High |
| [UC-142](more-c2.md#uc-142) | Fast-Flux DNS (C2 Infrastructure) | C2 | T1568.001 | 🟠 High |
| [UC-143](more-lateral-movement.md#uc-143) | DCOM Lateral Movement | Lateral Movement | T1021.003 | 🟠 High |
| [UC-144](more-lateral-movement.md#uc-144) | Remote Registry Access | Lateral Movement | T1112 | 🟡 Medium |
| [UC-145](more-lateral-movement.md#uc-145) | PrintNightmare / Print Spooler Exploit | Lateral Movement | T1068 | 🔴 Critical |
| [UC-146](more-lateral-movement.md#uc-146) | Token Impersonation for Lateral Movement | Lateral Movement | T1134.001 | 🔴 Critical |
| [UC-147](more-lateral-movement.md#uc-147) | SMB Enumeration / Spray from Internal Host | Lateral Movement | T1046 | 🟠 High |
| [UC-148](more-lateral-movement.md#uc-148) | Pass-the-Hash via Overpass-the-Hash | Lateral Movement | T1550.002 | 🔴 Critical |
| [UC-149](more-credential-theft.md#uc-149) | AS-REP Roasting | Credential Theft | T1558.004 | 🟠 High |
| [UC-150](more-credential-theft.md#uc-150) | Golden Ticket Attack | Credential Theft | T1558.001 | 🔴 Critical |
| [UC-151](more-credential-theft.md#uc-151) | DPAPI Secret Extraction | Credential Theft | T1555.004 | 🟠 High |
| [UC-152](more-credential-theft.md#uc-152) | Password Spraying — Active Directory | Credential Theft | T1110.003 | 🟠 High |
| [UC-153](more-credential-theft.md#uc-153) | Credential Stuffing Attack | Credential Theft | T1110.004 | 🟠 High |
| [UC-154](more-credential-theft.md#uc-154) | Windows Vault / Credential Manager Dump | Credential Theft | T1555.004 | 🟠 High |
| [UC-155](more-credential-theft.md#uc-155) | Silver Ticket Attack | Credential Theft | T1558.002 | 🔴 Critical |
| [UC-156](more-correlation.md#uc-156) | Full Attack Chain: Recon→Cred→Lateral→DC | Correlation | Multi-Stage | 🔴 Critical |
| [UC-157](more-correlation.md#uc-157) | Brute Force then Successful Login | Correlation | T1110 | 🔴 Critical |
| [UC-158](more-correlation.md#uc-158) | Recon then Lateral Movement (Same Host) | Correlation | T1087+T1021 | 🟠 High |
| [UC-159](more-correlation.md#uc-159) | BEC Attack Chain | Correlation | Multi-Stage | 🔴 Critical |
| [UC-160](more-correlation.md#uc-160) | Credential Theft then DC Access | Correlation | T1003+T1021 | 🔴 Critical |
| [UC-161](more-correlation.md#uc-161) | Supply Chain Attack Indicator | Correlation | T1195.002 | 🔴 Critical |
| [UC-162](more-correlation.md#uc-162) | Insider Threat Pattern (Anomalous Data Access) | Correlation | T1005 | 🟠 High |
| [UC-163](more-correlation.md#uc-163) | Zero-Day Proxy Exploitation Chain | Correlation | T1190 | 🔴 Critical |
| [UC-164](more-ransomware.md#uc-164) | Double Extortion — Data Staging Before Encryption | Ransomware | T1560+T1048 | 🔴 Critical |
| [UC-165](more-ransomware.md#uc-165) | LockBit 3.0 Specific Indicators | Ransomware | T1486+T1490 | 🔴 Critical |
| [UC-166](more-ransomware.md#uc-166) | Ransomware Deployed via RDP | Ransomware | T1021.001+T1486 | 🔴 Critical |
| [UC-167](more-ransomware.md#uc-167) | Network Share Encryption (File Server) | Ransomware | T1486 | 🔴 Critical |
| [UC-168](more-identity-iam.md#uc-168) | Account Lockout Storm | Identity/IAM | T1531 | 🟠 High |
| [UC-169](more-identity-iam.md#uc-169) | Service Account Interactive Login | Identity/IAM | T1078.002 | 🟠 High |
| [UC-170](more-identity-iam.md#uc-170) | Admin Login from Non-PAW Workstation | Identity/IAM | T1078 | 🟠 High |
| [UC-171](more-identity-iam.md#uc-171) | Stale Account Reactivated | Identity/IAM | T1078 | 🟠 High |
| [UC-172](more-identity-iam.md#uc-172) | Domain Admins Group Changed | Identity/IAM | T1098 | 🔴 Critical |
| [UC-173](more-identity-iam.md#uc-173) | Password Never Expires Accounts (Newly Set) | Identity/IAM | T1098 | 🟡 Medium |
| [UC-174](more-identity-iam.md#uc-174) | Entra ID Privileged Role Assigned | Identity/IAM | T1098.003 | 🔴 Critical |
| [UC-175](more-identity-iam.md#uc-175) | Guest Account Added to Privileged Azure Resource | Identity/IAM | T1098.003 | 🟠 High |
| [UC-176](more-persistence.md#uc-176) | COM Object Hijacking | Persistence | T1546.015 | 🟠 High |
| [UC-177](more-persistence.md#uc-177) | Image File Execution Options (IFEO) Debugger | Persistence | T1546.012 | 🔴 Critical |
| [UC-178](more-persistence.md#uc-178) | AppCert / AppInit DLL Persistence | Persistence | T1546.009 | 🟠 High |
| [UC-179](more-persistence.md#uc-179) | Office Add-in Persistence | Persistence | T1137.006 | 🟠 High |
| [UC-180](more-persistence.md#uc-180) | Screensaver Executable Modified | Persistence | T1546.002 | 🟡 Medium |
| [UC-181](more-persistence.md#uc-181) | Startup Folder Drop (New Executable) | Persistence | T1547.001 | 🟠 High |
| [UC-182](more-initial-access.md#uc-182) | ISO / IMG Mount for Malware Delivery | Initial Access | T1553.005 | 🟠 High |
| [UC-183](more-initial-access.md#uc-183) | OneNote Embedded Payload Execution | Initial Access | T1566.001 | 🟠 High |
| [UC-184](more-initial-access.md#uc-184) | HTML Smuggling (JavaScript Dropper) | Initial Access | T1027.006 | 🟠 High |
| [UC-185](more-initial-access.md#uc-185) | Malicious LNK File Execution | Initial Access | T1204.002 | 🟠 High |
| [UC-186](more-initial-access.md#uc-186) | Teams / Slack Phishing File Delivery | Initial Access | T1566.003 | 🟠 High |
| [UC-187](more-initial-access.md#uc-187) | Zip Password-Protected Archive with Executable | Initial Access | T1566.001 | 🟠 High |
| [UC-188](more-deception.md#uc-188) | Honey Credential Used (Windows Authentication) | Deception | T1003 | 🔴 Critical |
| [UC-189](more-deception.md#uc-189) | Canary AWS Access Key Used | Deception | T1552.001 | 🔴 Critical |
| [UC-190](more-deception.md#uc-190) | Honey User Account Logon | Deception | T1078 | 🔴 Critical |
| [UC-191](more-deception.md#uc-191) | Canary DNS Query Detected | Deception | T1567 | 🔴 Critical |
| [UC-192](more-deception.md#uc-192) | Honeypot Port Scan Detected | Deception | T1046 | 🟠 High |
| [UC-193](more-deception.md#uc-193) | Honeyfile Accessed on File Server | Deception | T1083 | 🔴 Critical |
| [UC-194](more-deception.md#uc-194) | Honey Share Accessed (Network Lateral Detection) | Deception | T1135 | 🔴 Critical |
| [UC-195](more-deception.md#uc-195) | Honey Token Service Accessed (HTTP) | Deception | T1078 | 🟠 High |
| [UC-196](more-deception.md#uc-196) | Decoy SSH Key Used on Bastion | Deception | T1098.004 | 🔴 Critical |
| [UC-197](more-deception.md#uc-197) | Fake MFA Bypass Attempt on Honey Identity | Deception | T1621 | 🟠 High |
| [UC-198](more-deception.md#uc-198) | Canary API Key Used in Production API | Deception | T1552 | 🔴 Critical |
| [UC-199](more-deception.md#uc-199) | LDAP Honey Object Queried | Deception | T1069.002 | 🟠 High |
| [UC-200](more-deception.md#uc-200) | Global Deception Alert Aggregation | Deception/Correlation | Multiple | 🔴 Critical |

---

## Filter by Severity

### 🔴 Critical (78 UCs)

UC-001, UC-002, UC-003, UC-004, UC-005, UC-006, UC-007, UC-008, UC-010, UC-011,
UC-016, UC-029, UC-031, UC-033, UC-035, UC-036, UC-040, UC-046, UC-050, UC-052,
UC-072, UC-073, UC-076, UC-078, UC-097, UC-103, UC-104, UC-112, UC-113, UC-116,
UC-120, UC-121, UC-122, UC-124, UC-125, UC-129, UC-131, UC-133, UC-136, UC-137,
UC-138, UC-145, UC-146, UC-148, UC-150, UC-155, UC-156, UC-157, UC-159, UC-160,
UC-161, UC-163, UC-164, UC-165, UC-166, UC-167, UC-172, UC-174, UC-177, UC-188,
UC-189, UC-190, UC-191, UC-193, UC-194, UC-196, UC-198, UC-200

### 🟠 High (99 UCs)

UC-009, UC-012, UC-013, UC-014, UC-015, UC-017, UC-018, UC-019, UC-020, UC-021,
UC-022, UC-024, UC-027, UC-028, UC-030, UC-032, UC-034, UC-037, UC-038, UC-042,
UC-044, UC-045, UC-047, UC-048, UC-049, UC-053, UC-054, UC-055, UC-056, UC-057,
UC-059, UC-061, UC-062, UC-065, UC-069, UC-070, UC-071, UC-074, UC-075, UC-077,
UC-079, UC-080, UC-082, UC-083, UC-084, UC-085, UC-086, UC-088, UC-089, UC-092,
UC-093, UC-094, UC-095, UC-098, UC-099, UC-100, UC-101, UC-102, UC-105, UC-106,
UC-107, UC-108, UC-109, UC-110, UC-111, UC-114, UC-115, UC-117, UC-118, UC-119,
UC-123, UC-126, UC-128, UC-130, UC-132, UC-134, UC-135, UC-139, UC-140, UC-141,
UC-142, UC-143, UC-147, UC-149, UC-151, UC-152, UC-153, UC-154, UC-158, UC-162,
UC-168, UC-169, UC-170, UC-171, UC-175, UC-176, UC-178, UC-179, UC-181, UC-182,
UC-183, UC-184, UC-185, UC-186, UC-187, UC-192, UC-195, UC-197, UC-199

### 🟡 Medium / 🔵 Low (23 UCs)

UC-023, UC-025, UC-026, UC-039, UC-041, UC-043, UC-051, UC-058, UC-060, UC-063,
UC-064, UC-066, UC-067, UC-068, UC-081, UC-087, UC-090, UC-091, UC-096, UC-127,
UC-144, UC-173, UC-180

---

## Filter by MITRE Tactic

| Tactic | UC Count | Example UCs |
|---|---|---|
| Initial Access | 14 | UC-017, UC-022, UC-182–187 |
| Execution | 6 | UC-018–021, UC-103, UC-134 |
| Persistence | 16 | UC-023–026, UC-041, UC-043, UC-176–181 |
| Privilege Escalation | 8 | UC-071–078 |
| Defense Evasion | 15 | UC-047–060, UC-139 |
| Credential Access | 13 | UC-006–011, UC-149–155 |
| Discovery | 10 | UC-061–070 |
| Lateral Movement | 11 | UC-012–016, UC-143–148 |
| Collection | 3 | UC-083, UC-087, UC-088 |
| Command & Control | 8 | UC-027–030, UC-139–142 |
| Exfiltration | 10 | UC-079–088 |
| Impact | 11 | UC-001–005, UC-164–167 |
| Identity (IAM) | 16 | UC-031–035, UC-168–175 |
| Deception | 14 | UC-046, UC-188–200 |
