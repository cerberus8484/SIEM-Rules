# Rule Packs — Overview

The Enterprise Hunt Pack is organized into 28 detection domains. Each pack covers a
specific threat category with rules tuned to minimize false positives while maintaining
high confidence for true attack patterns.

---

## Pack Inventory

| Pack | ID Range | Rules | Platforms | Tactics |
|---|---|---|---|---|
| [Windows & Sysmon](windows-sysmon.md) | SP-1xxxxx | ~400 | Splunk, QRadar | Exec, Persist, Evade, CredAccess, LM, Disc, Exfil, PrivEsc, IA |
| [Identity / IAM](identity-iam.md) | SP-7xxxxx | 75 | Splunk, QRadar, SecOps, Wazuh | IA, Persist, PrivEsc, CredAccess |
| [Cloud (AWS/Azure/GCP/M365)](cloud.md) | SP-2xxxxx | ~80 | Splunk, QRadar, SecOps, Wazuh | IA, Persist, PrivEsc, Exfil |
| [Linux](linux.md) | SP-3xxxxx | ~60 | Splunk, QRadar | Persist, PrivEsc, Evade |
| [Container / Kubernetes](container-kubernetes.md) | SP-71xxxx | 20 | Splunk | PrivEsc, LM, Persist |
| [DevOps / CI-CD](devops-cicd.md) | SP-72xxxx | 20 | Splunk | IA, CredAccess, Exfil |
| [Backup / Resilience](backup-resilience.md) | SP-73xxxx | 20 | Splunk | Impact |
| [Email Security](email.md) | SP-75xxxx | 20 | Splunk | IA, Collection |
| [Database](database.md) | SP-76xxxx | 20 | Splunk | Exec, Exfil, Impact |
| [VPN / Remote Access](vpn.md) | SP-77xxxx | 20 | Splunk | IA, LM |
| [macOS](macos.md) | SP-78xxxx | 20 | Splunk | Persist, PrivEsc, Evade |
| [DLP / Exfiltration](dlp.md) | SP-79xxxx | 20 | Splunk | Exfil, Collection |
| [Deception / Canary](deception.md) | SP-80xxxx | 15 | Splunk, Wazuh | Collection, CredAccess |
| [Correlation](correlation.md) | SP-81xxxx | 20 | Splunk | Multiple |
| Network | SP-4xxxxx | ~40 | Splunk | Exfil, Disc |
| Web Application | SP-5xxxxx | ~40 | Splunk | IA, Exec |
| Threat Intelligence | SP-6xxxxx | ~40 | Splunk | Multiple |
| Hypervisor / VMware | SP-74xxxx | 20 | Splunk | Persist, Impact |

---

## ID Namespace Reference

All rules follow a structured ID namespace to prevent collisions across packs and platforms:

| Prefix | Platform |
|---|---|
| `SP-` | Splunk SPL |
| `QR-` | QRadar AQL |
| `GS-` | Google SecOps UDM |
| `WZ-` | Wazuh KQL |

| Range | Domain |
|---|---|
| `SP-1xxxxx` | Windows / Sysmon (Exec, Persist, Evade, CredAccess, LM, Disc, Exfil, IA, PrivEsc, Impact, C2) |
| `SP-2xxxxx` | Cloud (AWS CloudTrail, Azure AD, M365, GCP) |
| `SP-3xxxxx` | Linux |
| `SP-4xxxxx` | Network |
| `SP-5xxxxx` | Web Application |
| `SP-6xxxxx` | Threat Intelligence |
| `SP-70xxxx` | Identity / IAM — Generic |
| `SP-71xxxx` | Container / Kubernetes |
| `SP-72xxxx` | DevOps / CI-CD |
| `SP-73xxxx` | Backup / Resilience |
| `SP-74xxxx` | Hypervisor / VMware |
| `SP-75xxxx` | Email Security |
| `SP-76xxxx` | Database |
| `SP-77xxxx` | VPN / Remote Access |
| `SP-78xxxx` | macOS |
| `SP-79xxxx` | DLP / Exfiltration |
| `SP-80xxxx` | Deception / Canary |
| `SP-81xxxx` | Correlation / Multi-Stage |

---

## Severity Distribution

| Severity | Count | Typical Use |
|---|---|---|
| CRITICAL | ~120 | Confirmed attack patterns, near-zero FP (confidence 90+) |
| HIGH | ~350 | Strong indicators, low FP rate (confidence 75–89) |
| MEDIUM | ~420 | Suspicious activity, context-dependent (confidence 55–74) |
| LOW | ~120 | Weak signals, high-volume environments (confidence 35–54) |
| INFO | ~19 | Telemetry enrichment, baselining |

---

## MITRE ATT&CK Coverage

| Tactic | Rules | Key Techniques |
|---|---|---|
| Initial Access | 80+ | T1566, T1078, T1190, T1204 |
| Execution | 120+ | T1059, T1047, T1204, T1569 |
| Persistence | 100+ | T1547, T1053, T1543, T1546 |
| Privilege Escalation | 60+ | T1134, T1548, T1574 |
| Defense Evasion | 90+ | T1055, T1218, T1562, T1070 |
| Credential Access | 80+ | T1003, T1558, T1550, T1110 |
| Discovery | 50+ | T1087, T1069, T1018, T1082 |
| Lateral Movement | 60+ | T1021, T1047, T1570 |
| Collection | 30+ | T1074, T1530, T1560 |
| Command & Control | 50+ | T1071, T1095, T1571, T1048 |
| Exfiltration | 40+ | T1041, T1048, T1567 |
| Impact | 70+ | T1486, T1490, T1489, T1529 |
