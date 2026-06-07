# Windows & Sysmon Pack

**~400 rules — Splunk + QRadar — the core foundation pack**

The Windows pack covers the full ATT&CK kill chain for Windows environments,
from initial access through impact. It is the largest pack and forms the
detection backbone for any Windows-heavy enterprise.

---

## Pack Summary

| Property | Value |
|---|---|
| Pack Directories | `execution/`, `persistence/`, `defense_evasion/`, `credential_access/`, `c2/`, `lateral_movement/`, `discovery/`, `exfiltration/`, `impact/`, `privilege_escalation/`, `initial_access/` |
| ID Range | SP-100001 – SP-699999 |
| Platforms | Splunk, QRadar |
| Tactics Covered | All 12 MITRE ATT&CK tactics |
| Key Event Sources | WinEventLog:Security, WinEventLog:System, Sysmon (EventCode 1/3/7/8/10/11/13) |

---

## Sub-Pack Overview

### Execution (SP-100001–SP-109999)

Detects command execution through PowerShell, WMI, LOLBins, Office macros, and
scripting interpreters.

**Key rules:**

| Rule ID | Name | Severity | Technique |
|---|---|---|---|
| SP-100001 | PowerShell Encoded Command | HIGH | T1059.001 |
| SP-100002 | WMIC Process Create | HIGH | T1047 |
| SP-100003 | Mshta Executing Remote Script | HIGH | T1218.005 |
| SP-100004 | Certutil Download Cradle | HIGH | T1105 |
| SP-100005 | Regsvr32 Executing SCT | HIGH | T1218.010 |
| SP-100006 | Office Macro Spawning Shell | CRITICAL | T1204.002 |

### Persistence (SP-200001–SP-209999)

Registry Run keys, scheduled tasks, services, COM hijacking, and WMI subscriptions.

**Key rules:**

| Rule ID | Name | Severity | Technique |
|---|---|---|---|
| SP-200001 | Registry Run Key Added | HIGH | T1547.001 |
| SP-200002 | Scheduled Task Created via Schtasks | HIGH | T1053.005 |
| SP-200003 | New Service Created | HIGH | T1543.003 |
| SP-200004 | WMI Event Subscription Created | CRITICAL | T1546.003 |

### Credential Access (SP-300001–SP-309999)

LSASS memory access, DCSync, Kerberoasting, AS-REP roasting, and credential dumping.

**Key rules:**

| Rule ID | Name | Severity | Technique |
|---|---|---|---|
| SP-300001 | LSASS Memory Read (MiniDump) | CRITICAL | T1003.001 |
| SP-300002 | DCSync (DS-Replication-Get-Changes-All) | CRITICAL | T1003.006 |
| SP-300003 | Kerberoasting (SPN Enumeration) | HIGH | T1558.003 |
| SP-300004 | AS-REP Roasting (No Preauth) | HIGH | T1558.004 |

### Lateral Movement (SP-400001–SP-409999)

PsExec remote execution, WMI remote, Pass-the-Hash, and RDP abuse.

**Key rules:**

| Rule ID | Name | Severity | Technique |
|---|---|---|---|
| SP-400001 | PsExec Service Installed on Target | CRITICAL | T1570 |
| SP-400002 | WMI Remote Command Execution | HIGH | T1047 |
| SP-400003 | Pass-the-Hash (NTLM Type 3 Logon) | CRITICAL | T1550.002 |
| SP-400004 | RDP Lateral Movement (EventCode 4624 Type 10) | HIGH | T1021.001 |

### Defense Evasion (SP-500001–SP-509999)

Process injection, AMSI bypass, masquerading, log clearing, and timestomping.

**Key rules:**

| Rule ID | Name | Severity | Technique |
|---|---|---|---|
| SP-500001 | Process Hollowing Detected | CRITICAL | T1055.012 |
| SP-500002 | AMSI Provider Registry Modified | HIGH | T1562.001 |
| SP-500003 | Security Log Cleared (EventCode 1102) | CRITICAL | T1070.001 |
| SP-500004 | Suspicious Executable in Temp Folder | HIGH | T1027 |

---

## Sysmon Dependency

Many rules in this pack require Sysmon to be deployed with the
[SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) or
[Olaf Hartong](https://github.com/olafhartong/sysmon-modular) configuration.

Required Sysmon Event IDs:

| Event ID | Type | Used By |
|---|---|---|
| 1 | Process Create | Execution, Persistence, LOLBins |
| 3 | Network Connect | C2 / Beaconing |
| 7 | Image Loaded | Defense Evasion, Injection |
| 8 | CreateRemoteThread | Process Injection |
| 10 | ProcessAccess | Credential Access (LSASS) |
| 11 | FileCreate | Persistence, Dropper |
| 13 | RegistryEvent (Set) | Persistence, Evasion |

---

## Splunk Onboarding

```bash
# index your Windows event logs
[monitor://WinEventLog:Security]
index = windows
sourcetype = WinEventLog:Security

[monitor://WinEventLog:Microsoft-Windows-Sysmon/Operational]
index = windows
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```
