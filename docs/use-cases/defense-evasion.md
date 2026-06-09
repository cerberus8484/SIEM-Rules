# Defense Evasion

Use cases for detecting attacker attempts to hide activity, disable defenses, and evade detection.

**Rule packs:** `windows_sysmon`, `execution`

---

## UC-047 — AMSI Bypass {#uc-047}

**Threat:** Attacker patches AmsiScanBuffer in memory to disable AMSI (Antimalware Scan Interface),
allowing malicious PowerShell/VBA to run without antivirus scanning.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 88 |
| **MITRE** | T1562.001 — Impair Defenses: Disable or Modify Tools |
| **Data Sources** | PowerShell 4104 (ScriptBlock), Windows Security 4688 |
| **Rule IDs** | SP-evasion-001 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| where match(ScriptBlockText, "(?i)(AmsiScanBuffer|AmsiInitialize|amsiContext|AmsiUtils|amsiBypass|Reflection\.Assembly.*amsi|[Cc]orrupt.*amsi|patch.*amsi)")
    OR match(ScriptBlockText, "(?i)(0xEB|0x90|VirtualProtect.*amsi|WriteProcessMemory.*amsi)")
| eval technique="T1562.001 - AMSI Bypass"
| table _time, host, user, ScriptBlockText, technique
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "ScriptBlockText" AS "Script", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE "LogSourceType" = 'Microsoft Windows Security Event Log'
    AND EventID = '4104'
    AND (LOWER("ScriptBlockText") LIKE '%amsiscanbuffer%'
        OR LOWER("ScriptBlockText") LIKE '%amsibypass%'
        OR LOWER("ScriptBlockText") LIKE '%amsiutils%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Review full script block log surrounding the bypass attempt
2. Determine what was executed after the bypass (check subsequent 4104 events)
3. Enable PowerShell Constrained Language Mode to reduce bypass surface
4. Check if AMSI providers are intact: `Get-MpComputerStatus`
5. Correlate with Defender/AV alerts on same host

---

## UC-048 — ETW Patch / Event Tracing Disabled {#uc-048}

**Threat:** Attacker patches Event Tracing for Windows (ETW) providers in memory to prevent
PowerShell/AMSI telemetry from being recorded. Used by advanced APT tooling.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 85 |
| **MITRE** | T1562.006 — Impair Defenses: Indicator Blocking |
| **Data Sources** | PowerShell 4104, Sysmon Event 10 |
| **Rule IDs** | SP-evasion-002 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| where match(ScriptBlockText, "(?i)(EtwEventWrite|ntdll.*etw|SilenceEventLogging|Reflection.*ntdll.*EtwEventWrite|NtTraceEvent)")
    OR match(ScriptBlockText, "(?i)(patch.*etw|disable.*etw|0xC3.*etw)")
| table _time, host, user, ScriptBlockText
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "ScriptBlockText" AS "Script", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Microsoft Windows Security Event Log'
    AND EventID = '4104'
    AND (LOWER("ScriptBlockText") LIKE '%etweventwrite%'
        OR LOWER("ScriptBlockText") LIKE '%sil%event%log%'
        OR LOWER("ScriptBlockText") LIKE '%nttraceevent%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. This technique is used by sophisticated threat actors — treat as high-priority IR
2. Enable full process memory scanning if EDR supports it
3. Reboot affected host to restore patched memory (temporary fix)
4. Review what was executed after the ETW patch
5. Verify integrity of ntdll.dll on disk vs memory

---

## UC-049 — Event Log Cleared {#uc-049}

**Threat:** Attacker clears Windows Security or System event log to destroy forensic
evidence. Event 1102 (Security log cleared) or 104 (System log cleared) fires once.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 92 |
| **MITRE** | T1070.001 — Indicator Removal: Clear Windows Event Logs |
| **Data Sources** | Windows Security 1102, Windows System 104 |
| **Rule IDs** | SP-evasion-003 |

### Splunk SPL

```spl
index=windows EventCode IN (1102, 104)
| eval log_type=case(EventCode=1102, "Security Log", EventCode=104, "System Log")
| table _time, host, user, log_type, SubjectUserName
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    QIDNAME(qid) AS "Log Cleared", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID IN ('1102', '104')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Pull surviving logs from SIEM before they expire
2. Check wevtutil history for recent audit policy changes
3. Identify what activity was being hidden — look at Sysmon (separate log, harder to clear)
4. Review who cleared the log (SubjectUserName in Event 1102)
5. Deploy Windows Event Forwarding (WEF) to forward logs to SIEM in real time

---

## UC-050 — Sysmon Driver Unloaded / Service Stopped {#uc-050}

**Threat:** Attacker stops or uninstalls Sysmon to blind endpoint detection. Requires admin
rights and is itself a high-confidence indicator of malicious activity.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 97 |
| **MITRE** | T1562.001 — Impair Defenses: Disable or Modify Tools |
| **Data Sources** | Windows System 7036, Windows Security 4688 |
| **Rule IDs** | SP-evasion-004 |

### Splunk SPL

```spl
index=windows
    (EventCode=7036 AND match(Message, "(?i)Sysmon.*stopped"))
    OR (EventCode=4688 AND match(CommandLine, "(?i)(sysmon.*-u|sc.*stop.*sysmon|fltmc.*unload.*SysmonDrv)"))
| table _time, host, user, CommandLine, Message
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "Command" AS "CommandLine", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE
    (EventID = '7036' AND LOWER("ServiceName") LIKE '%sysmon%')
    OR (LOWER("Command") LIKE '%sysmon%' AND LOWER("Command") LIKE '%-u%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. **Immediate alert** — attacker is actively removing detection capability
2. Re-deploy Sysmon via GPO or SCCM immediately
3. Check what happened on the host in the minutes after Sysmon was stopped
4. Rotate to alternate detection: Windows Event Forwarding, EDR telemetry
5. Treat host as actively compromised

---

## UC-051 — Timestomping {#uc-051}

**Threat:** Attacker modifies file timestamps to blend malicious files with legitimate
system files, making timeline reconstruction harder.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 80 |
| **MITRE** | T1070.006 — Indicator Removal: Timestomp |
| **Data Sources** | Sysmon Event 2 (FileCreateTime) |
| **Rule IDs** | SP-evasion-005 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=2
| where NOT match(Image, "(?i)(msiexec|wusa|TrustedInstaller|tiworker)")
| eval time_delta=abs(strptime(CreationUtcTime,"%Y-%m-%d %H:%M:%S.%Q") - strptime(PreviousCreationUtcTime,"%Y-%m-%d %H:%M:%S.%Q"))
| where time_delta > 86400
| table _time, host, user, TargetFilename, Image, CreationUtcTime, PreviousCreationUtcTime, time_delta
| sort -time_delta
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", "TargetFilename" AS "File",
    "CreationTime" AS "New Timestamp", "PreviousCreationTime" AS "Old Timestamp",
    "process" AS "Modifier", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - File creation time changed'
    AND "process" NOT IN ('msiexec.exe','TrustedInstaller.exe','tiworker.exe')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Compare file creation time vs actual last-write time in MFT ($MFT record)
2. Check IMPHASH and digital signature of the timestomped file
3. Correlate with Sysmon Event 11 — when was the file actually written?
4. Note: Timestomping doesn't affect $MFT last-change timestamp (MACE analysis)
5. Submit file to sandbox for analysis

---

## UC-052 — Process Hollowing / Injection {#uc-052}

**Threat:** Attacker creates a legitimate process (e.g. svchost.exe) in suspended state,
replaces its memory with malicious code, then resumes it. The malicious code runs under
the trusted process identity.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 85 |
| **MITRE** | T1055.012 — Process Injection: Process Hollowing |
| **Data Sources** | Sysmon Events 8/10/25 |
| **Rule IDs** | SP-evasion-006 |

### Splunk SPL

```spl
| union
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=25
     | eval detection="ProcessTampering Event 25"]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8
     | where match(StartModule, "(?i)\\AppData\\|\\Temp\\|\\ProgramData\\")
     | eval detection="Remote Thread from Suspicious DLL"]
| table _time, host, user, SourceImage, TargetImage, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", "SourceProcess" AS "Injector",
    "TargetProcess" AS "Target", QIDNAME(qid) AS "Event",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) IN (
    'Sysmon - Process Tampering','Sysmon - CreateRemoteThread detected')
    AND "TargetProcess" IN ('svchost.exe','explorer.exe','lsass.exe','notepad.exe')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Dump the memory of the injected process for analysis
2. Check the startup path of the injecting process
3. Sysmon Event 25 (ProcessTampering) is the most direct indicator — prioritize
4. Correlate with network connections from the injected process
5. Deploy EDR with memory scanning capability for ongoing detection

---

## UC-053 — Parent PID Spoofing {#uc-053}

**Threat:** Attacker creates a process with a fake parent PID to bypass process tree-based
detections. E.g., spawning powershell.exe claiming to be a child of explorer.exe.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 78 |
| **MITRE** | T1134.004 — Access Token Manipulation: Parent PID Spoofing |
| **Data Sources** | Sysmon Event 1 |
| **Rule IDs** | SP-evasion-007 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(Image,"(?i)(powershell|cmd|wscript|cscript|mshta)\.exe")
    AND match(ParentImage,"(?i)(explorer|outlook|winword|excel|chrome|msedge)\.exe")
| stats count by host, Image, ParentImage, CommandLine, _time
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "process" AS "Child Process", "ParentProcessName" AS "Claimed Parent",
    "Command" AS "CommandLine", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND LOWER("process") IN ('powershell.exe','cmd.exe','wscript.exe')
    AND LOWER("ParentProcessName") IN ('outlook.exe','winword.exe','excel.exe')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Examine the process tree — does the claimed parent PID actually match?
2. Use Sysmon ProcessGUID and ParentProcessGUID to validate the tree
3. This technique is used by Cobalt Strike and advanced tooling — treat as high-priority
4. Correlate with named pipe or network indicators from the same process
5. Memory dump the suspicious process

---

## UC-054 — Windows Defender Disabled {#uc-054}

**Threat:** Attacker disables Windows Defender real-time protection to allow malware
execution without detection. Can be done via PowerShell, Registry, or Group Policy.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 90 |
| **MITRE** | T1562.001 — Impair Defenses: Disable or Modify Tools |
| **Data Sources** | Windows Security 4688, Registry Events, Defender Event 5001 |
| **Rule IDs** | SP-evasion-008 |

### Splunk SPL

```spl
| union
    [search index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
     | where match(CommandLine,"(?i)(Set-MpPreference.*DisableRealtimeMonitoring.*\$true|Add-MpPreference.*ExclusionPath|Set-MpPreference.*DisableIOAVProtection)")
     | eval detection="PowerShell Defender Disable"]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational" EventCode=5001
     | eval detection="Defender Event 5001 - RTP Disabled"]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
     | where match(TargetObject,"(?i)SOFTWARE\\Microsoft\\Windows Defender.*DisableAntiSpyware|DisableRealtimeMonitoring")
         AND Details="DWORD (0x00000001)"
     | eval detection="Registry - Defender Disabled"]
| table _time, host, user, detection, CommandLine
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "Command" AS "CommandLine", QIDNAME(qid) AS "Event",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE
    (LOWER("Command") LIKE '%set-mppreference%disablerealtimemonitoring%true%'
    OR LOWER("Command") LIKE '%add-mppreference%exclusionpath%'
    OR EventID = '5001')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Re-enable Defender: `Set-MpPreference -DisableRealtimeMonitoring $false`
2. Check what was excluded — malware often adds itself to exclusion list
3. Run a full Defender scan after re-enabling
4. Correlate with other evasion techniques on same host
5. Deploy centralized Defender for Endpoint policy via Intune/SCCM to prevent future disable

---

## UC-055 — Audit Policy Changed {#uc-055}

**Threat:** Attacker modifies Windows audit policy to stop logging specific event categories
(e.g., disable logon auditing to hide authentication events).

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 85 |
| **MITRE** | T1562.002 — Impair Defenses: Disable Windows Event Logging |
| **Data Sources** | Windows Security 4719 |
| **Rule IDs** | SP-evasion-009 |

### Splunk SPL

```spl
index=windows EventCode=4719
| where NOT match(SubjectUserName, "(?i)(SYSTEM|\$$)")
| eval policy=SubcategoryGuid, change=AuditPolicyChanges
| table _time, host, SubjectUserName, SubcategoryGuid, SubcategoryId, AuditPolicyChanges
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "SubcategoryId" AS "Policy Changed", "AuditPolicyChanges" AS "Change",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID = '4719'
    AND username NOT IN ('SYSTEM') AND username NOT LIKE '%$'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Restore audit policy via GPO immediately
2. Identify which policy categories were changed (logon? object access? process tracking?)
3. Assess the window of missing logs — what activity may have been hidden?
4. Correlate with other evasion indicators on same host
5. Enable advanced audit policy enforcement via GPO with "No Override" flag

---

## UC-056 — Signed Binary DLL Sideloading {#uc-056}

**Threat:** Attacker drops a malicious DLL in the same directory as a legitimate signed binary.
When the binary loads, it uses the malicious DLL due to DLL search order. The process
appears legitimate but executes attacker code.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 75 |
| **MITRE** | T1574.002 — Hijack Execution Flow: DLL Side-Loading |
| **Data Sources** | Sysmon Event 7 (ImageLoad) |
| **Rule IDs** | SP-evasion-010 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7
| where Signed="false"
    AND match(Image,"(?i)(C:\\Program Files|C:\\Windows)")
    AND NOT match(ImageLoaded,"(?i)(C:\\Windows\\System32|C:\\Windows\\SysWOW64|C:\\Program Files)")
| table _time, host, Image, ImageLoaded, Signed, Hashes
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", "Image" AS "Legitimate Process",
    "ImageLoaded" AS "Loaded DLL", "Signed" AS "Signed",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Image loaded'
    AND "Signed" = 'false'
    AND "Image" LIKE 'C:\\Program Files%'
    AND "ImageLoaded" NOT LIKE 'C:\\Windows\\System32%'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Check if the DLL was expected alongside the signed binary
2. Compare DLL hash against VirusTotal
3. Look for other suspicious unsigned DLLs loaded by the same process
4. Consider deploying ASR rule: "Block untrusted and unsigned processes that run from USB"
5. Check parent directory for recent file drops (Sysmon Event 11)

---

## UC-057 — Binary Masquerading (Renamed Tool) {#uc-057}

**Threat:** Attacker renames a known attack tool (e.g., mimikatz.exe → svchost.exe) to
evade filename-based detection. The OriginalFileName field in Sysmon reveals the true identity.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 82 |
| **MITRE** | T1036.003 — Masquerading: Rename System Utilities |
| **Data Sources** | Sysmon Event 1 |
| **Rule IDs** | SP-evasion-011 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where OriginalFileName!=mvindex(split(Image,"\\"),-1)
    AND match(OriginalFileName,"(?i)(mimikatz|psexec|meterpreter|cobaltstrike|cobaltrike|rubeus|sharpview|lazagne|procdump|netcat|nmap)")
| table _time, host, user, Image, OriginalFileName, CommandLine
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "process" AS "Used Name", "OriginalFileName" AS "True Name",
    "Command" AS "CommandLine", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND LOWER("OriginalFileName") IN ('mimikatz.exe','psexec.c','rubeus.exe','lazagne.exe')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Zero-FP alert — OriginalFileName match on known attack tools
2. Identify where the binary was dropped from (parent process, download URL)
3. Check for other copies of the binary on the same host and network shares
4. Block the file hash at endpoint protection
5. Begin full IR for the affected host

---

## UC-058 — Indicator Removal — Malicious File Deleted {#uc-058}

**Threat:** After execution, malware deletes itself or its dropper to remove forensic evidence.
Sysmon Event 23 captures the file deletion with process and target path.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 72 |
| **MITRE** | T1070.004 — Indicator Removal: File Deletion |
| **Data Sources** | Sysmon Event 23 (FileDelete) |
| **Rule IDs** | SP-evasion-012 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=23
| where match(TargetFilename,"(?i)(\\AppData\\|\\Temp\\|\\ProgramData\\|\\Downloads\\).*\.(exe|dll|ps1|bat|vbs|hta|js|lnk|scr)")
    AND NOT match(Image,"(?i)(MsMpEng|WinDefend|explorer|conhost)")
| table _time, host, user, Image, TargetFilename, Hashes
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "process" AS "Deleting Process", "filename" AS "Deleted File",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - File deleted'
    AND ("filename" LIKE '%\\AppData\\%' OR "filename" LIKE '%\\Temp\\%')
    AND (LOWER("filename") LIKE '%.exe' OR LOWER("filename") LIKE '%.ps1'
        OR LOWER("filename") LIKE '%.dll')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Check Sysmon Event 11 for when the file was first created
2. Retrieve file from VSS/backup before it's overwritten
3. Check Sysmon archived file hash if `ArchiveDirectory` is configured
4. Correlate: what did the process do before deleting itself? (Event 1 context)
5. Enable Sysmon `FileDeleteArchived` to save a copy of deleted files

---

## UC-059 — Firewall Rule Added to Allow Inbound {#uc-059}

**Threat:** Attacker adds a Windows Firewall rule to allow inbound connections to a
backdoor or to open RDP/WinRM from the internet.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 83 |
| **MITRE** | T1562.004 — Impair Defenses: Disable or Modify System Firewall |
| **Data Sources** | Windows Security 4946/4947, Security Audit |
| **Rule IDs** | SP-evasion-013 |

### Splunk SPL

```spl
index=windows EventCode IN (4946, 4947)
| eval action=case(EventCode=4946,"Rule Added",EventCode=4947,"Rule Modified")
| where NOT match(SubjectUserName,"(?i)(SYSTEM|\$$)")
| table _time, host, SubjectUserName, action, RuleAttr, RuleName
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "RuleName" AS "Firewall Rule", QIDNAME(qid) AS "Action",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID IN ('4946','4947')
    AND username NOT IN ('SYSTEM') AND username NOT LIKE '%$'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Review the rule details — what port/protocol was opened? To what scope?
2. Remove the rule if unauthorized: `netsh advfirewall firewall delete rule name="RuleName"`
3. Check if the rule was added to allow a new listening service (Sysmon Event 3)
4. Audit all non-Microsoft firewall rules: `netsh advfirewall firewall show rule name=all`
5. Enforce firewall baseline via GPO to prevent unauthorized rule changes

---

## UC-060 — Execution from Unusual Location {#uc-060}

**Threat:** Executable launched from a user-writable location (AppData, Temp, Downloads, ProgramData)
is a strong indicator of malware — legitimate software installs to Program Files.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 70 |
| **MITRE** | T1036.005 — Masquerading: Match Legitimate Name or Location |
| **Data Sources** | Windows Security 4688, Sysmon Event 1 |
| **Rule IDs** | SP-evasion-014 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where match(Image,"(?i)(\\AppData\\|\\Temp\\|\\ProgramData\\|\\Downloads\\|\\Desktop\\|\\Public\\).*\.exe$")
    AND NOT match(Image,"(?i)(\\AppData\\Local\\Microsoft\\Teams|\\AppData\\Local\\Google\\Chrome|\\AppData\\Local\\Slack)")
| table _time, host, user, Image, ParentImage, CommandLine
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "process" AS "Executable", "ParentProcessName" AS "Parent",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND ("process" LIKE '%\\AppData\\%' OR "process" LIKE '%\\Temp\\%'
        OR "process" LIKE '%\\ProgramData\\%' OR "process" LIKE '%\\Downloads\\%')
    AND "process" NOT LIKE '%\\AppData\\Local\\Microsoft\\Teams%'
    AND "process" NOT LIKE '%\\AppData\\Local\\Google\\Chrome%'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Examine the binary: hash, signature, strings
2. Check what process dropped the binary in that location (Sysmon Event 11 correlation)
3. Establish whether this is a known false positive (portable apps, some installers)
4. Submit unknown hashes to VirusTotal
5. Block execution from AppData/Temp via AppLocker or SRP for non-admin users
