# Initial Access & Execution

Use cases for detecting the first stage of an attack — phishing, macro execution,
LOLBin abuse, and download cradles.

**Rule packs:** `execution`, `initial_access`

---

## UC-017 — Office Macro Spawning Shell {#uc-017}

**Threat:** Malicious Office document executes a macro that spawns a command interpreter
(cmd.exe, powershell.exe, wscript.exe). Primary delivery vector for Emotet, QakBot, and
most commodity crimeware loaders.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 90 |
| **MITRE** | T1566.001 / T1204.002 — Phishing: Spearphishing Attachment |
| **Data Sources** | Windows Security 4688, Sysmon Event 1 |
| **Rule IDs** | SP-100001, SP-100002 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where match(ParentImage, "(?i)(WINWORD|EXCEL|POWERPNT|OUTLOOK|ONENOTE|MSPUB|MSACCESS|VISIO)\.EXE")
    AND match(Image, "(?i)(cmd|powershell|pwsh|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin)\.exe")
| eval parent=mvindex(split(ParentImage, "\\"), -1)
| eval child=mvindex(split(Image, "\\"), -1)
| table _time, host, user, parent, child, CommandLine
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Host",
    username AS "User",
    "ParentProcessName" AS "OfficeApp",
    "process" AS "SpawnedProcess",
    "Command" AS "CommandLine",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    (
        "ParentProcessName" LIKE '%WINWORD.EXE%'
        OR "ParentProcessName" LIKE '%EXCEL.EXE%'
        OR "ParentProcessName" LIKE '%POWERPNT.EXE%'
        OR "ParentProcessName" LIKE '%OUTLOOK.EXE%'
        OR "ParentProcessName" LIKE '%ONENOTE.EXE%'
    )
    AND (
        LOWER("process") LIKE '%cmd.exe%'
        OR LOWER("process") LIKE '%powershell.exe%'
        OR LOWER("process") LIKE '%wscript.exe%'
        OR LOWER("process") LIKE '%mshta.exe%'
        OR LOWER("process") LIKE '%regsvr32.exe%'
    )
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Quarantine the document — retrieve from the email gateway for analysis
2. Identify all recipients of the email (search email logs for same attachment hash)
3. Check child process command line for download cradle (→ UC-019)
4. Submit document to sandbox (MalwareBazaar, Any.run)
5. Block sender domain and file hash at email gateway

---

## UC-018 — Encoded PowerShell Execution {#uc-018}

**Threat:** Attacker uses Base64 encoding, -EncodedCommand flag, or in-memory execution
(IEX, Invoke-Expression) to run PowerShell while evading string-based detection.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 85 |
| **MITRE** | T1059.001 — Command and Scripting Interpreter: PowerShell |
| **Data Sources** | Windows Security 4688, PowerShell 4104 (ScriptBlock), Sysmon 1 |
| **Rule IDs** | SP-100003, SP-100004 |

### Splunk SPL

```spl
index=windows
    (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
     OR source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104)
| where match(CommandLine, "(?i)(-enc(odedcommand)?|-ec\s|-W(indowStyle)?\s+[Hh]idden|-noni(nteractive)?|-ep\s+bypass|iex\s*\(|invoke-expression)")
    OR match(ScriptBlockText, "(?i)(iex\s*\(|invoke-expression|downloadstring|net\.webclient|system\.reflection\.assembly|[Cc]onvert.*frombase64)")
| eval risk=case(
    match(CommandLine,"(?i)-enc"), "Encoded Command",
    match(CommandLine,"(?i)IEX|invoke-expression"), "In-Memory Execution",
    match(CommandLine,"(?i)downloadstring"), "Download Cradle",
    1=1, "Obfuscated PS"
  )
| table _time, host, user, CommandLine, risk
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Host",
    username AS "User",
    "Command" AS "CommandLine",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    LOWER("Command") LIKE '%encodedcommand%'
    OR LOWER("Command") LIKE '%-enc %'
    OR LOWER("Command") LIKE '%windowstyle hidden%'
    OR LOWER("Command") LIKE '%executionpolicy bypass%'
    OR LOWER("Command") LIKE '%-ep bypass%'
    OR (LOWER("Command") LIKE '%iex%' AND LOWER("Command") LIKE '%webclient%')
    OR LOWER("Command") LIKE '%invoke-expression%'
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Decode the Base64 payload: `[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("..."))`
2. Check if ScriptBlock logging is enabled — if so, pull the full decoded script
3. Identify what the script does (download cradle? shellcode loader? lateral movement?)
4. Enable PowerShell Constrained Language Mode for non-admin users
5. Enable AMSI — many loaders are blocked by AMSI scanning

---

## UC-019 — certutil Download Cradle {#uc-019}

**Threat:** Attacker uses certutil.exe — a legitimate Windows binary — to download
and optionally decode malicious payloads. Certutil is a trusted Windows binary, bypassing
application allowlisting and AV.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 91 |
| **MITRE** | T1105 — Ingress Tool Transfer |
| **Data Sources** | Windows Security 4688, Sysmon Event 1/3 |
| **Rule IDs** | SP-100005 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (1,3))
| where Image LIKE "%certutil.exe"
    AND (
        match(CommandLine, "(?i)-urlcache.*-split|-urlcache.*-f|-decode")
        OR match(CommandLine, "(?i)http[s]?://")
    )
| table _time, host, user, CommandLine, DestinationIp, DestinationPort
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Host",
    username AS "User",
    "Command" AS "CommandLine",
    destinationip AS "Download Source IP",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    LOWER("process") LIKE '%certutil%'
    AND (
        LOWER("Command") LIKE '%-urlcache%'
        OR LOWER("Command") LIKE '%-decode%'
        OR LOWER("Command") LIKE '%http%'
    )
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Identify the download URL from the command line
2. Check what was downloaded and where it was saved
3. Submit the downloaded file hash to VirusTotal / MalwareBazaar
4. Block the download URL at the proxy/firewall
5. Consider blocking certutil.exe from making outbound connections via AppLocker rule

---

## UC-020 — mshta / regsvr32 LOLBin Execution {#uc-020}

**Threat:** Attacker uses legitimate Windows binaries (mshta.exe, regsvr32.exe, rundll32.exe)
to execute malicious scripts or DLLs, bypassing application allowlisting.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 87 |
| **MITRE** | T1218 — System Binary Proxy Execution |
| **Data Sources** | Windows Security 4688, Sysmon Event 1/3 |
| **Rule IDs** | SP-100006, SP-100007 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (1,3))
| where (Image LIKE "%mshta.exe" AND (match(CommandLine, "(?i)http[s]?://") OR match(CommandLine, "(?i)vbscript:|javascript:")))
    OR (Image LIKE "%regsvr32.exe" AND match(CommandLine, "(?i)(/s.*scrobj|/n.*http|/u.*http)"))
    OR (Image LIKE "%rundll32.exe" AND (match(CommandLine, "(?i)(http|javascript:|vbscript:|\\.AppData\\)") OR match(CommandLine, "(?i)\\Temp\\")))
    OR (Image LIKE "%InstallUtil.exe" AND NOT match(Image, "(?i)C:\\Windows\\Microsoft\.NET\\Framework"))
| eval lolbin=mvindex(split(Image, "\\"), -1)
| table _time, host, user, lolbin, CommandLine
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Host",
    username AS "User",
    "process" AS "LOLBin",
    "Command" AS "CommandLine",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    (LOWER("process") LIKE '%mshta.exe%'
        AND (LOWER("Command") LIKE '%http%' OR LOWER("Command") LIKE '%vbscript%'))
    OR (LOWER("process") LIKE '%regsvr32.exe%'
        AND (LOWER("Command") LIKE '%/s%scrobj%' OR LOWER("Command") LIKE '%http%'))
    OR (LOWER("process") LIKE '%rundll32.exe%'
        AND (LOWER("Command") LIKE '%javascript%' OR LOWER("Command") LIKE '%http%'))
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Block the LOLBin from making network connections via Windows Firewall or AppLocker
2. Retrieve the remote script/DLL for analysis
3. Check if regsvr32 / mshta is used in any legitimate admin workflows before blocking
4. Consider deploying Attack Surface Reduction (ASR) rules via Microsoft Defender

---

## UC-021 — WMIC Process Create Remote {#uc-021}

**Threat:** Attacker uses WMIC to create a process on a remote system without
installing a service. Clean — no PSEXESVC artifacts.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 83 |
| **MITRE** | T1047 — Windows Management Instrumentation |
| **Data Sources** | Windows Security 4688, Sysmon Event 1 |
| **Rule IDs** | SP-100008 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where match(CommandLine, "(?i)wmic\s+.*/node:.+process\s+(call\s+)?create")
    OR match(CommandLine, "(?i)wmic\s+/format:hta")
| rex field=CommandLine "(?i)/node:[\"\']?(?P<TargetNode>[^\s\"\']+)"
| table _time, host, user, TargetNode, CommandLine
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Source Host",
    username AS "User",
    "Command" AS "CommandLine",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    LOWER("Command") LIKE '%wmic%/node:%'
    AND LOWER("Command") LIKE '%process%'
    AND (LOWER("Command") LIKE '%call%create%' OR LOWER("Command") LIKE '%/format%hta%')
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Extract the target node — which remote host was targeted?
2. Review Security event logs on the target for process creation from wmiprvse.exe
3. Correlate with logon events to identify the credential used
4. Block WMIC remote access in firewall if not operationally required

---

## UC-022 — Malicious Email Attachment Execution {#uc-022}

**Threat:** Phishing email with malicious attachment — Office document, PDF, or
archive containing a dropper. Detected by file creation in user Download path
followed by immediate execution.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 79 |
| **MITRE** | T1566.001 — Phishing: Spearphishing Attachment |
| **Data Sources** | Windows Security 4688, Sysmon Event 1/11, Email logs |
| **Rule IDs** | SP-100009, SP-initial_access-001 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| where match(TargetFilename, "(?i)(\\Downloads\\|\\AppData\\Local\\Temp\\|\\AppData\\Roaming\\).*\.(exe|dll|ps1|vbs|js|hta|bat|cmd|lnk|iso|img)$")
    AND NOT match(TargetFilename, "(?i)(C:\\Program Files|C:\\Windows)")
| join host [search index=windows (EventCode=4688 OR EventCode=1)
    | where match(CommandLine, "(?i)(\\Downloads\\|\\AppData\\Local\\Temp\\).*\.(exe|dll|ps1|vbs|js|hta)")
    | table host, CommandLine, _time]
| table _time, host, user, TargetFilename, CommandLine
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Host",
    username AS "User",
    "filename" AS "DroppedFile",
    "Command" AS "CommandLine",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    QIDNAME(qid) = 'File Created'
    AND (
        "filename" LIKE '%\\Downloads\\%'
        OR "filename" LIKE '%\\AppData\\Local\\Temp\\%'
    )
    AND (
        LOWER("filename") LIKE '%.exe' OR LOWER("filename") LIKE '%.ps1'
        OR LOWER("filename") LIKE '%.vbs' OR LOWER("filename") LIKE '%.hta'
        OR LOWER("filename") LIKE '%.lnk' OR LOWER("filename") LIKE '%.js'
    )
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Retrieve the malicious file from the Download folder for sandbox analysis
2. Search email gateway for the delivery email — quarantine all copies
3. Extract sender, subject, and attachment hash — block at gateway
4. Check all users who received the same email and check for execution on their hosts
5. Review MOTW (Mark of the Web) status — did the file bypass SmartScreen?
