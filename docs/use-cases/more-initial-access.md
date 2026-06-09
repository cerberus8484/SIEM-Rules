# Initial Access & Execution — Extended

Extended initial access and execution detection beyond UC-017–022.

**Rule packs:** `initial_access`, `execution`

---

## UC-182 — ISO / IMG Mount for Malware Delivery {#uc-182}

**Threat:** Attackers deliver malware inside ISO or IMG disk images to bypass
Mark-of-the-Web (MOTW) restrictions. When mounted, files inside are treated as
coming from the local filesystem, bypassing SmartScreen.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 82 |
| **MITRE** | T1553.005 — Subvert Trust Controls: Mark-of-the-Web Bypass |
| **Data Sources** | Sysmon Events 1/11, Windows Security 4688 |
| **Rule IDs** | SP-initial-001 |

### Splunk SPL

```spl
| union
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
     | where match(TargetFilename,"(?i)\.(iso|img|vhd|vhdx)$")
         AND match(Image,"(?i)(outlook|chrome|msedge|firefox|winword|excel|teams)")
     | eval detection="ISO Downloaded via Email/Browser"]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
     | where match(CommandLine,"(?i)(\.lnk|\.bat|\.cmd|\.exe)")
         AND match(ParentImage,"(?i)(explorer\.exe)")
         AND match(CommandLine,"(?i)^[A-Z]:\\[A-Z0-9]{8}-[A-Z0-9]{4}\\")
     | eval detection="Execution from Virtual Drive (ISO Mount)"]
| table _time, host, user, detection, TargetFilename, CommandLine
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "filename" AS "ISO File", "process" AS "Downloaded By",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - File created'
    AND (LOWER("filename") LIKE '%.iso' OR LOWER("filename") LIKE '%.img'
        OR LOWER("filename") LIKE '%.vhd')
    AND "process" IN ('outlook.exe','chrome.exe','msedge.exe','firefox.exe')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Check if any executables were launched from the mounted drive letter
2. Hash the ISO and check against VirusTotal
3. Block ISO/IMG execution via Attack Surface Reduction rule: "Block executable files from running unless they meet a prevalence, age, or trusted list criteria"
4. Disable ISO file association from auto-mount via Group Policy
5. Educate users: email-delivered ISO files are a major malware delivery vector

---

## UC-183 — OneNote Embedded Payload Execution {#uc-183}

**Threat:** Malicious OneNote file contains an embedded executable or script attachment.
When the user double-clicks the attachment within OneNote, it executes directly
(bypassing normal attachment security). Used by Qakbot, IcedID, and others.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 85 |
| **MITRE** | T1566.001 — Phishing: Spearphishing Attachment |
| **Data Sources** | Sysmon Event 1, Windows Security 4688 |
| **Rule IDs** | SP-initial-002 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(ParentImage,"(?i)(ONENOTE|OneNote)\.exe")
    AND match(Image,"(?i)(cmd|powershell|pwsh|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin)\.exe")
| table _time, host, user, Image, ParentImage, CommandLine
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "process" AS "Spawned Process", "ParentProcessName" AS "OneNote",
    "Command" AS "CommandLine", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND LOWER("ParentProcessName") LIKE '%onenote%'
    AND LOWER("process") IN ('cmd.exe','powershell.exe','wscript.exe','cscript.exe','mshta.exe')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Isolate the host — OneNote spawning scripts is active exploitation
2. Review the OneNote file attachment that was clicked
3. Check subsequent process activity for payload download/execution
4. Disable OneNote embedded file execution via Group Policy if not required
5. Update to latest OneNote version — Microsoft has added warnings for embedded files

---

## UC-184 — HTML Smuggling (JavaScript Dropper) {#uc-184}

**Threat:** HTML attachment or web page uses JavaScript Blob or Base64 to dynamically
create and download a file, bypassing email gateway attachment scanning.
The HTML file itself is benign; the payload is assembled in-browser.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 78 |
| **MITRE** | T1027.006 — Obfuscated Files or Information: HTML Smuggling |
| **Data Sources** | Sysmon Events 1/11, Browser telemetry |
| **Rule IDs** | SP-initial-003 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| where match(TargetFilename,"(?i)\\Downloads\\.*\.(iso|img|zip|exe|msi|lnk|bat|hta|js)")
    AND match(Image,"(?i)(chrome|msedge|firefox|iexplore)\.exe")
| bucket _time span=5m
| join type=inner host
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
     | where match(ParentImage,"(?i)\\Downloads\\") OR match(CommandLine,"(?i)\\Downloads\\")
     | table _time, host, Image, CommandLine]
| table _time, host, user, TargetFilename, Image, CommandLine
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "filename" AS "Downloaded File", "process" AS "Browser",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - File created'
    AND "filename" LIKE '%Downloads%'
    AND (LOWER("filename") LIKE '%.iso' OR LOWER("filename") LIKE '%.zip'
        OR LOWER("filename") LIKE '%.lnk' OR LOWER("filename") LIKE '%.hta')
    AND "process" IN ('chrome.exe','msedge.exe','firefox.exe')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Identify the HTML file source (email attachment, URL, Teams message)
2. Hash and sandbox the downloaded file
3. Block the URL/domain that served the HTML page
4. Disable execution of .lnk, .hta, .js files from Downloads folder via AppLocker
5. Consider MDE's ASR rule: "Block JavaScript or VBScript from launching downloaded executable content"

---

## UC-185 — Malicious LNK File Execution {#uc-185}

**Threat:** LNK (shortcut) file used to deliver payloads — either sent directly via email,
inside an archive, or dropped on the system. LNK files can contain arbitrary command
execution via `Target` or `Arguments` fields.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 80 |
| **MITRE** | T1204.002 — User Execution: Malicious File |
| **Data Sources** | Sysmon Events 1/11 |
| **Rule IDs** | SP-initial-004 |

### Splunk SPL

```spl
| union
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
     | where match(TargetFilename,"(?i)(\\Downloads\\|\\Temp\\|\\AppData\\|\\Desktop\\).*\.lnk$")
         AND NOT match(Image,"(?i)(explorer|TASKBAND|SearchApp|StartMenuExperienceHost)")
     | eval detection="Suspicious LNK Created"]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
     | where match(ParentImage,"(?i)explorer\.exe")
         AND match(CommandLine,"(?i)(cmd.*\/c|powershell.*-c|wscript|cscript|mshta|regsvr32)")
         AND match(CommandLine,"(?i)(\\Downloads\\|\\Temp\\|\\Desktop\\)")
     | eval detection="Process from Suspicious LNK Click"]
| table _time, host, user, TargetFilename, CommandLine, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "Command" AS "Executed Command", "ParentProcessName" AS "Parent",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND "ParentProcessName" = 'explorer.exe'
    AND (LOWER("Command") LIKE '%cmd /c%' OR LOWER("Command") LIKE '%powershell -c%'
        OR LOWER("Command") LIKE '%wscript%')
    AND ("Command" LIKE '%Downloads%' OR "Command" LIKE '%Temp%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Inspect the LNK file target command — what does it execute?
2. Check if a payload was downloaded or executed after the LNK was clicked
3. Block LNK files via email gateway (add .lnk to blocked attachment types)
4. Enable "Show hidden file extensions" in Explorer to help users identify suspicious files
5. Deploy ASR rule: "Block Office applications from creating executable content"

---

## UC-186 — Teams / Slack Phishing File Delivery {#uc-186}

**Threat:** Attacker uses a compromised or guest account in Microsoft Teams or Slack
to deliver malicious files directly to users. Teams/Slack file shares often bypass
email gateway controls.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 78 |
| **MITRE** | T1566.003 — Phishing: Spearphishing via Service |
| **Data Sources** | M365 Audit Log, Sysmon Event 11 |
| **Rule IDs** | SP-initial-005 |

### Splunk SPL

```spl
| union
    [search index=o365 sourcetype="o365:management:activity"
     | where Operation IN ("FileUploaded","FileAccessed")
         AND match(SourceFileName,"(?i)\.(exe|bat|ps1|hta|lnk|vbs|iso|img|zip|rar)")
         AND match(SiteUrl,"(?i)(teams\.microsoft|sharepoint\.com)")
     | eval detection="Executable Uploaded to Teams/SharePoint"]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
     | where match(TargetFilename,"(?i)(\\AppData\\Local\\Microsoft\\Teams\\|\\AppData\\Roaming\\Slack\\).*\.(exe|bat|ps1|hta|lnk)")
     | eval detection="Executable Written by Teams/Slack Client"]
| table _time, host, user, SourceFileName, TargetFilename, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "User", "SourceFileName" AS "File",
    "SiteUrl" AS "Platform", QIDNAME(qid) AS "Action",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Microsoft Exchange'
    AND "Operation" IN ('FileUploaded','FileAccessed')
    AND (LOWER("SourceFileName") LIKE '%.exe' OR LOWER("SourceFileName") LIKE '%.hta'
        OR LOWER("SourceFileName") LIKE '%.lnk' OR LOWER("SourceFileName") LIKE '%.iso')
    AND "SiteUrl" LIKE '%teams.microsoft%'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Remove the file from the Teams/Slack channel immediately
2. Notify all channel members who may have accessed the file
3. Check if the file was opened on any endpoints (Sysmon correlation)
4. Review the account that uploaded the file — was it compromised or a new guest?
5. Configure Teams to block external file sharing or scan attachments via Defender for Office 365

---

## UC-187 — Zip Password-Protected Archive with Executable {#uc-187}

**Threat:** Attackers deliver malware inside password-protected ZIP archives with the
password in the email body. This bypasses email gateway scanning which cannot inspect
encrypted archives.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 82 |
| **MITRE** | T1566.001 — Phishing: Spearphishing Attachment |
| **Data Sources** | Exchange logs, Sysmon Event 11 |
| **Rule IDs** | SP-initial-006 |

### Splunk SPL

```spl
| union
    [search index=exchange OR index=email_gateway
     | where match(AttachmentName,"(?i)\.zip$") AND match(Subject,"(?i)(password|pwd|pass.*:\s*\d|the.*password.*is)")
     | eval detection="Password-Protected ZIP with Password in Subject"]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
     | where match(TargetFilename,"(?i)(\\Downloads\\|\\Temp\\|\\AppData\\|\\Desktop\\).*\.(exe|bat|ps1|hta|lnk)")
         AND match(Image,"(?i)(winzip|7z|winrar|expand|Expand-Archive)")
     | eval detection="Executable Extracted from Archive"]
| table _time, host, user, Subject, AttachmentName, TargetFilename, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT "SenderAddress" AS "Sender", "RecipientAddress" AS "Recipient",
    "Subject" AS "Email Subject", "AttachmentName" AS "Attachment",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Microsoft Exchange'
    AND "Operation" = 'MessageDelivered'
    AND LOWER("AttachmentName") LIKE '%.zip'
    AND (LOWER("Subject") LIKE '%password%' OR LOWER("Subject") LIKE '%pwd%'
        OR LOWER("Subject") LIKE '%pass%is%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Check if the archive was extracted and if any executables were run from it
2. Isolate the user's workstation if execution is confirmed
3. Configure email gateway to block password-protected archives where password is in the email body
4. Deploy Advanced Threat Protection for Office 365 (Defender for Office) with Safe Attachments
5. Detonate all ZIP attachments in a sandbox before delivery (most modern email gateways support this)
