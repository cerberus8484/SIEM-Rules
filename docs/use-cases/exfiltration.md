# Exfiltration & DLP

Use cases for detecting data theft, large transfers, and data staging before exfiltration.

**Rule packs:** `dlp`, `correlation`

---

## UC-079 — Large Outbound Data Transfer {#uc-079}

**Threat:** Attacker exfiltrates large volumes of data via HTTP/HTTPS, FTP, or custom
protocols. Detectable as unusually large outbound transfers to external IPs.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 75 |
| **MITRE** | T1048 — Exfiltration Over Alternative Protocol |
| **Data Sources** | Firewall logs, Sysmon Event 3, Proxy logs |
| **Rule IDs** | SP-dlp-001 |

### Splunk SPL

```spl
index=firewall OR index=proxy
| where NOT match(dest_ip,"(?i)(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)") 
| stats sum(bytes_out) as TotalBytes by src_ip, dest_ip, _time
| eval TotalMB=round(TotalBytes/1024/1024,2)
| where TotalMB >= 100
| sort -TotalMB
| table _time, src_ip, dest_ip, TotalMB
```

### QRadar AQL

```sql
SELECT sourceip AS "Source", destinationip AS "Destination",
    SUM(CAST("BytesOut" AS BIGINT)) / 1048576 AS "MB Sent",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Window"
FROM events WHERE "LogSourceType" = 'Firewall'
    AND destinationip NOT LIKE '10.%' AND destinationip NOT LIKE '192.168.%'
    AND destinationip NOT LIKE '172.%'
GROUP BY sourceip, destinationip, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING SUM(CAST("BytesOut" AS BIGINT)) >= 104857600
LAST 24 HOURS ORDER BY "MB Sent" DESC
```

### Response Actions
1. Identify the destination — check threat intel for the external IP
2. Correlate with data staging commands (7-zip, rar, robocopy) from the same host
3. If HTTP/S traffic: inspect proxy logs for the URL path and user-agent
4. Block the connection at the firewall while investigating
5. Correlate with recent file access patterns from the same host

---

## UC-080 — Cloud Storage Upload (Suspicious) {#uc-080}

**Threat:** Attacker uploads sensitive data to personal/attacker-controlled cloud storage
(Mega, Dropbox personal, Google Drive personal, WeTransfer, OneDrive personal) to bypass
DLP controls that focus on email.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 78 |
| **MITRE** | T1567.002 — Exfiltration Over Web Service: Exfiltration to Cloud Storage |
| **Data Sources** | Proxy logs, DNS logs, Sysmon Event 3/22 |
| **Rule IDs** | SP-dlp-002 |

### Splunk SPL

```spl
index=proxy OR index=dns
| where match(dest_host,"(?i)(mega\.nz|transfer\.sh|wetransfer\.com|gofile\.io|anonfiles|temp\.sh|file\.io|upload\.ee)")
    OR (match(dest_host,"(?i)(dropbox\.com|drive\.google\.com|onedrive\.live\.com)")
        AND bytes_out >= 10485760)
| stats sum(bytes_out) as TotalBytes, count by src_ip, dest_host, user, _time
| eval TotalMB=round(TotalBytes/1024/1024,2)
| sort -TotalMB
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "hostname" AS "Cloud Service", SUM(CAST("BytesOut" AS BIGINT)) / 1048576 AS "MB Uploaded",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Web Proxy'
    AND ("hostname" LIKE '%mega.nz%' OR "hostname" LIKE '%transfer.sh%'
        OR "hostname" LIKE '%wetransfer.com%' OR "hostname" LIKE '%gofile.io%')
GROUP BY sourceip, username, "hostname", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
LAST 24 HOURS ORDER BY "MB Uploaded" DESC
```

### Response Actions
1. Block unauthorized cloud storage at the proxy/firewall for corporate devices
2. Identify what was uploaded — check endpoint artifacts for staged files
3. Review user context — is this an insider threat or a compromised account?
4. Check browser history for navigation to these services
5. Deploy CASB (Cloud Access Security Broker) for ongoing visibility

---

## UC-081 — USB Mass Storage Device Connected {#uc-081}

**Threat:** Insider threat or attacker connects a USB drive to copy sensitive data.
Detectable via PnP manager events and Sysmon file create activity.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 72 |
| **MITRE** | T1052.001 — Exfiltration over Physical Medium: USB |
| **Data Sources** | Windows Security 6416, Windows System 20001 |
| **Rule IDs** | SP-dlp-003 |

### Splunk SPL

```spl
| union
    [search index=windows EventCode=6416
     | where ClassName="DiskDrive"
         AND NOT match(SubjectUserName,"(?i)(SYSTEM|\$$)")
     | eval detection="USB Drive Connected"]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
     | where match(TargetFilename,"(?i)^[D-Z]:\\.*\.(zip|rar|7z|tar|gz|pdf|docx|xlsx|pptx|csv|sql|bak|db)$")
         AND NOT match(TargetFilename,"(?i)(C:\\|AppData\\Local\\Temp)")
     | bucket _time span=10m
     | stats count, dc(TargetFilename) as UniqueFiles by host, user, _time
     | where UniqueFiles >= 10
     | eval detection="Files Written to Removable Drive"]
| table _time, host, user, detection, UniqueFiles
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "DeviceDescription" AS "USB Device", QIDNAME(qid) AS "Event",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID = '6416'
    AND "DeviceClass" = 'DiskDrive'
    AND username NOT LIKE '%$' AND username != 'SYSTEM'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Identify what was copied to the USB drive (Event 4663 / Sysmon 11 on removable path)
2. Check if the USB device is on the approved device list
3. Consider USB blocking via Group Policy or DLP for sensitive hosts
4. Interview the user if this appears to be an insider threat
5. Forensically image the USB device if accessible

---

## UC-082 — Data Archiving Before Exfiltration {#uc-082}

**Threat:** Before exfiltrating, attackers often stage and compress data using 7-zip, WinRAR,
or PowerShell Compress-Archive. Large archive creation in user-writable paths is suspicious.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 80 |
| **MITRE** | T1560.001 — Archive Collected Data: Archive via Utility |
| **Data Sources** | Sysmon Event 1/11, Windows Security 4688 |
| **Rule IDs** | SP-dlp-004 |

### Splunk SPL

```spl
| union
    [search index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
     | where match(CommandLine,"(?i)(7z\s+(a|u)|rar\s+(a|u)|tar\s+-c|Compress-Archive).*\.(zip|rar|7z|tar\.gz|tar\.bz2)")
         AND match(CommandLine,"(?i)(\\Users\\|\\AppData\\|\\Temp\\|\\Documents\\|\\Desktop\\)")
     | eval detection="Archive Created via CLI"]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
     | where match(TargetFilename,"(?i)(\\Temp\\|\\AppData\\|\\Desktop\\|\\Downloads\\).*\.(zip|rar|7z|tar\.gz)")
         AND NOT match(Image,"(?i)(browser|update|setup|install)")
     | eval detection="Archive File Created"]
| table _time, host, user, CommandLine, TargetFilename, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "Command" AS "Archive Command",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND (LOWER("Command") LIKE '%7z%' OR LOWER("Command") LIKE '%winrar%'
        OR LOWER("Command") LIKE '%compress-archive%')
    AND (LOWER("Command") LIKE '%.zip%' OR LOWER("Command") LIKE '%.7z%'
        OR LOWER("Command") LIKE '%.rar%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Identify the contents of the archive — was it created over sensitive directories?
2. Check if the archive was then transferred (correlate with large outbound transfer)
3. Check if the archive is password-protected (7z a -p flag) — indicates intent to obfuscate
4. Review what files are in the archive by examining command-line arguments
5. Correlate the archive creation timing with any C2 beaconing or DNS queries

---

## UC-083 — Screen Capture / Keylogger Indicators {#uc-083}

**Threat:** Attacker installs or runs tools that capture screenshots or keystrokes
to harvest credentials, VPN URLs, MFA codes, and internal system information.
Common RAT features: Cobalt Strike screenshots, Meterpreter keylogger.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 78 |
| **MITRE** | T1113 — Screen Capture / T1056.001 — Input Capture: Keylogging |
| **Data Sources** | Sysmon 1, Windows Security 4688 |
| **Rule IDs** | SP-dlp-005 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where match(CommandLine,"(?i)(screenshot|Invoke-Screenshot|Get-Screen|PrintWindow|BitBlt|GetDesktopWindow)")
    OR match(CommandLine,"(?i)(SetWindowsHookEx|GetAsyncKeyState|keylogger|keyboard.*hook|LogKeys)")
    OR (match(Image,"(?i)(powershell|pwsh)") AND match(CommandLine,"(?i)(\[Windows\.Graphics\.Capture|BitBlt|GdipBitmapSaveToStream)"))
| table _time, host, user, Image, CommandLine
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "Command" AS "CommandLine", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND (LOWER("Command") LIKE '%screenshot%'
        OR LOWER("Command") LIKE '%keylogger%'
        OR LOWER("Command") LIKE '%setwindowshookex%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Memory dump the process — look for captured data in memory
2. Check for screenshot files on disk (.png, .bmp, .jpg in temp directories)
3. Assess what sensitive information was potentially visible on screen (VPN creds, internal tools)
4. Consider full IR — screen/keyboard capture implies long-term access was the goal
5. Rotate all credentials that may have been captured

---

## UC-084 — Git Clone / Code Repository Exfiltration {#uc-084}

**Threat:** Developer account or attacker clones internal source code repositories
(GitLab, Bitbucket, GitHub Enterprise) containing IP, credentials, or API keys.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 70 |
| **MITRE** | T1213 — Data from Information Repositories |
| **Data Sources** | Git audit logs, Proxy logs, Sysmon 1 |
| **Rule IDs** | SP-dlp-006 |

### Splunk SPL

```spl
| union
    [search index=proxy OR index=gitlab OR index=github
     | where match(uri,"(?i)(\.git$|\/clone|\/archive|\/download|format=zip)")
         AND bytes_out >= 10485760
     | eval detection="Large Git Clone via Web"]
    [search index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
     | where match(Image,"(?i)git\.exe")
         AND match(CommandLine,"(?i)git\s+(clone|pull)\s+http")
     | eval detection="Git Clone Command"]
| table _time, host, user, uri, CommandLine, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "URL" AS "Repository URL", CAST("BytesOut" AS BIGINT) / 1048576 AS "MB",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Web Proxy'
    AND ("URL" LIKE '%.git' OR "URL" LIKE '%/archive/%'
        OR "URL" LIKE '%format=zip%')
    AND CAST("BytesOut" AS BIGINT) >= 10485760
LAST 24 HOURS ORDER BY "MB" DESC
```

### Response Actions
1. Identify which repositories were cloned — assess their sensitivity
2. Check if the repos contain API keys, passwords, or sensitive architecture docs
3. Rotate any credentials found in the potentially exposed repositories
4. Review if this was an authorized user or a compromised developer account
5. Enable Git audit logging in GitLab/GitHub Enterprise (Access logs, clone events)

---

## UC-085 — FTP / SCP / rsync Exfiltration {#uc-085}

**Threat:** Attacker uses FTP, SCP, or rsync to exfiltrate data to an external server.
These protocols may bypass HTTP-focused DLP controls.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 80 |
| **MITRE** | T1048.003 — Exfiltration Over Alternative Protocol: Unencrypted/Obfuscated |
| **Data Sources** | Firewall logs, Sysmon Event 3, DNS |
| **Rule IDs** | SP-dlp-007 |

### Splunk SPL

```spl
index=firewall OR index=windows
| where (DestinationPort IN (21, 22, 873, 2049) AND match(dest_ip,"(?i)^(?!10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)"))
    OR (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" AND EventCode=3
        AND DestinationPort IN (21, 873) AND Initiated="true"
        AND NOT match(DestinationIp,"(?i)^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)"))
| table _time, host, user, Image, DestinationIp, DestinationPort, bytes_out
| sort -bytes_out
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", destinationip AS "External Server",
    destinationport AS "Port", SUM(CAST("BytesOut" AS BIGINT)) / 1048576 AS "MB Sent",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE destinationport IN (21, 873, 2049)
    AND destinationip NOT LIKE '10.%' AND destinationip NOT LIKE '192.168.%'
GROUP BY sourceip, destinationip, destinationport, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING SUM(CAST("BytesOut" AS BIGINT)) >= 10485760
LAST 24 HOURS ORDER BY "MB Sent" DESC
```

### Response Actions
1. Block FTP (port 21) outbound at the perimeter — rarely needed by end-user systems
2. Identify what was transferred — check server-side logs if accessible
3. Check if SCP/rsync usage is authorized for this host
4. Correlate with prior data staging commands from the same host
5. Verify destination IP/hostname via threat intelligence

---

## UC-086 — ICMP Tunneling {#uc-086}

**Threat:** Attacker tunnels data through ICMP echo requests/replies to bypass firewall
policies that only filter TCP/UDP. Tools: icmpsh, ptunnel, pingtunnel.
Indicator: unusually large ICMP packets (>64 bytes) or high ICMP volume.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 75 |
| **MITRE** | T1095 — Non-Application Layer Protocol |
| **Data Sources** | Firewall logs, IDS/IPS, Network flow data |
| **Rule IDs** | SP-dlp-008 |

### Splunk SPL

```spl
index=firewall OR index=netflow
| where protocol="ICMP" AND (bytes >= 256 OR packet_count >= 100)
    AND NOT match(dest_ip,"(?i)^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)")
| stats sum(bytes) as TotalBytes, sum(packet_count) as TotalPackets, count by src_ip, dest_ip, _time
| eval TotalKB=round(TotalBytes/1024,2)
| where TotalKB >= 10
| sort -TotalKB
```

### QRadar AQL

```sql
SELECT sourceip AS "Source", destinationip AS "Destination",
    SUM(CAST("packetcount" AS INTEGER)) AS "ICMP Packets",
    SUM(CAST("BytesOut" AS BIGINT)) / 1024 AS "KB Sent",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Firewall'
    AND "Protocol" = 'ICMP'
    AND destinationip NOT LIKE '10.%' AND destinationip NOT LIKE '192.168.%'
GROUP BY sourceip, destinationip, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING SUM(CAST("BytesOut" AS BIGINT)) >= 10240
LAST 24 HOURS ORDER BY "KB Sent" DESC
```

### Response Actions
1. Block large ICMP packets at the perimeter firewall (max-size policy)
2. Capture a pcap of the ICMP traffic and examine payload content
3. Identify the host generating the ICMP tunnel — likely compromised
4. If outbound ICMP tunneling is confirmed, escalate to full IR
5. Check for icmpsh, ptunnel binaries on the source host

---

## UC-087 — Clipboard Data Access {#uc-087}

**Threat:** Malware or RAT reads clipboard data to harvest passwords, tokens,
cryptocurrency wallet addresses, or other sensitive content that users copy/paste.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 70 |
| **MITRE** | T1115 — Clipboard Data |
| **Data Sources** | Sysmon Event 1, Windows Security 4688 |
| **Rule IDs** | SP-dlp-009 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where match(CommandLine,"(?i)(Get-Clipboard|clip\.exe|OpenClipboard|GetClipboardData|powershell.*\[Windows\.Forms\.Clipboard\])")
    AND NOT match(ParentImage,"(?i)(explorer|Teams|slack|chrome|msedge|firefox|vscode)")
| table _time, host, user, Image, CommandLine, ParentImage
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "Command" AS "CommandLine", "ParentProcessName" AS "Parent",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND (LOWER("Command") LIKE '%get-clipboard%'
        OR LOWER("Command") LIKE '%openclipboard%'
        OR LOWER("Command") LIKE '%getclipboarddata%')
    AND "ParentProcessName" NOT IN ('explorer.exe','Teams.exe','slack.exe')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Correlate with other RAT/C2 indicators from the same host
2. Consider what was in the clipboard — password manager copy, MFA codes, tokens?
3. Force password rotation for any potentially clipboard-captured credentials
4. This is often a feature of Cobalt Strike, Meterpreter, or commodity RATs
5. Deploy clipboard isolation for sensitive applications (password managers, VPN clients)

---

## UC-088 — Mass File Access on File Server {#uc-088}

**Threat:** Attacker rapidly accesses a large number of files on a file server — indicating
data staging before exfiltration. Detectable as high read volume from a single host.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 80 |
| **MITRE** | T1005 — Data from Local System |
| **Data Sources** | Windows Security 4663 (File Server audit) |
| **Rule IDs** | SP-dlp-010 |

### Splunk SPL

```spl
index=windows EventCode=4663
| where AccessMask IN ("0x1","0x80","0x100")
    AND NOT match(SubjectUserName,"(?i)(SYSTEM|\$$)")
    AND match(ObjectName,"(?i)(\\Finance\\|\\HR\\|\\Legal\\|\\Executives\\|\\Confidential\\|\\Restricted\\)")
| bucket _time span=10m
| stats count, dc(ObjectName) as UniqueFiles by SubjectUserName, host, IpAddress, _time
| where UniqueFiles >= 100
| sort -UniqueFiles
```

### QRadar AQL

```sql
SELECT username AS "User", sourceip AS "Source Host",
    COUNT(DISTINCT "objectname") AS "Files Accessed",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Window"
FROM events WHERE EventID = '4663'
    AND ("objectname" LIKE '%Finance%' OR "objectname" LIKE '%HR%'
        OR "objectname" LIKE '%Confidential%' OR "objectname" LIKE '%Restricted%')
    AND username NOT LIKE '%$' AND username != 'SYSTEM'
GROUP BY username, sourceip, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(DISTINCT "objectname") >= 100
LAST 1 HOURS ORDER BY "Files Accessed" DESC
```

### Response Actions
1. Immediately check if this host is currently transferring data (firewall outbound)
2. Identify what files were accessed — were they encrypted at rest?
3. Correlate with prior archive creation or cloud upload activity
4. Review the file server audit logs for adjacent time period
5. Consider deploying a UEBA solution to baseline normal access patterns per user
