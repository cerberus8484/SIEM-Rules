# Ransomware — Extended

Extended ransomware detection beyond UC-001–005. Covers double extortion, RDP-based,
and LockBit-specific indicators.

**Rule packs:** `backup-resilience`, `correlation`

---

## UC-164 — Double Extortion — Data Staging Before Encryption {#uc-164}

**Threat:** Modern ransomware groups (LockBit, BlackCat/ALPHV, Cl0p) first exfiltrate
data to their servers, then encrypt. Detecting the staging phase (large archive creation
+ outbound transfer) before encryption can prevent data leakage.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 88 |
| **MITRE** | T1560.001 + T1048 — Archive + Exfil over Web |
| **Data Sources** | Sysmon Events 1/3/11, Firewall logs |
| **Rule IDs** | SP-ransomware-001 |

### Splunk SPL

```spl
| join type=inner host
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
     | where match(TargetFilename,"(?i)(\\AppData\\|\\Temp\\|\\ProgramData\\).*\.(zip|rar|7z)")
     | bucket _time span=30m
     | stats sum(eval(len(TargetFilename))) as TotalSize, count by host, _time
     | eval stage="staging" | table host, _time, stage]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
     | where Initiated="true"
         AND NOT match(DestinationIp,"(?i)^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)") 
     | bucket _time span=30m
     | stats sum(eval(1)) as NetConns by host, _time
     | where NetConns >= 5
     | eval stage="exfil" | table host, _time, stage]
| stats dc(stage) as Stages by host, _time
| where Stages >= 2
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", COUNT(DISTINCT "stage") AS "Exfil Stages",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Window"
FROM (
    SELECT sourceip, 'archive_create' AS stage, starttime FROM events
        WHERE QIDNAME(qid) = 'Sysmon - File created' AND ("filename" LIKE '%.7z' OR "filename" LIKE '%.rar')
    UNION
    SELECT sourceip, 'external_upload' AS stage, starttime FROM events
        WHERE QIDNAME(qid) = 'Sysmon - Network connection detected'
        AND "Initiated" = 'true' AND destinationip NOT LIKE '10.%'
    LAST 2 HOURS
) chain
GROUP BY sourceip, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(DISTINCT "stage") >= 2
LAST 2 HOURS ORDER BY starttime DESC
```

### Response Actions
1. **Stop the exfiltration first** — block outbound connections from the host immediately
2. Isolate the host to prevent encryption from spreading
3. Identify what data was staged — check archive contents if accessible
4. Begin ransomware IR playbook — assume encryption will start if not already
5. Notify data protection officer — data exfiltration triggers GDPR/breach notification

---

## UC-165 — LockBit 3.0 Specific Indicators {#uc-165}

**Threat:** LockBit 3.0 specific TTPs: `HrxD.exe` or random-named executable,
disables VSS, clears event logs, runs `cmd /c ping 1.1.1.1 -n 5 >nul && del /f /q "<self>"` for self-deletion.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 92 |
| **MITRE** | T1486 + T1490 + T1070 |
| **Data Sources** | Sysmon Events 1/11, Windows Security 4688 |
| **Rule IDs** | SP-ransomware-002 |

### Splunk SPL

```spl
| union
    [search index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
     | where match(CommandLine,"(?i)(ping.*1\.1\.1\.1.*&&.*del.*\/f.*\/q|del.*\/q.*self)")
     | eval detection="LockBit Self-Delete Pattern"]
    [search index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
     | where match(CommandLine,"(?i)(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|bcdedit.*recovery.*none)")
         AND match(CommandLine,"(?i)(\/all|\/quiet)")
     | eval detection="VSS Deletion (Ransomware Precursor)"]
    [search index=windows EventCode IN (1102, 104)
     | eval detection="Event Log Cleared (Ransomware Cover)"]
| table _time, host, user, CommandLine, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", "Command" AS "LockBit Indicator",
    QIDNAME(qid) AS "Event Type", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE
    (LOWER("Command") LIKE '%ping%1.1.1.1%&&%del%'
    OR (LOWER("Command") LIKE '%vssadmin%delete%shadows%all%')
    OR EventID IN ('1102','104'))
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. **Activate IR immediately** — LockBit moves fast (full encryption in ~5 minutes on fast systems)
2. Network-isolate the host — pull the network cable if necessary
3. Do NOT reboot — this may trigger the encryption if not already started
4. Preserve memory image before power-off
5. Check for LockBit ransom note (README.txt, .lockbit extension) to confirm

---

## UC-166 — Ransomware Deployed via RDP {#uc-166}

**Threat:** Attacker gains RDP access (via brute force or stolen credentials),
manually deploys ransomware, and runs it interactively. Detectable as: RDP login
from unusual source → new executable dropped → encryption activity.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 90 |
| **MITRE** | T1021.001 + T1486 |
| **Data Sources** | Windows Security 4624/4625, Sysmon 1/11 |
| **Rule IDs** | SP-ransomware-003 |

### Splunk SPL

```spl
| join type=inner host
    [search index=windows EventCode=4624
     | where LogonType=10 AND NOT match(IpAddress,"(?i)^(10\.|192\.168\.|127\.)")
     | eval stage="rdp_login" | table _time, host, TargetUserName, IpAddress, stage]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
     | where match(TargetFilename,"(?i)(\\Temp\\|\\AppData\\|\\Desktop\\).*\.exe$")
     | eval stage="exe_dropped" | table _time, host, Image, TargetFilename, stage]
| where abs(strptime(_time, "%Y-%m-%dT%H:%M:%S") - strptime(rdp_login_time, "%Y-%m-%dT%H:%M:%S")) < 3600
| table _time, host, TargetUserName, IpAddress, TargetFilename
| sort -_time
```

### QRadar AQL

```sql
SELECT h1.destinationip AS "Target Host", h1.username AS "Compromised Account",
    h1.sourceip AS "RDP Source", h2."filename" AS "Dropped Executable",
    DATEFORMAT(h1.starttime,'yyyy-MM-dd HH:mm:ss') AS "RDP Login",
    DATEFORMAT(h2.starttime,'yyyy-MM-dd HH:mm:ss') AS "Exe Drop"
FROM events h1
JOIN events h2 ON h1.destinationip = h2.sourceip
    AND h2.starttime > h1.starttime AND h2.starttime < h1.starttime + 3600000
WHERE h1.EventID = '4624' AND h1."LogonType" = '10'
    AND h1.sourceip NOT LIKE '10.%' AND h1.sourceip NOT LIKE '192.168.%'
    AND QIDNAME(h2.qid) = 'Sysmon - File created'
    AND h2."filename" LIKE '%\\Temp\\%.exe'
LAST 2 HOURS ORDER BY h1.starttime DESC
```

### Response Actions
1. Disable RDP immediately if not required: `Set-ItemProperty -Path HKLM:\SYSTEM\...\Terminal Services -Name fDenyTSConnections -Value 1`
2. Check for Network Level Authentication (NLA) enforcement
3. Isolate host and begin ransomware IR
4. Block the source IP at the perimeter firewall
5. Enforce VPN-only access for RDP — never expose RDP directly to the internet

---

## UC-167 — Network Share Encryption (File Server Ransomware) {#uc-167}

**Threat:** Ransomware encrypts files on network shares rather than (only) local disk.
Detectable via rapid creation of many encrypted files (random names) and ransom notes
on file server shares.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 94 |
| **MITRE** | T1486 — Data Encrypted for Impact |
| **Data Sources** | Windows Security 4663/4660, File Server audit |
| **Rule IDs** | SP-ransomware-004 |

### Splunk SPL

```spl
index=windows EventCode IN (4663, 4660)
| where match(ObjectName,"(?i)\\\\fileserver\\|\\\\nas\\|\\\\shares\\")
    AND AccessMask IN ("0x2","0x6","0x40")
| bucket _time span=1m
| stats count, dc(ObjectName) as UniqueFiles by SubjectUserName, IpAddress, _time
| where UniqueFiles >= 100
| sort -UniqueFiles
```

### QRadar AQL

```sql
SELECT username AS "User", sourceip AS "Source Host",
    COUNT(DISTINCT "objectname") AS "Files Modified",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "1-Minute Window"
FROM events WHERE EventID IN ('4663','4660')
    AND "objectname" LIKE '\\\\fileserver\\%'
    AND username NOT LIKE '%$' AND username != 'SYSTEM'
GROUP BY username, sourceip, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(DISTINCT "objectname") >= 100
LAST 30 MINUTES ORDER BY "Files Modified" DESC
```

### Response Actions
1. **Immediately disable the source host's network access** — stop the encryption spread
2. Check how many files were encrypted on the share — assess recovery scope
3. Verify VSS shadow copies on the file server are intact before recovery begins
4. Identify the ransomware family — many shares have decryptors available
5. Restore from backup if VSS copies are corrupted (ransomware often targets VSS first)
