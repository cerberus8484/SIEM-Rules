# Persistence

Use cases for detecting attacker mechanisms to maintain access after reboot or credential rotation.

**Rule packs:** `windows_sysmon`, `execution`

---

## UC-023 — Registry Run Key Persistence {#uc-023}

**Threat:** Attacker writes a value to HKLM/HKCU Run or RunOnce keys to execute
malware on every logon. One of the most common persistence mechanisms.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 75 |
| **MITRE** | T1547.001 — Registry Run Keys / Startup Folder |
| **Data Sources** | Windows Security 4657, Sysmon Event 13 |
| **Rule IDs** | SP-400001 |

### Splunk SPL

```spl
index=windows (EventCode=4657 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13)
| where match(ObjectName, "(?i)(SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce)")
    OR match(TargetObject, "(?i)(SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce)")
| eval value=coalesce(NewValue, Details)
| where NOT match(value, "(?i)(C:\\Program Files|C:\\Windows\\System32|C:\\Windows\\SysWOW64)")
| table _time, host, user, TargetObject, value
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Host",
    username AS "User",
    "objectname" AS "RegistryKey",
    "newvalue" AS "Value",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    EventID IN ('4657', '4663')
    AND (
        LOWER("objectname") LIKE '%currentversion\\run%'
        OR LOWER("objectname") LIKE '%currentversion\\runonce%'
    )
    AND "newvalue" NOT LIKE 'C:\\Program Files%'
    AND "newvalue" NOT LIKE 'C:\\Windows\\System32%'
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Examine the value written — what binary/script will execute on next logon?
2. Delete the run key value if malicious
3. Scan the binary for malware
4. Check if the process that wrote the key is the malware itself (parent process)
5. Review all run keys on the host for additional persistence entries

---

## UC-024 — WMI Event Subscription Persistence {#uc-024}

**Threat:** Attacker creates a WMI event subscription to execute code on system events
(logon, process start, time interval). Survives reboots and is invisible to most AV.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 88 |
| **MITRE** | T1546.003 — Event Triggered Execution: Windows Management Instrumentation Event Subscription |
| **Data Sources** | Sysmon Events 19/20/21, WMI Activity Log |
| **Rule IDs** | SP-400003, SP-400004 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (19,20,21)
| eval event_type=case(EventCode=19, "Filter Created", EventCode=20, "Consumer Created", EventCode=21, "Binding Created")
| table _time, host, user, event_type, Name, Query, Destination
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Host",
    username AS "User",
    QIDNAME(qid) AS "WMI Event Type",
    "Name" AS "SubscriptionName",
    "Destination" AS "ConsumerDestination",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    QIDNAME(qid) IN (
        'Sysmon - WmiEventFilter activity detected',
        'Sysmon - WmiEventConsumer activity detected',
        'Sysmon - WmiEventConsumerToFilter activity detected'
    )
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. List all WMI subscriptions on the host: `Get-WMIObject -Namespace root\subscription -Class __EventFilter`
2. Remove malicious subscription: `Get-WmiObject __EventFilter -namespace root\subscription | Remove-WmiObject`
3. Identify what command the consumer executes
4. WMI subscriptions are rare in legitimate operations — treat as high priority
5. Check for matching subscription name patterns in IR threat intel feeds

---

## UC-025 — Scheduled Task Created by Script {#uc-025}

**Threat:** Attacker creates a scheduled task via schtasks.exe or PowerShell New-ScheduledTask
to maintain persistence or execute payloads at a future time.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 70 |
| **MITRE** | T1053.005 — Scheduled Task/Job: Scheduled Task |
| **Data Sources** | Windows Security 4698/4702, Sysmon Event 1 |
| **Rule IDs** | SP-400005 |

### Splunk SPL

```spl
| union
    [search index=windows EventCode IN (4698, 4702)
     | eval source="Security Log - Task Created/Modified"
     | where NOT match(TaskName, "(?i)(\\Microsoft\\Windows\\|\\Microsoft\\Office\\)")]
    [search index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
     | where match(CommandLine, "(?i)schtasks.*(\/create|\/change).*(\/tr|\/ru)")
         AND (match(CommandLine, "(?i)\\AppData\\|\\Temp\\|\\ProgramData\\") OR match(CommandLine, "(?i)powershell|cmd|wscript|mshta"))
     | eval source="CLI - schtasks"]
| table _time, host, user, CommandLine, TaskName, source
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Host",
    username AS "User",
    "TaskName" AS "TaskName",
    "Command" AS "CommandLine",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    EventID IN ('4698', '4702')
    AND "TaskName" NOT LIKE '\\Microsoft\\Windows\\%'
    AND "TaskName" NOT LIKE '\\Microsoft\\Office\\%'
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. List all non-Microsoft scheduled tasks: `Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\Microsoft\*'}`
2. Examine the task action and trigger
3. Delete if malicious: `Unregister-ScheduledTask -TaskName "TaskName" -Confirm:$false`
4. Check the binary pointed to by the task action
5. Review who created the task and from which process

---

## UC-026 — New Service Installation {#uc-026}

**Threat:** Attacker installs a malicious Windows service for persistence or to run
as SYSTEM. Commonly done by PsExec, MSI installers, and rootkits.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 72 |
| **MITRE** | T1543.003 — Create or Modify System Process: Windows Service |
| **Data Sources** | Windows System 7045, Sysmon Event 13 |
| **Rule IDs** | SP-400006 |

### Splunk SPL

```spl
index=windows EventCode=7045
| where NOT match(ServiceName, "(?i)(^(Wudfrd|WdFilter|WdNisDrv|mssecflt|sense|Microsoft|Windows|Defender|CrowdStrike|SentinelOne))")
    AND NOT match(ServiceFileName, "(?i)(C:\\Windows\\System32|C:\\Program Files)")
| table _time, host, user, ServiceName, ServiceFileName, ServiceType, ServiceStartType
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Host",
    username AS "User (Installer)",
    "ServiceName" AS "Service Name",
    "ServiceFileName" AS "Binary Path",
    "ServiceType" AS "Type",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    EventID = '7045'
    AND "ServiceFileName" NOT LIKE 'C:\\Windows\\System32%'
    AND "ServiceFileName" NOT LIKE 'C:\\Program Files%'
    AND "ServiceName" NOT LIKE '%Microsoft%'
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Review the service binary path — is it in a temp or user-writable directory?
2. Stop and delete if malicious: `sc stop ServiceName && sc delete ServiceName`
3. Check service run-as account — SYSTEM-level services require elevated privileges
4. Scan the binary for malware
5. Check if similar service names exist across other hosts (lateral spread)
