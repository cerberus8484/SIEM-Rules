# Ransomware Precursors

Use cases covering the pre-encryption kill chain. Every step of the ransomware sequence —
VSS deletion, backup service kill, boot recovery disabling, and ransom note drop — is
detectable before file encryption begins.

**Rule pack:** `backup-resilience` (SP-730001–SP-730020)  
**Correlation:** SP-810019 Backup Wiper Chain

---

## UC-001 — VSS Shadow Copy Deletion {#uc-001}

**Threat:** Attacker deletes Volume Shadow Copies to prevent recovery. Observed in
LockBit, BlackCat/ALPHV, Hive, Akira, and virtually all modern ransomware families.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 97 |
| **MITRE** | T1490 — Inhibit System Recovery |
| **Data Sources** | Windows Security 4688, Sysmon Event 1 |
| **Rule IDs** | SP-730001, SP-730002 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where match(CommandLine, "(?i)(vssadmin|wmic|powershell).*(delete.*shadow|shadowcopy.*delete|Win32_ShadowCopy)")
| eval risk_score=100
| stats count, values(CommandLine) as CommandLine, values(ParentProcessName) as Parent
    by host, user, _time
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Host",
    username AS "User",
    "Command" AS "CommandLine",
    QIDNAME(qid) AS "Event",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    (
        LOWER("Command") LIKE '%vssadmin%delete%shadow%'
        OR LOWER("Command") LIKE '%wmic%shadowcopy%delete%'
        OR LOWER("Command") LIKE '%win32_shadowcopy%delete%'
    )
    AND "Event Category" = 'Application'
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Isolate the host immediately — VSS deletion is irreversible
2. Preserve memory dump before remediation
3. Identify parent process — determine if human operator or automated ransomware dropper
4. Check for concurrent `sc stop` / `net stop` calls to backup services (→ UC-002)
5. Verify backup integrity of all affected systems

---

## UC-002 — Backup Service Kill Chain {#uc-002}

**Threat:** Attacker stops backup services (Veeam, Windows Backup, SQL Agent) to prevent
recovery and to release file locks before encryption.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 95 |
| **MITRE** | T1489 — Service Stop |
| **Data Sources** | Windows Security 4688, Windows System 7036/7040 |
| **Rule IDs** | SP-730003, SP-730004 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR EventCode=7036 OR EventCode=7040)
| where match(CommandLine, "(?i)(sc|net)\s+(stop|delete).*(vss|backup|veeam|acronis|sqlserveragent|mssql|msexchange|dfsr)")
    OR (EventCode=7036 AND match(Message, "(?i)(vss|veeam|backup|sqlserveragent|msexchange).*stopped"))
| stats count, values(CommandLine) as Commands, values(Message) as Messages
    by host, user, _time
| where count >= 1
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Host",
    username AS "User",
    "Command" AS "CommandLine",
    QIDNAME(qid) AS "Event",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    (
        (LOWER("Command") LIKE '%sc stop%' OR LOWER("Command") LIKE '%net stop%')
        AND (
            LOWER("Command") LIKE '%vss%' OR LOWER("Command") LIKE '%veeam%'
            OR LOWER("Command") LIKE '%backup%' OR LOWER("Command") LIKE '%sqlserveragent%'
            OR LOWER("Command") LIKE '%mssql%' OR LOWER("Command") LIKE '%acronis%'
        )
    )
    OR (
        LOWER("Command") LIKE '%taskkill%'
        AND (LOWER("Command") LIKE '%veeam%' OR LOWER("Command") LIKE '%backup%')
    )
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Identify which services were stopped and in what order
2. Correlate with UC-001 — VSS deletion often follows backup service kill
3. Check if the stopping process is an expected admin tool or unknown binary
4. Re-enable stopped services only after confirming no active ransomware
5. Escalate to Incident Response if 3+ services stopped within 5 minutes

---

## UC-003 — Boot Recovery Disabled via BCDEdit {#uc-003}

**Threat:** Attacker disables Windows Recovery Environment to prevent victim from
booting into recovery mode after encryption. BCDEdit and reagentc are the primary tools.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 98 |
| **MITRE** | T1490 — Inhibit System Recovery |
| **Data Sources** | Windows Security 4688, Sysmon Event 1 |
| **Rule IDs** | SP-730005, SP-730006 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where match(CommandLine, "(?i)bcdedit.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures|safeboot)")
    OR match(CommandLine, "(?i)reagentc\s+(/disable|/enable)")
| eval tactic="T1490 - Inhibit System Recovery"
| table _time, host, user, CommandLine, ParentProcessName, tactic
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
    LOWER("Command") LIKE '%bcdedit%recoveryenabled%no%'
    OR LOWER("Command") LIKE '%bcdedit%bootstatuspolicy%ignoreallfailures%'
    OR (LOWER("Command") LIKE '%reagentc%' AND LOWER("Command") LIKE '%/disable%')
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. This has near-zero false positives — treat every alert as confirmed malicious
2. Immediately isolate the host from the network
3. Re-enable recovery: `bcdedit /set recoveryenabled yes`
4. Check timeline for concurrent shadow deletion (UC-001) — ransomware sequence is underway
5. Preserve forensic evidence before remediation

---

## UC-004 — Ransom Note File Drop {#uc-004}

**Threat:** Ransomware writes a text file with payment instructions. The filename pattern
is the most reliable late-stage indicator — encryption is already in progress.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 96 |
| **MITRE** | T1486 — Data Encrypted for Impact |
| **Data Sources** | Sysmon Event 11 (FileCreate) |
| **Rule IDs** | SP-730010, SP-730011 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| where match(TargetFilename, "(?i)(HOW_TO_DECRYPT|RECOVER_FILES|README_DECRYPT|RESTORE_FILES|YOUR_FILES_ARE_ENCRYPTED|DECRYPT_INSTRUCTIONS|_readme\.txt)")
    OR match(TargetFilename, "(?i)\.(locked|crypt|locky|ryuk|blackcat|lockbit|hive|akira|rhysida|medusa|cl0p|deadbolt)$")
| stats count, values(TargetFilename) as Files, dc(TargetFilename) as UniqueFiles
    by host, Image, _time
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Host",
    username AS "User",
    "filename" AS "TargetFile",
    "process" AS "Process",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    QIDNAME(qid) = 'File Created'
    AND (
        LOWER("filename") LIKE '%how_to_decrypt%'
        OR LOWER("filename") LIKE '%recover_files%'
        OR LOWER("filename") LIKE '%readme_decrypt%'
        OR LOWER("filename") LIKE '%.locked'
        OR LOWER("filename") LIKE '%.ryuk'
        OR LOWER("filename") LIKE '%.lockbit'
        OR LOWER("filename") LIKE '%.hive'
        OR LOWER("filename") LIKE '%.akira'
    )
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. **Encryption is in progress** — isolate immediately
2. Do NOT reboot — this may trigger further encryption or destroy forensic evidence
3. Pull full list of affected file paths from Sysmon Event 11 logs
4. Identify the encrypting process (Image field) — terminate if still running
5. Engage Incident Response and notify backup team for recovery assessment

---

## UC-005 — Ransomware Precursor Kill Chain (Correlation) {#uc-005}

**Threat:** Correlation rule that scores multi-stage ransomware activity. Fires when 3 or more
precursor events occur on the same host within 10 minutes. High confidence because the
combination is extremely rare in legitimate operations.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 99 |
| **MITRE** | T1490 + T1489 + T1486 |
| **Data Sources** | Windows Security 4688, Sysmon 1/11/13 |
| **Rule IDs** | SP-810019 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| eval indicator=case(
    match(CommandLine,"(?i)vssadmin.*delete|wmic.*shadowcopy.*delete"), "vss_deletion",
    match(CommandLine,"(?i)(sc|net)\s+stop.*(vss|backup|veeam|sqlserveragent)"), "backup_service_kill",
    match(CommandLine,"(?i)bcdedit.*recoveryenabled\s+no|bootstatuspolicy.*ignoreallfailures"), "recovery_disabled",
    match(CommandLine,"(?i)wbadmin.*delete.*(catalog|backup)"), "wbadmin_delete",
    match(CommandLine,"(?i)cipher\s+/w"), "cipher_wipe",
    1=1, null()
  )
| where isnotnull(indicator)
| bin _time span=10m
| stats dc(indicator) as indicator_count, values(indicator) as indicators,
    values(CommandLine) as Commands, values(user) as Users
    by host, _time
| where indicator_count >= 3
| eval risk_score=indicator_count*25, tactic="Ransomware Kill Chain"
| sort -risk_score
```

### QRadar AQL (Rules-based — reference for Rule Builder)

```sql
-- Use this as the basis for a QRadar Building Block Rule:
-- "Ransomware Precursor Kill Chain"
-- Rule: When any 3 of the following QRadar offenses are opened for the
--       same source IP within 10 minutes:
--   1. "VSS Shadow Copy Deletion Detected"
--   2. "Backup Service Stopped by Non-System Process"
--   3. "BCDEdit Recovery Disabled"
--   4. "WBAdmin Backup Catalog Deleted"

SELECT
    sourceip AS "Host",
    COUNT(*) AS "PrecursorCount",
    MIN(DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss')) AS "FirstEvent",
    MAX(DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss')) AS "LastEvent"
FROM events
WHERE
    LOWER("Command") LIKE '%vssadmin%delete%'
    OR LOWER("Command") LIKE '%net stop%veeam%'
    OR LOWER("Command") LIKE '%bcdedit%recoveryenabled%no%'
    OR LOWER("Command") LIKE '%wbadmin%delete%catalog%'
GROUP BY sourceip
HAVING COUNT(*) >= 3
LAST 10 MINUTES
ORDER BY PrecursorCount DESC
```

### Response Actions

1. **Automated:** Create P1 ticket, page on-call SOC analyst, trigger host isolation workflow
2. Preserve complete process tree from the alert window
3. Notify backup team — verify last-known-good backup timestamp
4. Check lateral reach: which shares does this host have access to?
5. Engage full IR playbook — do not attempt manual remediation without IR lead
