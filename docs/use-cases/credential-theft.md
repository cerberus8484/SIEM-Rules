# Credential Theft

Use cases for credential dumping, Kerberos attacks, and hash extraction.
These are among the highest-confidence detections in the rule set — the
tools and techniques used have extremely low false-positive rates.

**Rule packs:** `credential_access`, `identity`

---

## UC-006 — LSASS Memory Dump via ProcDump {#uc-006}

**Threat:** Attacker uses Sysinternals ProcDump (or a renamed copy) to create a full
memory dump of lsass.exe, then extracts credentials offline with Mimikatz.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 96 |
| **MITRE** | T1003.001 — OS Credential Dumping: LSASS Memory |
| **Data Sources** | Windows Security 4688, Sysmon Event 1/10 |
| **Rule IDs** | SP-200001, SP-200002 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where match(CommandLine, "(?i)(procdump|procdump64).*lsass")
    OR match(CommandLine, "(?i)comsvcs.*minidump")
    OR match(CommandLine, "(?i)rundll32.*comsvcs.*")
    OR (match(CommandLine, "(?i)-ma") AND match(CommandLine, "(?i)lsass"))
| eval technique="T1003.001 - LSASS Memory Dump"
| table _time, host, user, CommandLine, ParentProcessName, technique
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Host",
    username AS "User",
    "Command" AS "CommandLine",
    "Parent Process" AS "ParentProcess",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    (
        (LOWER("Command") LIKE '%procdump%' OR LOWER("Command") LIKE '%procdump64%')
        AND LOWER("Command") LIKE '%lsass%'
    )
    OR (LOWER("Command") LIKE '%comsvcs%' AND LOWER("Command") LIKE '%minidump%')
    OR (LOWER("Command") LIKE '%rundll32%' AND LOWER("Command") LIKE '%comsvcs%')
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Treat as confirmed credential compromise — assume all credentials on host are stolen
2. Force password reset for all accounts that logged in to this host in the last 30 days
3. Check for `.dmp` / `.mdmp` files created by the process (Sysmon Event 11)
4. Search for outbound file transfer of the dump file (large file transfer to external IP)
5. Rotate service account and privileged account passwords immediately

---

## UC-007 — Mimikatz Execution {#uc-007}

**Threat:** Mimikatz — the most commonly used credential extraction tool. Detects
by command-line keywords, OriginalFileName, and known module names (sekurlsa, lsadump, kerberos).

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 97 |
| **MITRE** | T1003 — OS Credential Dumping |
| **Data Sources** | Windows Security 4688, Sysmon Event 1 |
| **Rule IDs** | SP-200003, SP-200004 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where match(CommandLine, "(?i)(sekurlsa|logonpasswords|lsadump|dcsync|kerberos::ptt|kerberos::list|privilege::debug|token::elevate|vault::cred|dpapi::cred|crypto::certificates)")
    OR match(OriginalFileName, "(?i)mimikatz")
    OR match(CommandLine, "(?i)invoke-mimikatz|invoke-mimikatz\.ps1")
| eval confidence=97, technique="T1003 - Mimikatz"
| table _time, host, user, CommandLine, OriginalFileName, technique
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
    LOWER("Command") LIKE '%sekurlsa%'
    OR LOWER("Command") LIKE '%logonpasswords%'
    OR LOWER("Command") LIKE '%lsadump%'
    OR LOWER("Command") LIKE '%dcsync%'
    OR LOWER("Command") LIKE '%privilege::debug%'
    OR LOWER("Command") LIKE '%token::elevate%'
    OR LOWER("Command") LIKE '%kerberos::ptt%'
    OR LOWER("Command") LIKE '%invoke-mimikatz%'
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Full credential rotation for the affected host and any connected systems
2. Check for .kirbi ticket files (Sysmon Event 11) — indicates pass-the-ticket
3. Review DC Security event logs for 4662 (DCSync) or 4769 (Kerberos Service Ticket)
4. Forensically analyze the binary — may be renamed to evade detection
5. Check AMSI bypass commands in PowerShell history

---

## UC-008 — DCSync Attack {#uc-008}

**Threat:** Attacker replicates AD password hashes by abusing the Domain Controller
replication protocol. No malware required — only domain replication rights.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 94 |
| **MITRE** | T1003.006 — OS Credential Dumping: DCSync |
| **Data Sources** | Windows Security 4662 (DC), Sysmon 1 |
| **Rule IDs** | SP-200005 |

### Splunk SPL

```spl
| union
    [search index=windows EventCode=4662
     | where match(Properties, "(?i)1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c")
     | where NOT match(SubjectUserName, "(?i)\$$")
     | eval source="DC Replication Rights"]
    [search index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
     | where match(CommandLine, "(?i)(secretsdump|lsadump::dcsync|impacket)")
     | eval source="DCSync Tool"]
| stats count, values(source) as DetectionSource by host, user, _time
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Source Host",
    destinationip AS "Target DC",
    username AS "User",
    "objectname" AS "Object",
    QIDNAME(qid) AS "Event",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    EventID = '4662'
    AND (
        "Properties" LIKE '%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%'
        OR "Properties" LIKE '%1131f6ad-9c07-11d1-f79f-00c04fc2dcd2%'
        OR "Properties" LIKE '%89e95b76-444d-4c62-991a-0facbeda640c%'
    )
    AND username NOT LIKE '%$'
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. **All AD hashes are compromised** — initiate full krbtgt rotation procedure
2. Rotate krbtgt twice (for Golden Ticket invalidation)
3. Check which account initiated the sync — was it a service account or user?
4. Review if account has DS-Replication-Get-Changes permissions
5. Engage AD recovery runbook

---

## UC-009 — Kerberoasting — GetUserSPNs {#uc-009}

**Threat:** Attacker requests Kerberos service tickets for accounts with SPNs,
then brute-forces the RC4 ticket offline to recover plaintext passwords.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 85 |
| **MITRE** | T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting |
| **Data Sources** | Windows Security 4769 (DC), Sysmon Event 1 |
| **Rule IDs** | SP-200007, SP-200008 |

### Splunk SPL

```spl
| union
    [search index=windows EventCode=4769
     | where TicketEncryptionType="0x17" AND ServiceName!="krbtgt" AND NOT match(ServiceName, "\$$")
     | stats count by ClientAddress, AccountName, ServiceName, _time
     | where count >= 5
     | eval source="4769 RC4 Ticket Burst"]
    [search index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
     | where match(CommandLine, "(?i)(GetUserSPNs|Invoke-Kerberoast|Rubeus.*kerberoast|request.*spn)")
     | eval source="Tool Detected"]
| sort -_time
```

### QRadar AQL

```sql
SELECT
    "ClientAddress" AS "Source IP",
    username AS "Account",
    "ServiceName" AS "Target SPN",
    COUNT(*) AS "TicketCount",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    EventID = '4769'
    AND "TicketEncryptionType" = '0x17'
    AND username NOT LIKE '%$'
    AND "ServiceName" NOT LIKE 'krbtgt%'
GROUP BY "ClientAddress", username, "ServiceName"
HAVING COUNT(*) >= 5
LAST 1 HOURS
ORDER BY TicketCount DESC
```

### Response Actions

1. Identify service accounts targeted — force password change on all Kerberoastable accounts
2. Ensure targeted service account passwords are 25+ characters (brute-force resistant)
3. Check if targeted accounts have high-privilege roles
4. Consider converting RC4-only service accounts to AES-256 Kerberos
5. Review who requested the tickets and from which workstation

---

## UC-010 — NTDS.dit Extraction {#uc-010}

**Threat:** Attacker extracts the Active Directory database file (NTDS.dit) to dump
all domain password hashes offline. Achieved via ntdsutil, VSS, or disk-level copy.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 95 |
| **MITRE** | T1003.003 — OS Credential Dumping: NTDS |
| **Data Sources** | Windows Security 4688, Sysmon Event 1/11 |
| **Rule IDs** | SP-200009, SP-200010 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (1,11))
| where match(CommandLine, "(?i)ntdsutil.*ifm|ntdsutil.*ac\s+i\s+ntds")
    OR match(CommandLine, "(?i)vssadmin.*ntds\.dit")
    OR (EventCode=11 AND match(TargetFilename, "(?i)ntds\.dit") AND NOT match(TargetFilename, "\\Windows\\NTDS\\"))
    OR match(CommandLine, "(?i)(copy|xcopy|robocopy).*ntds\.dit")
| eval technique="T1003.003 - NTDS Extraction"
| table _time, host, user, CommandLine, TargetFilename, technique
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
    LOWER("Command") LIKE '%ntdsutil%'
    OR (LOWER("Command") LIKE '%ntds.dit%'
        AND (LOWER("Command") LIKE '%copy%' OR LOWER("Command") LIKE '%vssadmin%'))
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. **All domain credentials are compromised** — initiate full AD recovery
2. Identify the output path and check for exfiltration (outbound large file transfer)
3. Full krbtgt rotation (twice) — prevents Golden Ticket attacks
4. All privileged account passwords must be rotated
5. Consider forest recovery if domain admin accounts were extracted

---

## UC-011 — SAM/SECURITY Hive Dump via Reg {#uc-011}

**Threat:** Attacker uses `reg.exe save` to copy the SAM and SECURITY registry hives,
which contain local account password hashes. Offline cracking recovers local admin passwords.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 96 |
| **MITRE** | T1003.002 — OS Credential Dumping: Security Account Manager |
| **Data Sources** | Windows Security 4688, Sysmon Event 1 |
| **Rule IDs** | SP-200011 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where match(CommandLine, "(?i)reg\s+(save|export).*(hklm\\sam|hklm\\security|hklm\\system)")
    OR match(CommandLine, "(?i)(esentutl|ntdsutil).*(sam|security|system)")
| eval technique="T1003.002 - SAM Hive Dump"
| table _time, host, user, CommandLine, technique
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
    (LOWER("Command") LIKE '%reg%save%' OR LOWER("Command") LIKE '%reg%export%')
    AND (
        LOWER("Command") LIKE '%hklm\\sam%'
        OR LOWER("Command") LIKE '%hklm\\security%'
        OR LOWER("Command") LIKE '%hklm\\system%'
    )
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Force local administrator password rotation on affected host
2. Verify LAPS is deployed — if not, all local admin hashes with same password are compromised
3. Check for outbound file transfer of the hive files (look for .sav extension)
4. If domain user was harvested: rotate affected domain account immediately
5. Review who called reg.exe — was it interactive or from a remote session?
