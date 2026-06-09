# Lateral Movement

Use cases for detecting attacker movement from one host to another after initial compromise.

**Rule packs:** `lateral_movement`, `windows_sysmon`

---

## UC-012 — PsExec Lateral Movement {#uc-012}

**Threat:** Attacker uses Sysinternals PsExec (or a renamed copy) to execute commands
on remote hosts over SMB. Creates the PSEXESVC service on the target.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 88 |
| **MITRE** | T1570 — Lateral Tool Transfer / T1021.002 — Remote Services: SMB |
| **Data Sources** | Windows Security 4688/7045, Sysmon Event 1/17 |
| **Rule IDs** | SP-300001, SP-300002 |

### Splunk SPL

```spl
| union
    [search index=windows EventCode=7045
     | where ServiceName="PSEXESVC"
     | eval source="Service Install"]
    [search index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
     | where match(Image, "(?i)psexec(64)?\.exe") OR match(OriginalFileName, "(?i)psexec")
     | eval source="PsExec Binary"]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=17
     | where match(PipeName, "(?i)\\\\PSEXESVC")
     | eval source="Named Pipe"]
| table _time, host, user, CommandLine, source
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Source Host",
    destinationip AS "Target Host",
    username AS "User",
    "Command" AS "CommandLine",
    QIDNAME(qid) AS "Event",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    LOWER("Command") LIKE '%psexec%'
    OR "ServiceName" = 'PSEXESVC'
    OR LOWER("PipeName") LIKE '%psexesvc%'
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Identify source and all target hosts — map the lateral movement path
2. Check if this is authorized admin activity (compare against change records)
3. Terminate the PSEXESVC service on target hosts: `sc \\target stop PSEXESVC`
4. Review all commands executed via PsExec in the session (child processes of PSEXESVC)
5. If unauthorized: treat all visited hosts as compromised

---

## UC-013 — WMI Remote Execution {#uc-013}

**Threat:** Attacker uses WMI (wmic or PowerShell Win32_Process) to execute commands
on remote hosts without needing to drop a service binary.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 82 |
| **MITRE** | T1047 — Windows Management Instrumentation |
| **Data Sources** | Windows Security 4688, Sysmon Event 1 |
| **Rule IDs** | SP-300003, SP-300004 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where match(CommandLine, "(?i)wmic.*/node:.+process\s+call\s+create")
    OR match(CommandLine, "(?i)invoke-wmimethod.*win32_process.*create")
    OR match(CommandLine, "(?i)invoke-cimmethod.*win32_process.*create")
    OR (match(ParentProcessName, "(?i)wmiprvse\.exe") AND NOT match(Image, "(?i)(msiexec|svchost|wermgr)"))
| table _time, host, user, CommandLine, ParentProcessName
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Source Host",
    destinationip AS "Target Host",
    username AS "User",
    "Command" AS "CommandLine",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    (LOWER("Command") LIKE '%wmic%/node:%' AND LOWER("Command") LIKE '%process%call%create%')
    OR (LOWER("Command") LIKE '%invoke-wmimethod%' AND LOWER("Command") LIKE '%win32_process%')
    OR ("ParentProcessName" LIKE '%wmiprvse.exe%'
        AND "process" NOT IN ('msiexec.exe', 'svchost.exe', 'wermgr.exe'))
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Identify which nodes were targeted (extract `/node:` parameter)
2. Check child processes of wmiprvse.exe on target hosts for executed commands
3. Correlate with logon events — which credential was used for WMI auth?
4. Disable WMI remote execution if not required: firewall port 135 between workstations
5. Review WMI subscriptions on visited hosts (→ UC-024 Persistence)

---

## UC-014 — RDP Lateral Movement {#uc-014}

**Threat:** Attacker uses Remote Desktop Protocol to interactively access hosts. May use
legitimate credentials, harvested passwords, or pass-the-hash (Restricted Admin mode).

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 75 |
| **MITRE** | T1021.001 — Remote Services: Remote Desktop Protocol |
| **Data Sources** | Windows Security 4624/4625/4778, RDP EventLog |
| **Rule IDs** | SP-300005, SP-300006 |

### Splunk SPL

```spl
index=windows EventCode IN (4624, 4778)
| where LogonType=10 OR LogonType=7
| where IpAddress!="127.0.0.1" AND IpAddress!="-" AND IpAddress!="::1"
| stats count, dc(IpAddress) as SourceCount, values(IpAddress) as SourceIPs
    by host, AccountName, _time
| where SourceCount > 1
| eval alert="Multiple Source IPs for same account"
| sort -SourceCount

| append
    [search index=windows EventCode=4625 LogonType=10
     | stats count by TargetUserName, IpAddress, _time
     | where count >= 5
     | eval alert="RDP Brute Force"]
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Source IP",
    destinationip AS "Target Host",
    username AS "Account",
    "LogonType" AS "LogonType",
    COUNT(*) AS "SessionCount",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    EventID IN ('4624', '4778')
    AND "LogonType" IN ('10', '7')
    AND sourceip NOT IN ('127.0.0.1', '::1')
GROUP BY sourceip, destinationip, username
HAVING COUNT(*) >= 1
LAST 24 HOURS
ORDER BY SessionCount DESC
```

### Response Actions

1. Map all RDP sessions in the timeframe — build attacker movement graph
2. Check if source IP is a workstation (unusual) or jump server (expected)
3. Review clipboard transfer and file drag-drop during session (RDP clipboard logs)
4. If pass-the-hash is suspected: check for NTLMv1 auth (Event 4624 LogonType=10 with NTLMv1)
5. Disable Restricted Admin RDP mode if not required: `reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1`

---

## UC-015 — WinRM / PowerShell Remoting {#uc-015}

**Threat:** Attacker uses PowerShell remoting (WinRM, port 5985/5986) for lateral movement.
Harder to detect than PsExec — no service installation, uses HTTP/HTTPS transport.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 78 |
| **MITRE** | T1021.006 — Remote Services: Windows Remote Management |
| **Data Sources** | Windows Security 4624, PowerShell 4103/4104 |
| **Rule IDs** | SP-300007 |

### Splunk SPL

```spl
| union
    [search index=windows EventCode=4624
     | where LogonType=3 AND AuthenticationPackageName="Kerberos"
     | where match(ProcessName, "(?i)wsmprovhost")
     | eval source="WinRM Logon"]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode IN (4103,4104)
     | where match(ScriptBlockText, "(?i)(New-PSSession|Invoke-Command|Enter-PSSession).*-ComputerName")
     | eval source="PS Remoting Command"]
| table _time, host, user, CommandLine, ScriptBlockText, source
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Source Host",
    destinationip AS "Target Host",
    username AS "User",
    destinationport AS "Port",
    QIDNAME(qid) AS "Event",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    destinationport IN (5985, 5986)
    AND "process" NOT IN ('svchost.exe', 'System')
    AND "AuthenticationPackage" NOT IN ('ANONYMOUS LOGON')
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. WinRM is rarely used host-to-host in normal operations — investigate immediately
2. Pull full PowerShell transcript from the session if ScriptBlock logging is enabled
3. Identify all commands executed in the session
4. Check if WinRM is legitimately enabled: `Get-Service WinRM`
5. Restrict WinRM access to jump servers only via GPO: `Set-Item WSMan:\localhost\Client\TrustedHosts`

---

## UC-016 — Pass-the-Hash / Pass-the-Ticket {#uc-016}

**Threat:** Attacker reuses stolen NTLM hashes or Kerberos tickets to authenticate
without knowing the plaintext password. No brute force required.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 80 |
| **MITRE** | T1550 — Use Alternate Authentication Material |
| **Data Sources** | Windows Security 4624/4768/4769 |
| **Rule IDs** | SP-300008, SP-300009 |

### Splunk SPL

```spl
| union
    [search index=windows EventCode=4624
     | where LogonType=3 AND AuthenticationPackageName="NTLM" AND NTLMv1 = "true"
     | eval technique="Pass-the-Hash (NTLMv1)"
     | where IpAddress!="127.0.0.1"]
    [search index=windows EventCode=4768
     | where TicketEncryptionType="0x17" AND NOT match(TargetUserName, "\$$")
     | eval technique="Overpass-the-Hash (RC4 TGT)"]
    [search index=windows EventCode=4769
     | where TicketEncryptionType="0x17" AND NOT match(ServiceName, "krbtgt")
     | stats count by ClientAddress, AccountName, _time
     | where count >= 10
     | eval technique="Pass-the-Ticket Burst"]
| table _time, host, user, IpAddress, technique
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Source IP",
    destinationip AS "Target Host",
    username AS "Account",
    "AuthenticationPackage" AS "AuthType",
    "LogonType" AS "LogonType",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    EventID = '4624'
    AND "LogonType" = '3'
    AND "AuthenticationPackage" = 'NTLM'
    AND sourceip NOT IN ('127.0.0.1', '::1')
    AND username NOT LIKE '%$'
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Pass-the-Hash: Reset the NTLM hash — force password change for affected account
2. Identify which systems the attacker accessed using the stolen hash
3. Check for logons with mismatched source IP (account logs in from IP ≠ normal workstation)
4. Enable Protected Users security group for privileged accounts (prevents NTLM auth)
5. Deploy LAPS for local administrator accounts — limits lateral movement blast radius
