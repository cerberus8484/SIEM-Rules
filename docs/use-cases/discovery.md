# Discovery & Reconnaissance

Use cases for detecting attacker enumeration of Active Directory, hosts, and network assets.

**Rule packs:** `windows_sysmon`, `credential_access`

---

## UC-061 — BloodHound / SharpHound AD Enumeration {#uc-061}

**Threat:** BloodHound collects AD graph data (ACLs, group memberships, session info) via
LDAP/Kerberos to find attack paths to Domain Admin. SharpHound is the ingestor.
Generates massive LDAP query bursts with unusual filter strings.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 88 |
| **MITRE** | T1087.002 — Account Discovery: Domain Account |
| **Data Sources** | Windows Security 4662 (DC), Sysmon 1, Network LDAP logs |
| **Rule IDs** | SP-discovery-001 |

### Splunk SPL

```spl
| union
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
     | where match(CommandLine,"(?i)(sharphound|bloodhound|azurehound|-CollectionMethod|--ldapusername|SharpHound\.exe)")]
    [search index=windows EventCode=4662
     | stats count by SubjectUserName, host, _time
     | where count > 1000
     | eval detection="Excessive LDAP queries - possible BloodHound"]
| table _time, host, user, CommandLine, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Source", username AS "User",
    "Command" AS "CommandLine", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND (LOWER("Command") LIKE '%sharphound%'
        OR LOWER("Command") LIKE '%bloodhound%'
        OR LOWER("Command") LIKE '%-collectionmethod%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Identify the host that ran SharpHound — dump memory, collect artifacts
2. Check what Collection methods were used (`-CollectionMethod All` = full enumeration)
3. BloodHound data may be exfiltrated — check for JSON file drops and uploads
4. Review subsequent actions by the same user/process
5. Rebuild BloodHound graph in defensive mode to understand what the attacker discovered

---

## UC-062 — Port Scan from Internal Host {#uc-062}

**Threat:** After initial compromise, attacker scans the internal network to find other
exploitable systems. Tools: nmap, Masscan, Invoke-Portscan, or raw PowerShell socket loops.
Detectable via high connection volume to diverse IPs/ports.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 82 |
| **MITRE** | T1046 — Network Service Discovery |
| **Data Sources** | Sysmon Event 3 (NetworkConnect), Firewall logs |
| **Rule IDs** | SP-discovery-002 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| where Initiated="true"
| bucket _time span=5m
| stats dc(DestinationIp) as UniqueIPs, dc(DestinationPort) as UniquePorts, count by SourceIp, host, Image, _time
| where UniqueIPs >= 20 OR UniquePorts >= 50
| eval scan_type=case(UniqueIPs>=20 AND UniquePorts<=5, "Host Discovery", UniquePorts>=50, "Port Scan", 1=1, "Mixed Scan")
| table _time, host, Image, SourceIp, UniqueIPs, UniquePorts, scan_type
| sort -UniqueIPs
```

### QRadar AQL

```sql
SELECT "SourceAddress" AS "Scanner", QIDNAME(qid) AS "Event",
    COUNT(*) AS "Connections", COUNT(DISTINCT destinationip) AS "Unique Targets",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Window Start"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Network connection detected'
    AND "Initiated" = 'true'
    AND starttime > NOW()-300000
GROUP BY "SourceAddress", QIDNAME(qid), DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(DISTINCT destinationip) >= 20
ORDER BY "Unique Targets" DESC
LAST 1 HOURS
```

### Response Actions
1. Isolate scanner host — this indicates active post-exploitation
2. Check what ports and services were discovered (correlate with subsequent lateral movement)
3. Look for nmap.exe / masscan.exe binary on disk
4. Rotate credentials on systems that were reachable from the scanner
5. Check for nmap XML output files as exfiltration indicators

---

## UC-063 — LDAP Enumeration for Domain Admins {#uc-063}

**Threat:** Attacker enumerates Domain Admins, Enterprise Admins, or privileged groups
via LDAP to identify high-value targets. Often precedes privilege escalation or Kerberoasting.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 72 |
| **MITRE** | T1069.002 — Permission Groups Discovery: Domain Groups |
| **Data Sources** | Windows Security 4661/4662 (DC) |
| **Rule IDs** | SP-discovery-003 |

### Splunk SPL

```spl
index=windows EventCode=4661
| where match(ObjectName,"(?i)(Domain Admins|Enterprise Admins|Schema Admins|Backup Operators|Account Operators)")
    AND NOT match(SubjectUserName,"(?i)(MSOL_|AAD_|AZUREAD|\$$|krbtgt)")
| stats count by SubjectUserName, ObjectName, host, _time
| where count >= 5
| sort -count
```

### QRadar AQL

```sql
SELECT username AS "Querier", "ObjectName" AS "Group Queried",
    COUNT(*) AS "Query Count", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID = '4661'
    AND ("ObjectName" LIKE '%Domain Admins%' OR "ObjectName" LIKE '%Enterprise Admins%'
        OR "ObjectName" LIKE '%Backup Operators%')
    AND username NOT LIKE '%$'
GROUP BY username, "ObjectName", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(*) >= 5
LAST 24 HOURS ORDER BY "Query Count" DESC
```

### Response Actions
1. Identify which account performed the enumeration
2. If a service account — it may have been compromised
3. Correlate with subsequent login attempts to the enumerated accounts
4. Review AD audit policy: ensure object access auditing is enabled on sensitive groups
5. Implement AD tiering to prevent low-privilege accounts from querying sensitive groups

---

## UC-064 — Local Admin Discovery via net Commands {#uc-064}

**Threat:** Attacker runs `net localgroup administrators` or `net user` to enumerate local
accounts and identify privileged accounts for lateral movement.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 68 |
| **MITRE** | T1087.001 — Account Discovery: Local Account |
| **Data Sources** | Windows Security 4688, Sysmon Event 1 |
| **Rule IDs** | SP-discovery-004 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where match(CommandLine,"(?i)(net\s+(user|group|localgroup|accounts)|net\.exe\s+(user|localgroup)|whoami\s+/all|query\s+user)")
    AND NOT match(ParentImage,"(?i)(ansible|puppet|chef|sccm)")
| bucket _time span=10m
| stats count, values(CommandLine) as commands by host, user, _time
| where count >= 3
| sort -count
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "Command" AS "CommandLine", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND (LOWER("Command") LIKE '%net localgroup%'
        OR LOWER("Command") LIKE '%net user%'
        OR LOWER("Command") LIKE '%whoami /all%')
    AND username NOT LIKE '%$'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Correlate with other discovery commands from the same host/user in the same timeframe
2. A single command may be legitimate; 3+ different recon commands is high-confidence compromise
3. Check parent process — was this executed from a script, macro, or interactive shell?
4. Alert if this follows any other attack chain indicators from the same host

---

## UC-065 — Domain Controller Discovery {#uc-065}

**Threat:** Attacker identifies domain controllers — the highest-value targets in an AD
environment. Methods: nltest /dclist, nslookup _ldap._tcp, PowerShell Get-ADDomainController.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 80 |
| **MITRE** | T1018 — Remote System Discovery |
| **Data Sources** | Windows Security 4688, Sysmon Event 1 |
| **Rule IDs** | SP-discovery-005 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where match(CommandLine,"(?i)(nltest\s+/dclist|nltest\s+/dsgetdc|nslookup\s+_ldap|Get-ADDomainController|[Nn]et\s+group.*Domain\s+Controllers)")
    AND NOT match(ParentImage,"(?i)(ansible|sccm|services\.exe)")
| table _time, host, user, CommandLine, ParentImage
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "Command" AS "CommandLine", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND (LOWER("Command") LIKE '%nltest%dclist%'
        OR LOWER("Command") LIKE '%nltest%dsgetdc%'
        OR LOWER("Command") LIKE '%get-addomaincontroller%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Treat as part of a recon chain — correlate with BloodHound, net commands, nmap from same host
2. Check if the account that ran the command is authorized (admins doing discovery vs. compromised user)
3. Alert on non-admin users running domain discovery tools
4. Check DC Event Log for unusual queries from this source IP shortly after

---

## UC-066 — SMB Share Enumeration {#uc-066}

**Threat:** Attacker enumerates SMB shares to find accessible file shares containing
sensitive data or to identify lateral movement targets.
Methods: net view, Invoke-ShareFinder, smbclient.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 70 |
| **MITRE** | T1135 — Network Share Discovery |
| **Data Sources** | Windows Security 4688/5140, Sysmon Event 1/3 |
| **Rule IDs** | SP-discovery-006 |

### Splunk SPL

```spl
| union
    [search index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
     | where match(CommandLine,"(?i)(net\s+view|Invoke-ShareFinder|Find-DomainShare|smbclient\s+-L)")
     | eval detection="Share Enumeration Command"]
    [search index=windows EventCode=5140
     | bucket _time span=5m
     | stats dc(IpAddress) as Sources, count by host, _time
     | where Sources >= 5
     | eval detection="Multiple Hosts Accessing Share"]
| table _time, host, user, CommandLine, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Scanner", destinationip AS "File Server",
    "ShareName" AS "Share", COUNT(*) AS "Access Count",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID = '5140'
GROUP BY sourceip, destinationip, "ShareName", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(*) >= 10
LAST 1 HOURS ORDER BY "Access Count" DESC
```

### Response Actions
1. Determine which shares were accessed and what data they contain
2. Check 5140 events for which shares were actually opened vs. just enumerated
3. Consider hiding internal share listings from standard users (Access-Based Enumeration)
4. Correlate with data staging and exfiltration indicators

---

## UC-067 — Security Software Discovery {#uc-067}

**Threat:** Attacker enumerates installed security software (AV, EDR, firewalls) to
understand the defensive landscape and plan evasion accordingly.
Methods: tasklist, sc query, Get-MpComputerStatus, wmic /namespace antivirus.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 65 |
| **MITRE** | T1518.001 — Software Discovery: Security Software Discovery |
| **Data Sources** | Windows Security 4688, Sysmon Event 1 |
| **Rule IDs** | SP-discovery-007 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where match(CommandLine,"(?i)(Get-MpComputerStatus|sc\s+query.*defender|tasklist.*Malware|wmic.*antivirus|netsh.*wf\.msc|Get-WinEvent.*Defender)")
    OR match(CommandLine,"(?i)(wmic\s+/namespace.*\\\\root\\\\SecurityCenter|Get-CimInstance.*AntiVirusProduct)")
| table _time, host, user, Image, CommandLine
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "Command" AS "CommandLine", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND (LOWER("Command") LIKE '%get-mpcomputerstatus%'
        OR LOWER("Command") LIKE '%securitycenter%'
        OR LOWER("Command") LIKE '%antivirusproduct%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Treat as pre-evasion reconnaissance — expect defense evasion techniques to follow shortly
2. Correlate with AMSI bypass, Defender disable attempts from same host
3. Review what was executed immediately after (within 30 minutes) from same host
4. Consider deploying decoy security software to detect this behavior as a tripwire

---

## UC-068 — SystemInfo / OS Recon {#uc-068}

**Threat:** Attacker collects detailed system information (hostname, OS version, domain,
IP configuration) to understand the environment and plan escalation.
Typically automated in initial payload execution.

| Field | Value |
|---|---|
| **Severity** | Low |
| **Confidence** | 55 |
| **MITRE** | T1082 — System Information Discovery |
| **Data Sources** | Windows Security 4688, Sysmon Event 1 |
| **Rule IDs** | SP-discovery-008 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where match(CommandLine,"(?i)^(systeminfo|ipconfig\s+/all|hostname|whoami|ver|set\s+)$")
    OR (match(CommandLine,"(?i)(systeminfo|ipconfig\s+/all|whoami|hostname)")
        AND match(ParentImage,"(?i)(powershell|cmd|wscript|cscript|mshta)"))
| bucket _time span=5m
| stats count, values(CommandLine) as cmds by host, user, _time
| where count >= 4
| sort -count
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    COUNT(*) AS "Recon Commands",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "5min Window"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND (LOWER("process") IN ('systeminfo.exe','ipconfig.exe','whoami.exe','hostname.exe')
        OR LOWER("Command") LIKE '%ipconfig /all%')
GROUP BY sourceip, username, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(*) >= 4
LAST 24 HOURS ORDER BY "Recon Commands" DESC
```

### Response Actions
1. Low severity alone — only escalate when combined with other post-exploitation indicators
2. Correlate with execution from unusual location, encoded PowerShell, or lateral movement
3. Review the parent process that spawned the recon chain
4. Build a timeline: initial_access → execution → recon → lateral movement

---

## UC-069 — Active Directory ACL Abuse Discovery {#uc-069}

**Threat:** Attacker uses PowerView/SharpView to enumerate AD ACL misconfigurations
(WriteDACL, GenericAll, GenericWrite) that enable privilege escalation without exploits.
These permissions allow password resets, DCSync grants, or object modifications.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 85 |
| **MITRE** | T1069.002 — Permission Groups Discovery: Domain Groups |
| **Data Sources** | Windows Security 4688/4662, Sysmon 1 |
| **Rule IDs** | SP-discovery-009 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where match(CommandLine,"(?i)(Get-ObjectAcl|Find-InterestingDomainAcl|Get-DomainObjectAcl|Invoke-ACLScanner|SharpView\.exe|Find-GPODelegation|Get-DomainGPO)")
    OR (match(Image,"(?i)(powershell|pwsh)") AND match(CommandLine,"(?i)(WriteProperty|GenericAll|WriteDACL|GenericWrite)"))
| table _time, host, user, CommandLine
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "Command" AS "CommandLine", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND (LOWER("Command") LIKE '%get-objectacl%'
        OR LOWER("Command") LIKE '%find-interestingdomainacl%'
        OR LOWER("Command") LIKE '%get-domainobjectacl%'
        OR LOWER("Command") LIKE '%invoke-aclscanner%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Identify misconfigurations discovered — use ADACLScanner defensively to enumerate the same
2. If attacker found WriteDACL on a domain object — treat as near-privilege-escalation
3. Review AD ACLs on sensitive objects: AdminSDHolder, Domain Admins, krbtgt, GPOs
4. Implement AD ACL monitoring via Purple Knight or BloodHound CE (enterprise)
5. Begin IR — this technique indicates targeted AD attack

---

## UC-070 — Browser History / Credential Discovery {#uc-070}

**Threat:** Attacker reads browser profile data (Chrome/Edge/Firefox) to extract saved
passwords, cookies, and browsing history. Also reads Windows Credential Manager store.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 80 |
| **MITRE** | T1555.003 — Credentials from Password Stores: Credentials from Web Browsers |
| **Data Sources** | Sysmon Events 10/11 |
| **Rule IDs** | SP-discovery-010 |

### Splunk SPL

```spl
| union
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
     | where match(TargetFilename,"(?i)(\\Google\\Chrome\\User Data\\Default\\Login Data|\\Microsoft\\Edge\\User Data\\Default\\Login Data|\\Mozilla\\Firefox\\Profiles.*key.*\\.db)")
     | where NOT match(Image,"(?i)(chrome|msedge|firefox)")
     | eval detection="Browser DB Access"]
    [search index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
     | where match(CommandLine,"(?i)(Get-StoredCredential|cmdkey\s+/list|vaultcmd\s+/list)")
     | eval detection="Credential Manager Enum"]
| table _time, host, user, Image, TargetFilename, CommandLine, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "process" AS "Process", "filename" AS "Accessed File",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - File created'
    AND ("filename" LIKE '%Chrome%Login Data%'
        OR "filename" LIKE '%Edge%Login Data%'
        OR "filename" LIKE '%Firefox%key4.db%')
    AND "process" NOT IN ('chrome.exe','msedge.exe','firefox.exe','browser_broker.exe')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Assume all browser-stored passwords are compromised — initiate password rotation
2. Check Credential Manager for stored RDP/network credentials
3. Notify users to change all saved browser passwords
4. Force sign-out of all active sessions for the affected user
5. Consider deploying an enterprise password manager to eliminate browser-stored credentials
