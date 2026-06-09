# Lateral Movement — Extended

Extended lateral movement detection beyond UC-012–016.

**Rule packs:** `lateral_movement`, `windows_sysmon`

---

## UC-143 — DCOM Lateral Movement {#uc-143}

**Threat:** Attacker uses DCOM (Distributed COM) objects (MMC, ShellWindows,
Excel.Application) to execute code on remote systems without deploying new services
or tools — making it harder to detect.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 80 |
| **MITRE** | T1021.003 — Remote Services: Distributed Component Object Model |
| **Data Sources** | Sysmon Event 1/3, Windows Security 4688 |
| **Rule IDs** | SP-lateral-001 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(ParentImage,"(?i)(svchost\.exe|dllhost\.exe)") 
    AND match(CommandLine,"(?i)(cmd|powershell|wscript|cscript|mshta)")
    AND match(ParentCommandLine,"(?i)(-k\s+DcomLaunch|-k\s+netsvcs)")
    AND NOT match(CommandLine,"(?i)(update|telemetry|diagnostics)")
| table _time, host, user, Image, ParentImage, CommandLine
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "process" AS "Spawned", "ParentProcessName" AS "Parent (DCOM)",
    "Command" AS "CommandLine", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND "ParentProcessName" IN ('svchost.exe','dllhost.exe')
    AND LOWER("process") IN ('cmd.exe','powershell.exe','wscript.exe','mshta.exe')
    AND LOWER("ParentCommandLine") LIKE '%-k dcomlaunch%'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Identify the source host and account used for the DCOM connection (Event 4624)
2. Review what was executed via DCOM on the target
3. Disable DCOM objects not required for business use via DCOMCNFG
4. Monitor Windows Firewall for unexpected DCE/RPC connections (port 135 + dynamic)
5. Correlate with prior credential theft or lateral movement from the same source host

---

## UC-144 — Remote Registry Access {#uc-144}

**Threat:** Attacker remotely accesses a host's registry to modify run keys, steal
configuration data, or collect credentials. Requires admin rights on the target.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 70 |
| **MITRE** | T1112 — Modify Registry |
| **Data Sources** | Windows Security 4663/5145 |
| **Rule IDs** | SP-lateral-002 |

### Splunk SPL

```spl
index=windows EventCode=5145
| where match(ShareName,"(?i)(WINREG|IPC\$)")
    AND match(RelativeTargetName,"(?i)(WINREG|registry|\\\\pipe\\winreg)")
    AND NOT match(SubjectUserName,"(?i)(SYSTEM|\$$)")
| table _time, host, SubjectUserName, IpAddress, ShareName, RelativeTargetName, AccessMask
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Source Host", destinationip AS "Target", username AS "User",
    "ShareName" AS "Accessed Share", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID = '5145'
    AND "ShareName" IN ('WINREG','IPC$')
    AND LOWER("RelativeTargetName") LIKE '%winreg%'
    AND username NOT LIKE '%$' AND username != 'SYSTEM'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Disable Remote Registry service on workstations: `sc config RemoteRegistry start= disabled`
2. Identify which registry keys were accessed
3. Check if any Run keys or startup entries were modified via the remote connection
4. Correlate with other lateral movement from the same source host
5. Enforce firewall rules to block port 135 + dynamic RPC between workstations

---

## UC-145 — PrintNightmare / Print Spooler Exploit {#uc-145}

**Threat:** CVE-2021-1675/CVE-2021-34527 — attackers load a malicious DLL via the
Print Spooler service using `AddPrinterDriverEx()` to execute code as SYSTEM.
Even patched systems may be vulnerable to certain variants.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 85 |
| **MITRE** | T1068 — Exploitation for Privilege Escalation |
| **Data Sources** | Sysmon Event 1/7, Windows System 316 |
| **Rule IDs** | SP-lateral-003 |

### Splunk SPL

```spl
| union
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7
     | where match(Image,"(?i)spoolsv\.exe") AND Signed="false"
     | eval detection="Spoolsv Loaded Unsigned DLL"]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
     | where match(ParentImage,"(?i)spoolsv\.exe")
         AND match(Image,"(?i)(cmd|powershell|rundll32|regsvr32)\.exe")
     | eval detection="Spoolsv Spawned Shell"]
    [search index=windows EventCode=316
     | where match(Message,"(?i)(AddPrinterDriverEx|print.*driver.*failed)")
     | eval detection="Print Driver Add Failure"]
| table _time, host, user, detection, Image, ParentImage, CommandLine
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "process" AS "Spawned", "ParentProcessName" AS "Parent",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND "ParentProcessName" = 'spoolsv.exe'
    AND LOWER("process") IN ('cmd.exe','powershell.exe','rundll32.exe','regsvr32.exe')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Disable Print Spooler on DCs and hosts that don't need printing: `Stop-Service Spooler`
2. Apply MS patch KB5004945 or later if not already applied
3. Block Print Spooler from accepting remote connections via Group Policy
4. If exploitation detected: isolate host, forensic memory dump of spoolsv.exe
5. Check for lateral movement from compromised host to DCs using the SYSTEM token

---

## UC-146 — Token Impersonation for Lateral Movement {#uc-146}

**Threat:** After local privilege escalation, attacker impersonates a domain admin's
cached token to authenticate to other systems as that user, pivoting across the network.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 82 |
| **MITRE** | T1134.001 — Access Token Manipulation: Token Impersonation/Theft |
| **Data Sources** | Windows Security 4624 (EventType 9 = NewCredentials) |
| **Rule IDs** | SP-lateral-004 |

### Splunk SPL

```spl
index=windows EventCode=4624
| where LogonType=9 AND ImpersonationLevel="%%1833"
    AND NOT match(SubjectUserName,"(?i)(SYSTEM|\$$|ServiceAccount)")
    AND NOT match(TargetUserName,"(?i)(\$$|DWM-|UMFD-)")
| stats count by SubjectUserName, TargetUserName, WorkstationName, IpAddress, _time
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Impersonating", "TargetAccount" AS "Target Identity",
    sourceip AS "Source Host", destinationip AS "Target Host",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID = '4624'
    AND "LogonType" = '9'
    AND "ImpersonationLevel" = 'Impersonation'
    AND username NOT IN ('SYSTEM') AND username NOT LIKE '%$'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Logon Type 9 with impersonation from a non-service account is unusual — investigate
2. Check if the TargetUserName holds admin privileges
3. Check what subsequent actions were taken using the impersonated identity
4. Rotate credentials for the impersonated account
5. Enable Credential Guard to protect domain credentials from token theft

---

## UC-147 — SMB Enumeration / Spray from Internal Host {#uc-147}

**Threat:** Compromised host scans the network for SMB (445) to identify vulnerable
shares, attempt lateral movement, or spray credentials. High connection volume to
diverse hosts on port 445.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 83 |
| **MITRE** | T1046 — Network Service Discovery |
| **Data Sources** | Sysmon Event 3, Firewall logs |
| **Rule IDs** | SP-lateral-005 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| where DestinationPort=445 AND Initiated="true"
| bucket _time span=5m
| stats dc(DestinationIp) as UniqueHosts, count by SourceIp, host, Image, _time
| where UniqueHosts >= 10
| sort -UniqueHosts
```

### QRadar AQL

```sql
SELECT sourceip AS "Scanner", COUNT(DISTINCT destinationip) AS "Hosts Scanned",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Window"
FROM events WHERE destinationport = 445
    AND sourceip LIKE '10.%'
GROUP BY sourceip, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(DISTINCT destinationip) >= 10
LAST 1 HOURS ORDER BY "Hosts Scanned" DESC
```

### Response Actions
1. Isolate the scanning host — this indicates active post-exploitation
2. Check what credentials were used in the subsequent SMB authentications
3. Block SMB between workstations at the firewall (server block)
4. Enable SMB signing to prevent relay attacks
5. Correlate with Kerberoasting or credential theft from the same host

---

## UC-148 — Pass-the-Hash via Overpass-the-Hash {#uc-148}

**Threat:** Attacker uses a stolen NTLM hash to request a Kerberos TGT (Overpass-the-Hash
via Mimikatz's `sekurlsa::pth`), enabling full network access without knowing the
cleartext password.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 82 |
| **MITRE** | T1550.002 — Use Alternate Authentication Material: Pass the Hash |
| **Data Sources** | Windows Security 4768/4769, Sysmon 1 |
| **Rule IDs** | SP-lateral-006 |

### Splunk SPL

```spl
| union
    [search index=windows EventCode=4768
     | where EncryptionType="0x17" AND NOT match(TargetUserName,"(?i)(\$$|krbtgt)")
     | eval detection="RC4 TGT Request (Overpass-the-Hash indicator)"]
    [search index=windows EventCode=4624
     | where LogonType=9 AND match(AuthenticationPackageName,"NTLM")
         AND NOT match(WorkstationName,"(?i)(localhost|127\.0\.0\.1)")
     | eval detection="NTLM Network Logon Type 9"]
| table _time, host, TargetUserName, SubjectUserName, EncryptionType, WorkstationName, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Target Account", sourceip AS "Source",
    "EncryptionType" AS "Ticket Encryption",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID = '4768'
    AND "EncryptionType" = '0x17'
    AND username NOT LIKE '%$' AND username NOT IN ('krbtgt')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Identify the DC that issued the RC4-encrypted TGT and the requester
2. Reset the compromised account's password immediately
3. Enforce AES encryption for Kerberos: disable RC4 (ArcFour) in domain GPO
4. Deploy Credential Guard to protect NTLM hashes from extraction
5. Enable Protected Users security group for privileged accounts — prevents NTLM auth
