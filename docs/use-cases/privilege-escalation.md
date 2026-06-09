# Privilege Escalation

Use cases for detecting attacker attempts to gain higher privileges.

**Rule packs:** `windows_sysmon`, `credential_access`

---

## UC-071 — UAC Bypass {#uc-071}

**Threat:** Attacker bypasses User Account Control (UAC) to elevate from standard admin to
full high-integrity process without prompting the user. Common methods: fodhelper, eventvwr,
ComputerDefaults, DiskCleanup, sdclt.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 88 |
| **MITRE** | T1548.002 — Abuse Elevation Control Mechanism: Bypass User Account Control |
| **Data Sources** | Sysmon Event 1, Windows Security 4688 |
| **Rule IDs** | SP-privesc-001 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where
    (match(ParentImage,"(?i)(fodhelper|eventvwr|computerdefaults|sdclt|diskcleanup|wsreset|dccw|cmstp)\.exe")
     AND match(Image,"(?i)(cmd|powershell|pwsh|wscript|cscript|mshta)\.exe"))
    OR (match(CommandLine,"(?i)(fodhelper|eventvwr|sdclt|computerdefaults)")
        AND match(CommandLine,"(?i)(reg\s+(add|query)|HKCU.*Classes.*shell|HKCU.*Classes.*mscfile)"))
| table _time, host, user, Image, ParentImage, CommandLine
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "process" AS "Spawned Process", "ParentProcessName" AS "UAC Bypass Parent",
    "Command" AS "CommandLine", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND LOWER("ParentProcessName") IN ('fodhelper.exe','eventvwr.exe','computerdefaults.exe',
        'sdclt.exe','diskcleanup.exe','wsreset.exe','cmstp.exe')
    AND LOWER("process") IN ('cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Check the registry keys used by the bypass method (HKCU\Software\Classes\...)
2. Determine what command was executed post-elevation
3. Enable Mandatory Integrity Control (MIC) auditing
4. Deploy UACME-based detection: monitor for unexpected high-integrity process creation
5. Set `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin = 2`
   to enable UAC for all admin operations

---

## UC-072 — Token Impersonation (SeImpersonatePrivilege) {#uc-072}

**Threat:** Attacker abuses SeImpersonatePrivilege (held by service accounts) to impersonate
higher-privileged tokens. Exploited by JuicyPotato, PrintSpoofer, RoguePotato.
Common when MSSQL, IIS service accounts are compromised.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 85 |
| **MITRE** | T1134.001 — Access Token Manipulation: Token Impersonation/Theft |
| **Data Sources** | Windows Security 4688/4624, Sysmon 1 |
| **Rule IDs** | SP-privesc-002 |

### Splunk SPL

```spl
| union
    [search index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
     | where match(CommandLine,"(?i)(juicypotato|printspoofer|roguepotato|sweetpotato|hotpotato|lonelypotato)")
     | eval detection="Known Potato Tool"]
    [search index=windows EventCode=4624
     | where LogonType=3 AND ImpersonationLevel="%%1833"
         AND NOT match(SubjectUserName,"(?i)(SYSTEM|\$$)")
     | eval detection="Delegation Logon (Impersonation)"]
| table _time, host, user, CommandLine, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "Command" AS "CommandLine", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND (LOWER("Command") LIKE '%juicypotato%'
        OR LOWER("Command") LIKE '%printspoofer%'
        OR LOWER("Command") LIKE '%roguepotato%'
        OR LOWER("Command") LIKE '%sweetpotato%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Immediate critical — service accounts should not be spawning admin shells
2. Identify the service account that was compromised (mssql service account, IIS AppPool, etc.)
3. Reset the service account password and review its permission scope
4. Remove SeImpersonatePrivilege from service accounts if not required
5. Patch for the Print Spooler vulnerability (MS-RPRN abuse) if PrintSpoofer was used

---

## UC-073 — Kernel Exploit Indicators {#uc-073}

**Threat:** Attacker exploits a local privilege escalation vulnerability in the Windows kernel
or a driver. Signs: unsigned driver load, crash dumps, privilege changes right after unusual
process execution.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 75 |
| **MITRE** | T1068 — Exploitation for Privilege Escalation |
| **Data Sources** | Sysmon Event 6 (DriverLoad), Windows Security 4688 |
| **Rule IDs** | SP-privesc-003 |

### Splunk SPL

```spl
| union
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=6
     | where Signed="false"
         AND NOT match(ImageLoaded,"(?i)(C:\\Windows\\System32|C:\\Windows\\SysWOW64)")
     | eval detection="Unsigned Driver Loaded"]
    [search index=windows EventCode=4688
     | where match(NewProcessName,"(?i)(cmd|powershell)") AND IntegrityLevel="High"
         AND match(ParentProcessName,"(?i)(svchost|services|dllhost|conhost)")
     | eval detection="Unexpected High-Integrity Child"]
| table _time, host, user, ImageLoaded, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", "ImageLoaded" AS "Driver",
    "Signed" AS "Signed", "SignatureStatus" AS "Sig Status",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Driver loaded'
    AND "Signed" = 'false'
    AND "ImageLoaded" NOT LIKE 'C:\\Windows\\System32%'
    AND "ImageLoaded" NOT LIKE 'C:\\Windows\\SysWOW64%'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Isolate the host immediately — kernel exploits imply full system compromise
2. Extract the unsigned driver for analysis — check hash against known CVE exploits
3. Check Windows Update status — is the system patched for recent LPE CVEs?
4. Enable Windows Hypervisor-Protected Code Integrity (HVCI) to block unsigned drivers
5. Review crash dumps in C:\Windows\Minidump for exploit indicators

---

## UC-074 — Always Install Elevated Abuse {#uc-074}

**Threat:** If `AlwaysInstallElevated` registry policy is enabled, any user can install
MSI packages with SYSTEM privileges. Attackers create a malicious MSI to escalate to SYSTEM.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 88 |
| **MITRE** | T1548.002 — Abuse Elevation Control Mechanism |
| **Data Sources** | Sysmon 13 (Registry), Windows Security 4688 |
| **Rule IDs** | SP-privesc-004 |

### Splunk SPL

```spl
| union
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
     | where match(TargetObject,"(?i)(HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer.*AlwaysInstallElevated|HKCU\\SOFTWARE\\Policies.*AlwaysInstallElevated)")
         AND Details="DWORD (0x00000001)"
     | eval detection="AlwaysInstallElevated Registry Set"]
    [search index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
     | where match(CommandLine,"(?i)msiexec.*\/i.*\.msi") AND IntegrityLevel="High"
         AND NOT match(ParentImage,"(?i)(msiexec|PSEXESVC|explorer)")
     | eval detection="MSI Executed with Elevation"]
| table _time, host, user, TargetObject, CommandLine, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", "TargetObject" AS "Registry Key",
    "Details" AS "Value", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Registry value set'
    AND LOWER("TargetObject") LIKE '%alwaysinstallelevated%'
    AND "Details" = 'DWORD (0x00000001)'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Disable AlwaysInstallElevated immediately via GPO:
   - HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 0
   - HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 0
2. Scan for malicious MSI files recently created on the system
3. Review MSI execution history in Windows Installer event log (Event 1033/1034)
4. This is a misconfiguration — check other systems in the same OU for the same policy

---

## UC-075 — Sudo Abuse on Linux {#uc-075}

**Threat:** Attacker abuses overly permissive sudo rules (NOPASSWD, unrestricted commands)
to escalate to root. Common misconfiguration: `user ALL=(ALL) NOPASSWD: ALL`.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 82 |
| **MITRE** | T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching |
| **Data Sources** | Linux auditd, /var/log/auth.log, /var/log/sudo.log |
| **Rule IDs** | SP-privesc-005 |

### Splunk SPL

```spl
index=linux sourcetype IN ("linux_secure","linux_audit","syslog")
| where match(_raw,"(?i)(sudo.*COMMAND.*|pam_unix.*sudo.*authentication failure)")
| rex field=_raw "USER=(?P<sudo_user>[^\s]+)\s+COMMAND=(?P<sudo_cmd>[^\n]+)"
| where match(sudo_cmd,"(?i)(bash|sh|python|perl|ruby|vi|vim|awk|nmap|nc\s|-c\s+|/bin/bash|/bin/sh)")
| table _time, host, sudo_user, sudo_cmd
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "Command" AS "Sudo Command", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Linux OS'
    AND LOWER("Message") LIKE '%sudo%command%'
    AND (LOWER("Command") LIKE '%/bin/bash%'
        OR LOWER("Command") LIKE '%/bin/sh%'
        OR LOWER("Command") LIKE '%python%'
        OR LOWER("Command") LIKE '%perl%')
    AND username NOT IN ('root','ansible','puppet')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Run `sudo -l -U <user>` to see what sudo rules apply to the account
2. Check `/etc/sudoers` and `/etc/sudoers.d/` for NOPASSWD entries
3. Remove NOPASSWD from any rule that allows unrestricted shell access
4. Enable sudo log to dedicated syslog server for tamper-resistance
5. Consider `requiretty` in sudoers to prevent non-interactive sudo abuse

---

## UC-076 — Shadow Credentials (Windows) {#uc-076}

**Threat:** Attacker with WriteMSDS-KeyCredentialLink permissions adds a KeyCredential
to a computer or user object, enabling PKINIT authentication as that target. This creates
persistent privileged access without changing passwords.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 90 |
| **MITRE** | T1556.006 — Modify Authentication Process |
| **Data Sources** | Windows Security 4662 (DC), Sysmon 1 |
| **Rule IDs** | SP-privesc-006 |

### Splunk SPL

```spl
index=windows EventCode=5136
| where AttributeLDAPDisplayName="msDS-KeyCredentialLink"
    AND OperationType="%%14674"
    AND NOT match(SubjectUserName,"(?i)(AZUREADSSOACC|\$$)")
| table _time, host, SubjectUserName, ObjectDN, AttributeLDAPDisplayName, AttributeValue
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "Attacker",
    "ObjectDN" AS "Target Object", "AttributeName" AS "Attribute",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID = '5136'
    AND "AttributeName" = 'msDS-KeyCredentialLink'
    AND username NOT LIKE '%$' AND username NOT IN ('AZUREADSSOACC')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. **Immediate escalation** — Shadow Credentials enable full account takeover
2. Remove the unauthorized KeyCredential:
   `Set-ADComputer -Identity <target> -Clear msDS-KeyCredentialLink`
3. Identify the account that wrote the credential — was it compromised?
4. Check for authentication attempts using the shadow credential (PKINIT events 4768)
5. Audit WriteMSDS-KeyCredentialLink permissions across all AD objects

---

## UC-077 — DLL Search Order Hijacking {#uc-077}

**Threat:** Attacker places a malicious DLL in a directory earlier in the search path
than the legitimate DLL location. When a privileged process loads the DLL, the
malicious code executes with elevated privileges.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 73 |
| **MITRE** | T1574.001 — Hijack Execution Flow: DLL Search Order Hijacking |
| **Data Sources** | Sysmon Event 7 (ImageLoad) |
| **Rule IDs** | SP-privesc-007 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7
| where Signed="false"
    AND match(Image,"(?i)(C:\\Windows\\System32|C:\\Program Files).*\.(exe)")
    AND match(ImageLoaded,"(?i)(C:\\Users\\|C:\\Temp\\|C:\\ProgramData\\)")
| table _time, host, user, Image, ImageLoaded, Signed, Hashes
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", "Image" AS "Loading Process",
    "ImageLoaded" AS "Suspicious DLL",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Image loaded'
    AND "Signed" = 'false'
    AND ("ImageLoaded" LIKE 'C:\\Users\\%'
        OR "ImageLoaded" LIKE 'C:\\ProgramData\\%')
    AND ("Image" LIKE 'C:\\Windows\\System32\\%'
        OR "Image" LIKE 'C:\\Program Files\\%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Examine the DLL — is it present in the expected system path? Hash comparison?
2. Check the directory permissions — can standard users write there?
3. Identify if the loading process runs as a privileged account
4. Enable SafeDllSearchMode via Group Policy to reduce search path exposure
5. Monitor directory write events (Sysmon 11) in sensitive locations

---

## UC-078 — ACL-Based Privilege Escalation (AD Object) {#uc-078}

**Threat:** Attacker exploits misconfigured AD permissions (GenericAll, WriteDACL, AddMember)
on a domain object to escalate privileges — e.g., adding themselves to Domain Admins,
resetting a privileged account's password, or granting DCSync rights.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 90 |
| **MITRE** | T1098 — Account Manipulation |
| **Data Sources** | Windows Security 4728/4732/4756/4738/5136 (DC) |
| **Rule IDs** | SP-privesc-008 |

### Splunk SPL

```spl
| union
    [search index=windows EventCode IN (4728, 4732, 4756)
     | where match(GroupName,"(?i)(Domain Admins|Enterprise Admins|Schema Admins|Backup Operators)")
         AND NOT match(SubjectUserName,"(?i)(\$$|admin_auto|sccm)")
     | eval detection="Added to Privileged Group"]
    [search index=windows EventCode=4738
     | where AccountExpires="" OR PasswordLastSet!=""
         AND NOT match(SubjectUserName,"(?i)(\$$|admin)")
     | eval detection="User Account Modified (Password Reset?)"]
| table _time, host, SubjectUserName, TargetUserName, GroupName, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "Actor",
    "TargetAccount" AS "Target", "GroupName" AS "Group",
    QIDNAME(qid) AS "Event", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID IN ('4728','4732','4756')
    AND ("GroupName" LIKE '%Domain Admins%' OR "GroupName" LIKE '%Enterprise Admins%'
        OR "GroupName" LIKE '%Backup Operators%')
    AND username NOT LIKE '%$'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. **Immediate critical** — privileged group membership changes require instant review
2. Remove unauthorized member: `Remove-ADGroupMember -Identity "Domain Admins" -Members <user>`
3. Review the account that made the change — is it authorized?
4. Check Group Policy Restricted Groups to enforce protected group membership
5. Enable Protected Users security group for all privileged accounts
