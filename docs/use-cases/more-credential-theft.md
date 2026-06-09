# Credential Theft — Extended

Extended credential theft detection beyond UC-006–011.

**Rule packs:** `credential_access`

---

## UC-149 — AS-REP Roasting {#uc-149}

**Threat:** Attacker requests Kerberos AS-REP for accounts that don't require pre-authentication
(`DONT_REQ_PREAUTH` flag). The response is encrypted with the account's password hash,
which can be cracked offline. Detectable via Event 4768 with no pre-authentication.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 82 |
| **MITRE** | T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting |
| **Data Sources** | Windows Security 4768 (DC) |
| **Rule IDs** | SP-cred-001 |

### Splunk SPL

```spl
index=windows EventCode=4768
| where PreAuthType="0"
    AND NOT match(TargetUserName,"(?i)(\$$|krbtgt|ANONYMOUS)")
    AND EncryptionType="0x17"
| bucket _time span=5m
| stats count, values(TargetUserName) as Accounts, dc(TargetUserName) as AccountCount by IpAddress, _time
| where AccountCount >= 3
| sort -AccountCount
```

### QRadar AQL

```sql
SELECT sourceip AS "Attacker IP", COUNT(DISTINCT username) AS "Accounts Targeted",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Window"
FROM events WHERE EventID = '4768'
    AND "PreAuthType" = '0' AND "EncryptionType" = '0x17'
    AND username NOT LIKE '%$' AND username NOT IN ('krbtgt','ANONYMOUS LOGON')
GROUP BY sourceip, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(DISTINCT username) >= 3
LAST 1 HOURS ORDER BY "Accounts Targeted" DESC
```

### Response Actions
1. Identify all accounts with `DONT_REQ_PREAUTH` set: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`
2. Remove the `DONT_REQ_PREAUTH` flag from all accounts unless strictly required
3. Force password resets on affected accounts — assume hashes are compromised
4. Enable AES encryption for all AS-REP: enforce pre-authentication requirement
5. Consider deploying honeypot accounts with this flag to detect future roasting

---

## UC-150 — Golden Ticket Attack {#uc-150}

**Threat:** Attacker who has obtained the KRBTGT hash creates a forged Kerberos TGT
(Golden Ticket) granting access to any service for any account for up to 10 years.
Indicators: anomalous TGT lifetime, unusual account usage patterns, rc4 encryption.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 78 |
| **MITRE** | T1558.001 — Steal or Forge Kerberos Tickets: Golden Ticket |
| **Data Sources** | Windows Security 4624/4769 (DC) |
| **Rule IDs** | SP-cred-002 |

### Splunk SPL

```spl
index=windows EventCode=4769
| where EncryptionType="0x17"
    AND NOT match(AccountName,"(?i)(\$$|krbtgt|ANONYMOUS)")
    AND TicketEncryptionType="0x17"
| join AccountName
    [search index=windows EventCode=4768
     | eval TGTTime=_time
     | table AccountName, TGTTime]
| eval TGSDelay=_time - TGTTime
| where TGSDelay < 0 OR TGSDelay > 3600
| table _time, host, AccountName, ServiceName, EncryptionType, TGSDelay
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Account", "ServiceName" AS "Service",
    "TicketEncryption" AS "Encryption",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID = '4769'
    AND "TicketEncryption" = '0x17'
    AND username NOT LIKE '%$' AND username NOT IN ('krbtgt')
    AND NOT EXISTS (
        SELECT 1 FROM events WHERE EventID = '4768'
            AND username = username AND starttime > NOW()-3600000
        LAST 1 HOURS
    )
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. **Double-reset krbtgt password** (twice, 24 hours apart) to invalidate all forged tickets
2. Identify how the krbtgt hash was obtained (DCSync, NTDS.dit dump)
3. Force logoff all active sessions across the domain
4. Golden ticket invalidation is complex — consult Microsoft DART guidance
5. Review all service tickets issued for admin accounts in the 24h before detection

---

## UC-151 — DPAPI Secret Extraction {#uc-151}

**Threat:** Attacker uses DPAPI (Windows Data Protection API) to decrypt secrets
protected by user/machine keys — including Chrome browser credentials, Windows Credential
Manager entries, and RDP connection passwords.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 80 |
| **MITRE** | T1555.004 — Credentials from Password Stores: Windows Credential Manager |
| **Data Sources** | Sysmon Event 1, Windows Security 4688 |
| **Rule IDs** | SP-cred-003 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where match(CommandLine,"(?i)(dpapi|CryptUnprotectData|Invoke-Mimikatz.*dpapi|SharpDPAPI|DPAPISniff|Get-VaultCredential)")
    OR (match(Image,"(?i)(powershell|pwsh)") AND match(CommandLine,"(?i)(Microsoft\.Win32\.Cryptography|System\.Security\.Cryptography\.ProtectedData|ProtectedData\.Unprotect)"))
| table _time, host, user, Image, CommandLine
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "Command" AS "CommandLine", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND (LOWER("Command") LIKE '%dpapi%'
        OR LOWER("Command") LIKE '%sharpdpapi%'
        OR LOWER("Command") LIKE '%cryptunprotectdata%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Assume all DPAPI-protected credentials are compromised
2. This includes Chrome/Edge passwords, WiFi credentials, Windows credentials
3. Rotate all credentials accessible from the host
4. Check Chrome Login Data file for last-access timestamp
5. Consider deploying enterprise password manager to eliminate browser-saved credentials

---

## UC-152 — Password Spraying — Active Directory {#uc-152}

**Threat:** Attacker tries a single password (or small set of passwords) against many
accounts to avoid triggering per-account lockout policies.
Indicator: one source IP with many 4771 failures against different accounts.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 85 |
| **MITRE** | T1110.003 — Brute Force: Password Spraying |
| **Data Sources** | Windows Security 4771 (DC), 4625 |
| **Rule IDs** | SP-cred-004 |

### Splunk SPL

```spl
index=windows EventCode IN (4771, 4625)
| where match(FailureCode,"(?i)(0x18|0x69|0xC000006A|0xC000006D)")
    AND NOT match(ClientAddress,"(?i)(127\.0\.0\.1|::1)")
| bucket _time span=10m
| stats dc(TargetUserName) as UniqueAccounts, count by ClientAddress, host, _time
| where UniqueAccounts >= 10
| sort -UniqueAccounts
```

### QRadar AQL

```sql
SELECT sourceip AS "Spraying Source", COUNT(DISTINCT username) AS "Accounts Targeted",
    COUNT(*) AS "Total Failures", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Window"
FROM events WHERE EventID IN ('4771','4625')
    AND "FailureCode" IN ('0x18','0x69')
    AND sourceip NOT IN ('127.0.0.1','::1')
GROUP BY sourceip, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(DISTINCT username) >= 10
LAST 1 HOURS ORDER BY "Accounts Targeted" DESC
```

### Response Actions
1. Block the source IP immediately — password spraying precedes full compromise
2. Check if any accounts were successfully authenticated by the spray source
3. Identify accounts that were targeted — force password resets for any that were sprayed
4. Enable Smart Lockout with increasing lockout thresholds
5. Consider deploying Microsoft Entra ID Password Protection to block common passwords

---

## UC-153 — Credential Stuffing Attack {#uc-153}

**Threat:** Attacker uses a list of username/password pairs from a previous data breach
to try to authenticate to your systems. Different from password spraying — each account
gets a unique (breached) password attempt.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 80 |
| **MITRE** | T1110.004 — Brute Force: Credential Stuffing |
| **Data Sources** | Windows Security 4625, VPN logs, Web app logs |
| **Rule IDs** | SP-cred-005 |

### Splunk SPL

```spl
index=windows OR index=vpn OR index=webapp
| where match(_raw,"(?i)(failed.*auth|authentication.*fail|login.*failed|invalid.*credentials)")
| bucket _time span=10m
| stats count, dc(user) as UniqueUsers, dc(src_ip) as SourceIPs by dest_host, _time
| where UniqueUsers >= 20 AND count >= 50
| sort -count
```

### QRadar AQL

```sql
SELECT destinationip AS "Target System", sourceip AS "Source",
    COUNT(DISTINCT username) AS "Unique Accounts", COUNT(*) AS "Total Attempts",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Window"
FROM events WHERE QIDNAME(qid) LIKE '%Authentication Failed%'
GROUP BY destinationip, sourceip, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(DISTINCT username) >= 20 AND COUNT(*) >= 50
LAST 1 HOURS ORDER BY "Total Attempts" DESC
```

### Response Actions
1. Enable Entra ID / AD Identity Protection for breach credential detection
2. Correlate with known breach data — enable HaveIBeenPwned enterprise API
3. Check for any successful authentications from the source IPs
4. Enforce MFA as the primary defense — credential stuffing cannot bypass MFA
5. Deploy CAPTCHA on web-facing login pages to slow automated attempts

---

## UC-154 — Windows Vault / Credential Manager Dump {#uc-154}

**Threat:** Attacker uses `cmdkey /list`, `vaultcmd`, or PowerShell to enumerate and
extract credentials stored in Windows Credential Manager (network passwords, RDP
saved passwords, generic credentials).

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 78 |
| **MITRE** | T1555.004 — Credentials from Password Stores: Windows Credential Manager |
| **Data Sources** | Sysmon Event 1, Windows Security 4688 |
| **Rule IDs** | SP-cred-006 |

### Splunk SPL

```spl
index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where match(CommandLine,"(?i)(cmdkey\s+/list|vaultcmd\s+/listcreds|vaultcmd\s+/listschemas|Get-StoredCredential|CredEnumerateW|[Cc]redential[Mm]anager)")
| table _time, host, user, Image, CommandLine
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "Command" AS "CommandLine", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Process creation'
    AND (LOWER("Command") LIKE '%cmdkey /list%'
        OR LOWER("Command") LIKE '%vaultcmd%'
        OR LOWER("Command") LIKE '%get-storedcredential%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Assume all Credential Manager entries are compromised
2. This includes RDP saved passwords, network drive credentials, application passwords
3. Delete all stored credentials: `cmdkey /delete:<target>` for each entry
4. Recommend users do not store passwords in Windows Credential Manager
5. Correlate with subsequent RDP or SMB access using the harvested credentials

---

## UC-155 — Silver Ticket Attack {#uc-155}

**Threat:** Attacker who has extracted a service account's password hash creates a forged
Kerberos service ticket (Silver Ticket). Unlike Golden Ticket, it doesn't require the DC
and is specific to one service — harder to detect.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 72 |
| **MITRE** | T1558.002 — Steal or Forge Kerberos Tickets: Silver Ticket |
| **Data Sources** | Windows Security 4769 |
| **Rule IDs** | SP-cred-007 |

### Splunk SPL

```spl
index=windows EventCode=4769
| where EncryptionType="0x17"
    AND TicketOptions="0x40810010"
    AND NOT match(AccountName,"(?i)(\$$|ANONYMOUS|IUSR)")
| table _time, host, AccountName, ServiceName, ClientAddress, TicketOptions, EncryptionType
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Account", "ServiceName" AS "Target Service",
    sourceip AS "Source", "EncryptionType" AS "Encryption",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID = '4769'
    AND "EncryptionType" = '0x17'
    AND username NOT LIKE '%$' AND username NOT IN ('ANONYMOUS LOGON')
    AND NOT EXISTS (
        SELECT 1 FROM events WHERE EventID = '4768'
            AND username = username AND starttime > NOW()-600000
        LAST 10 MINUTES
    )
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Identify which service was targeted (MSSQL, IIS, CIFS, etc.)
2. Reset the targeted service account's password and re-register the SPN
3. Enable AES encryption for all service accounts: `Set-ADUser -KerberosEncryptionType AES256`
4. Remove RC4 (DES/RC4) encryption types from all service accounts
5. Enable the `Validate KDC PAC Signature` setting to increase Silver Ticket detection

