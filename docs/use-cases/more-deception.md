# Deception & Canary — Extended

Extended deception detection beyond UC-046. Honey tokens, canary accounts,
DNS honeypots, and honeypot infrastructure.

**Rule packs:** `deception`, `correlation`

---

## UC-188 — Honey Credential Used (Windows Authentication) {#uc-188}

**Threat:** A decoy credential (honey account) planted in LSASS memory or
a fake password list is used to authenticate — proves LSASS was dumped and
credentials extracted. Zero false positives — these accounts are never used legitimately.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 99 |
| **MITRE** | T1003 — OS Credential Dumping |
| **Data Sources** | Windows Security 4776/4768/4769 (DC) |
| **Rule IDs** | SP-deception-003 |

### Splunk SPL

```spl
| inputlookup honey_accounts.csv as honey
| join type=inner TargetUserName
    [search index=windows EventCode IN (4768, 4769, 4776, 4624, 4625)
     | table _time, TargetUserName, IpAddress, LogonType, host]
| eval alert="HONEY CREDENTIAL USED"
| table _time, TargetUserName, IpAddress, host, LogonType, alert
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Honey Account Used", sourceip AS "Source IP",
    QIDNAME(qid) AS "Auth Event", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID IN ('4768','4769','4776','4624','4625')
    AND username IN (
        SELECT DISTINCT "AccountName" FROM reference_sets WHERE name='Honey-Account-List'
    )
LAST 24 HOURS ORDER BY starttime DESC
```

### Deployment Guide

Create honey accounts via PowerShell:
```powershell
New-ADUser -Name "svc_backup01" -SamAccountName "svc_backup01" `
    -PasswordNeverExpires $false -Enabled $true `
    -Description "HONEY-DO-NOT-USE" `
    -Path "OU=ServiceAccounts,DC=yourdomain,DC=com"
Set-ADUser -Identity "svc_backup01" -PasswordNotRequired $false
```

Log account name in `honey_accounts.csv`. Account should never be used — any auth event is confirmed LSASS dump.

### Response Actions
1. **Confirmed LSASS dump** — attacker has credential for this account (and likely others)
2. Identify the source IP — trace back to compromised host
3. Rotate ALL domain credentials immediately — this is not isolated
4. Check LSASS protection status: `(Get-ProcessMitigation -Name lsass.exe).ProcessImageLoadProtection`
5. Enable Credential Guard to prevent future LSASS credential extraction

---

## UC-189 — Canary AWS Access Key Used {#uc-189}

**Threat:** A decoy AWS access key deliberately planted in source code, configuration
files, or documentation is used in an API call — proves an attacker found and is
actively exploiting a credential from your environment.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 99 |
| **MITRE** | T1552.001 — Unsecured Credentials: Credentials in Files |
| **Data Sources** | AWS CloudTrail |
| **Rule IDs** | SP-deception-004 |

### Splunk SPL

```spl
| inputlookup canary_aws_keys.csv as canary
| join type=inner accessKeyId
    [search index=aws sourcetype="aws:cloudtrail"
     | table _time, userIdentity.accessKeyId, sourceIPAddress, eventName, awsRegion]
| eval alert="CANARY AWS KEY USED"
| table _time, accessKeyId, sourceIPAddress, eventName, awsRegion, alert
| sort -_time
```

### QRadar AQL

```sql
SELECT "accessKeyId" AS "Canary Key", sourceip AS "Attacker IP",
    "eventName" AS "API Called", "awsRegion" AS "Region",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Amazon AWS CloudTrail'
    AND "accessKeyId" IN (
        SELECT DISTINCT "KeyId" FROM reference_sets WHERE name='Canary-AWS-Keys'
    )
LAST 24 HOURS ORDER BY starttime DESC
```

### Deployment Guide

Create canary IAM user with no real permissions and get the access key:
```bash
aws iam create-user --user-name canary-detector-01
aws iam create-access-key --user-name canary-detector-01
# Store key ID in reference set / lookup table
# Plant the key in various locations: README.md, .env.example, config samples
# All API calls will fail (no permissions) but CloudTrail still records them
```

### Response Actions
1. **Confirmed credential theft** — attacker found a file/code containing AWS credentials
2. Identify the source IP of the API call — likely attacker infrastructure
3. Find where the canary key was planted — that location is where the theft occurred
4. Audit the repository/location for other real secrets that may have been found simultaneously
5. Rotate all AWS credentials that were in the same repository/directory as the canary key

---

## UC-190 — Honey User Account Logon {#uc-190}

**Threat:** A decoy user account (realistic name, valid but unused) authenticates.
These accounts are seeded in directory listings, on shares as "owner" of files,
or in password lists. Any authentication attempt is 100% malicious.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 99 |
| **MITRE** | T1078 — Valid Accounts |
| **Data Sources** | Windows Security 4624/4625 |
| **Rule IDs** | SP-deception-005 |

### Splunk SPL

```spl
| inputlookup honey_accounts.csv as honey
| join type=inner TargetUserName
    [search index=windows EventCode IN (4624, 4625)
     | table _time, TargetUserName, IpAddress, LogonType, WorkstationName, host]
| table _time, TargetUserName, IpAddress, WorkstationName, host, LogonType
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Honey Account", sourceip AS "Source",
    "WorkstationName" AS "Workstation", "LogonType" AS "Logon Type",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID IN ('4624','4625')
    AND username IN (SELECT DISTINCT "AccountName" FROM reference_sets WHERE name='Honey-Account-List')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Even a failed login against a honey account is high-confidence malicious
2. Successful logon: isolate the source workstation immediately
3. Trace the path of discovery — how did the attacker get this account name?
4. Deploy multiple honey accounts at different privilege tiers (user, admin, service)
5. Ensure honey accounts appear in relevant places (AD description fields, shares, logs)

---

## UC-191 — Canary DNS Query Detected {#uc-191}

**Threat:** A unique, never-used DNS hostname (canary domain) embedded in documents,
scripts, or configuration files is queried — proving the attacker opened and
executed/parsed the file. Works even when the file is exfiltrated and opened externally.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 99 |
| **MITRE** | T1567 — Exfiltration Over Web Service |
| **Data Sources** | DNS logs, Sysmon Event 22 |
| **Rule IDs** | SP-deception-006 |

### Splunk SPL

```spl
index=dns sourcetype IN ("cisco:umbrella","windows:dns","syslog")
| where match(query,"(?i)(canary\.|honey\.|\.canarytokens\.org|\.canarytokens\.com)")
    OR match(query,"(?i)(DO-NOT-QUERY|honeypot-detector|do-not-resolve)")
| table _time, query, src_ip, host
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Querier", "QueryDomain" AS "Canary Domain",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Query Time"
FROM events WHERE "LogSourceType" = 'DNS'
    AND ("QueryDomain" LIKE '%.canarytokens.org%'
        OR "QueryDomain" IN (SELECT DISTINCT "Domain" FROM reference_sets WHERE name='Canary-DNS-Domains'))
LAST 24 HOURS ORDER BY starttime DESC
```

### Deployment Guide

Use https://canarytokens.org/generate to create free DNS canary tokens.
Embed in:
- Word/Excel documents: `=WEBSERVICE("http://your-canary.canarytokens.org/")`
- PDF files: embedded URL
- Script files: DNS lookup at the start
- API documentation: example URL with canary hostname

### Response Actions
1. **Confirmed file access** — the file was opened (possibly outside your environment)
2. Identify the querier IP — was it internal (opened in office) or external (after exfiltration)?
3. Identify which canary document was triggered (each should have a unique hostname)
4. If external IP: the document was exfiltrated — initiate data breach response
5. Use canarytokens.org extended metadata: geolocation, user-agent of opener

---

## UC-192 — Honeypot Port Scan Detected {#uc-192}

**Threat:** A honeypot host (no legitimate services, never used in production)
receives connection attempts. Any traffic to this IP is definitionally unauthorized.
Even a port scan is high-confidence malicious when it hits a dedicated honeypot.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 95 |
| **MITRE** | T1046 — Network Service Discovery |
| **Data Sources** | Firewall logs, honeypot IDS |
| **Rule IDs** | SP-deception-007 |

### Splunk SPL

```spl
| inputlookup honeypot_ips.csv as honeypot
| join type=inner dest_ip
    [search index=firewall OR index=ids
     | table _time, src_ip, dest_ip, dest_port, protocol, action]
| stats count, dc(dest_port) as PortsScanned, values(dest_port) as Ports by src_ip, dest_ip, _time
| sort -PortsScanned
```

### QRadar AQL

```sql
SELECT sourceip AS "Scanner", destinationip AS "Honeypot IP",
    COUNT(DISTINCT destinationport) AS "Ports Hit",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE destinationip IN (
    SELECT DISTINCT "IP" FROM reference_sets WHERE name='Honeypot-IPs'
)
GROUP BY sourceip, destinationip, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
LAST 1 HOURS ORDER BY "Ports Hit" DESC
```

### Response Actions
1. Identify the source — internal host (already compromised) or external (direct attack)
2. Block the source IP at the firewall if external
3. If internal: the source host is actively conducting reconnaissance
4. Correlate the scanner's IP with other attack activity in your environment
5. Deploy more honeypot IPs in different VLANs to improve internal east-west detection

---

## UC-193 — Honeyfile Accessed on File Server {#uc-193}

**Threat:** A strategically placed "honey file" on a file server (labeled to appear
extremely valuable: "PasswordList.xlsx", "VPN_credentials_2024.txt") is accessed.
Legitimate users have no reason to open these files.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 98 |
| **MITRE** | T1083 — File and Directory Discovery |
| **Data Sources** | Windows Security 4663 |
| **Rule IDs** | SP-deception-008 |

### Splunk SPL

```spl
index=windows EventCode=4663
| where match(ObjectName,"(?i)(password.?list|credential.?backup|vpn.?cred|admin.?password|key.?backup|secret.?key|_honey_|_canary_)")
    AND AccessMask IN ("0x1","0x80","0x100","0x120089")
| table _time, host, SubjectUserName, IpAddress, ObjectName, AccessMask
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "User", sourceip AS "Source Host",
    "objectname" AS "Honey File Accessed", "AccessMask" AS "Access Type",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID = '4663'
    AND (LOWER("objectname") LIKE '%passwordlist%' OR LOWER("objectname") LIKE '%vpn_cred%'
        OR LOWER("objectname") LIKE '%_honey_%' OR LOWER("objectname") LIKE '%_canary_%'
        OR LOWER("objectname") LIKE '%admin_password%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. **Zero FP** — begin incident response immediately
2. Isolate the source workstation
3. Check if the file content was read or just opened (check access mask)
4. Review what the user/attacker did with the information (subsequent connections, exfiltration)
5. Begin lateral movement investigation — if they're searching for credentials, they plan to use them

---

## UC-194 — Honey Share Accessed (Network Lateral Detection) {#uc-194}

**Threat:** A decoy SMB share that no legitimate user has reason to access
is browsed or connected to. Ideal for detecting lateral movement scanning.
The share exists, allows anonymous listing, but contains only honeyfiles.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 97 |
| **MITRE** | T1135 — Network Share Discovery |
| **Data Sources** | Windows Security 5140/5142/5145 |
| **Rule IDs** | SP-deception-009 |

### Splunk SPL

```spl
| inputlookup honey_shares.csv as honey
| join type=inner ShareName
    [search index=windows EventCode IN (5140, 5142, 5145)
     | table _time, SubjectUserName, IpAddress, ShareName, host]
| table _time, SubjectUserName, IpAddress, ShareName, host
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "User", sourceip AS "Source",
    "ShareName" AS "Honey Share", destinationip AS "File Server",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID IN ('5140','5142','5145')
    AND "ShareName" IN (SELECT DISTINCT "Share" FROM reference_sets WHERE name='Honey-Shares')
LAST 24 HOURS ORDER BY starttime DESC
```

### Deployment Guide

Create a honey share on a file server:
```powershell
New-SmbShare -Name "backup_archive$" -Path "C:\Honeyshare" -FullAccess "Everyone"
# Enable auditing on the share path
# Populate with honey documents
```

### Response Actions
1. Any access to the honey share is confirmed unauthorized
2. Identify the source workstation — isolate from network
3. The attacker is conducting SMB enumeration — check what other shares they accessed
4. Review AD auth events from the source IP in the past hour
5. Escalate to full IR — active lateral movement is in progress

---

## UC-195 — Honey Token Service Accessed (HTTP) {#uc-195}

**Threat:** A canary HTTP endpoint (never used in production) receives a request.
Plant the URL in source code, documentation, environment variables, or secrets vaults.
Any request to it indicates the URL was found and an attacker is probing.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 95 |
| **MITRE** | T1078 — Valid Accounts |
| **Data Sources** | Web server logs, Azure/AWS API logs |
| **Rule IDs** | SP-deception-010 |

### Splunk SPL

```spl
index=webserver OR index=aws_api_gateway sourcetype IN ("access_combined","aws:apigateway")
| where match(uri,"(?i)(\/honey\/|\/canary\/|\/do-not-call\/|\/trap\/|\/bait\/)")
    OR match(uri,"(?i)(\/api\/v99\/|\/api\/internal\/honey|\/debug\/credentials)")
| table _time, src_ip, uri, user_agent, status
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Caller", "URI" AS "Honey Endpoint",
    "UserAgent" AS "User Agent", "StatusCode" AS "Response",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" IN ('Apache HTTP Server','Nginx','AWS API Gateway')
    AND ("URI" LIKE '%/honey/%' OR "URI" LIKE '%/canary/%'
        OR "URI" IN (SELECT DISTINCT "URL" FROM reference_sets WHERE name='Honey-Endpoints'))
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Identify the caller — internal (code execution) or external (direct web request)
2. Check user-agent: typical browser (human), curl (scripted), or custom agent (tool)
3. If the URL was planted in a Git repo: assume the repo was cloned by an attacker
4. Scan all repositories for similar patterns to assess blast radius
5. Rotate all credentials in repositories where honey tokens were planted

---

## UC-196 — Decoy SSH Key Used on Bastion {#uc-196}

**Threat:** A uniquely named decoy SSH private key (never the actual production key)
is planted on servers, in shares, or in developer workstations. When an attacker
finds and attempts to use it for SSH authentication, the bastion/jump host alerts.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 99 |
| **MITRE** | T1098.004 — Account Manipulation: SSH Authorized Keys |
| **Data Sources** | SSH auth log, bastion host logs |
| **Rule IDs** | SP-deception-011 |

### Splunk SPL

```spl
index=linux sourcetype IN ("syslog","linux_secure","auditd")
| where match(_raw,"(?i)(Accepted publickey|Failed publickey)")
    AND match(_raw,"(?i)(honey|canary|decoy|trap|bait|do.not.use)")
| table _time, host, user, _raw
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Attacker IP", username AS "User",
    "KeyFingerprint" AS "Key Used", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Linux OS'
    AND ("Message" LIKE '%Accepted publickey%' OR "Message" LIKE '%Failed publickey%')
    AND "KeyFingerprint" IN (SELECT DISTINCT "Fingerprint" FROM reference_sets WHERE name='Honey-SSH-Keys')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. **Confirmed key theft** — the decoy key was found on a compromised system
2. Identify where the decoy key was planted — that system is compromised
3. The attacker now has network-level knowledge — assume further access is planned
4. Block the source IP at the bastion host
5. Rotate all SSH keys on affected systems and audit authorized_keys files

---

## UC-197 — Fake MFA Bypass Attempt on Honey Identity {#uc-197}

**Threat:** An attacker targets a honey identity account with an MFA push notification
attack (MFA fatigue/push bombing) — repeatedly approving requests hoping the user
(which doesn't exist) will accept.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 92 |
| **MITRE** | T1621 — Multi-Factor Authentication Request Generation |
| **Data Sources** | Okta System Log, Entra ID Sign-in Log |
| **Rule IDs** | SP-deception-012 |

### Splunk SPL

```spl
| inputlookup honey_accounts.csv as honey
| join type=inner user
    [search index=okta OR index=azure_ad sourcetype IN ("okta:system","azure:aad:signin")
     | where match(_raw,"(?i)(push.*sent|mfa.*request|authentication.*pending|factor.*challenge)")
     | table _time, user, client_ip, factor_type]
| table _time, user, client_ip, factor_type
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Honey Account", sourceip AS "Attacker IP",
    "factorType" AS "MFA Factor", COUNT(*) AS "Push Attempts",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Window"
FROM events WHERE "LogSourceType" IN ('Okta','Microsoft Azure Active Directory')
    AND username IN (SELECT DISTINCT "AccountName" FROM reference_sets WHERE name='Honey-Account-List')
    AND LOWER("Message") LIKE '%mfa%'
GROUP BY username, sourceip, "factorType", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
LAST 1 HOURS ORDER BY "Push Attempts" DESC
```

### Response Actions
1. Block the source IP at the identity provider immediately
2. This indicates the attacker has the password for this honey account — credential confirmed compromised
3. Verify no real accounts share the same password pattern
4. Deploy MFA push number matching to prevent future MFA fatigue attacks
5. Identify how the honey account password was obtained — credential breach? LSASS dump?

---

## UC-198 — Canary API Key Used in Production API {#uc-198}

**Threat:** A specifically crafted API key embedded in internal documentation,
wikis, or onboarding materials is used to call your real API. Proves an
attacker found the documentation and is attempting to use internal credentials.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 98 |
| **MITRE** | T1552 — Unsecured Credentials |
| **Data Sources** | API gateway logs, Web server access logs |
| **Rule IDs** | SP-deception-013 |

### Splunk SPL

```spl
| inputlookup canary_api_keys.csv as canary
| join type=inner api_key
    [search index=api_gateway OR index=webserver
     | rex field=_raw "(?i)Authorization:\s*Bearer\s+(?P<api_key>[A-Za-z0-9._-]+)|(?i)x-api-key:\s*(?P<api_key>[A-Za-z0-9._-]+)"
     | table _time, src_ip, uri, api_key, user_agent]
| table _time, api_key, src_ip, uri, user_agent
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Caller IP", "APIKey" AS "Canary Key Used",
    "URI" AS "API Endpoint", "UserAgent" AS "Client",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" IN ('AWS API Gateway','Nginx','Apache HTTP Server')
    AND "APIKey" IN (SELECT DISTINCT "Key" FROM reference_sets WHERE name='Canary-API-Keys')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Identify where the canary key was planted — that resource was accessed by the attacker
2. Assess what the attacker could have found at that location (other credentials, internal docs)
3. Block the calling IP
4. Rotate all API keys in the documentation/wiki where the canary was found
5. Audit who has access to the documentation source — insider threat may be involved

---

## UC-199 — LDAP Honey Object Queried {#uc-199}

**Threat:** A decoy AD object (user, group, or OU) with an enticing description
(like "ServiceAccount-Admin-2024 — DO NOT USE") is queried via LDAP. Any query
specifically requesting this object's attributes is suspicious.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 90 |
| **MITRE** | T1069.002 — Permission Groups Discovery |
| **Data Sources** | Windows Security 4661/4662 (DC) |
| **Rule IDs** | SP-deception-014 |

### Splunk SPL

```spl
| inputlookup honey_ad_objects.csv as honey
| join type=inner ObjectName
    [search index=windows EventCode IN (4661, 4662)
     | table _time, SubjectUserName, ObjectName, host, IpAddress]
| table _time, SubjectUserName, ObjectName, IpAddress, host
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Querier", "ObjectName" AS "Honey Object",
    sourceip AS "Source", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID IN ('4661','4662')
    AND "ObjectName" IN (SELECT DISTINCT "ObjectName" FROM reference_sets WHERE name='Honey-AD-Objects')
    AND username NOT LIKE '%$'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. The querying account is conducting AD reconnaissance
2. If a machine account queried: the machine is likely running BloodHound/SharpHound
3. Correlate with other LDAP enumeration patterns from the same source
4. The honey object naming should be distinctive enough to only attract automated tools
5. Use the honey object to fingerprint specific recon tooling (BloodHound uses specific LDAP filters)

---

## UC-200 — Global Deception Alert Aggregation {#uc-200}

**Threat:** Multiple deception/canary signals firing within a short window from
the same attacker IP or user. Aggregating these signals provides maximum confidence
and context about the scope of the attacker's discovery.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 99 |
| **MITRE** | Multiple — Attack Chain Detected via Deception |
| **Data Sources** | All deception data sources combined |
| **Rule IDs** | SP-deception-015 |

### Splunk SPL

```spl
| union
    [search index=windows EventCode=4663 | where match(ObjectName,"(?i)(canary|honey|_do_not_|passwordlist)")
     | eval canary_type="HoneyFile" | table _time, SubjectUserName, IpAddress, canary_type]
    [search index=dns | where match(query,"(?i)(canarytokens|honey\.|canary\.|do-not-query)")
     | eval canary_type="CanaryDNS" | table _time, src_ip as IpAddress, SubjectUserName, canary_type]
    [search index=windows EventCode IN (4624,4625) | where match(TargetUserName,"(?i)(honey|decoy|canary|trap)")
     | eval canary_type="HoneyAccount" | table _time, TargetUserName as SubjectUserName, IpAddress, canary_type]
    [search index=firewall | where match(dest_ip,"(?i)honeypot")
     | eval canary_type="HoneypotAccess" | table _time, src_ip as IpAddress, canary_type]
| bucket _time span=1h
| stats count, dc(canary_type) as TypeCount, values(canary_type) as Types by IpAddress, _time
| where TypeCount >= 2 OR count >= 3
| sort -TypeCount
```

### QRadar AQL

```sql
SELECT "AttackerIP" AS "Attacker", COUNT(*) AS "Canary Hits",
    COUNT(DISTINCT "CanaryType") AS "Unique Canary Types",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Detection Window"
FROM (
    SELECT sourceip AS "AttackerIP", 'HoneyFile' AS "CanaryType", starttime FROM events
        WHERE EventID = '4663' AND LOWER("objectname") LIKE '%canary%'
    UNION
    SELECT sourceip AS "AttackerIP", 'CanaryDNS' AS "CanaryType", starttime FROM events
        WHERE QIDNAME(qid) = 'DNS' AND "QueryDomain" LIKE '%.canarytokens.org%'
    UNION
    SELECT sourceip AS "AttackerIP", 'HoneyAccount' AS "CanaryType", starttime FROM events
        WHERE EventID IN ('4624','4625')
        AND username IN (SELECT DISTINCT "AccountName" FROM reference_sets WHERE name='Honey-Account-List')
    LAST 1 HOURS
) all_canaries
GROUP BY "AttackerIP", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(*) >= 2
LAST 1 HOURS ORDER BY "Canary Hits" DESC
```

### Response Actions
1. **Maximum confidence IR trigger** — attacker is actively sweeping your environment
2. Multiple deception hits from one source = persistent attacker with broad access
3. Correlate the attacker IP with all SIEM data: what else has this IP done?
4. Isolate identified source hosts immediately
5. Begin full domain-wide IR — attacker likely has access beyond what's detected

---

*This completes the 200 Use Case catalog. Each use case includes production-ready Splunk SPL and QRadar AQL queries, MITRE ATT&CK mappings, and actionable response playbooks.*
