# VPN & Remote Access

Use cases for detecting malicious use of remote access infrastructure.

**Rule packs:** `vpn`, `identity`

---

## UC-089 — VPN Brute Force {#uc-089}

**Threat:** Attacker attempts repeated VPN authentication failures against valid or
guessed usernames, trying to gain remote access without MFA.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 85 |
| **MITRE** | T1110.001 — Brute Force: Password Guessing |
| **Data Sources** | VPN logs (Cisco ASA, Fortinet, Palo Alto GlobalProtect, OpenVPN) |
| **Rule IDs** | SP-vpn-001 |

### Splunk SPL

```spl
index=vpn sourcetype IN ("cisco:asa","fortinet:vpn","paloalto:globalprotect","openvpn")
| where match(_raw,"(?i)(authentication failed|rejected|access denied|invalid credentials|login failed)")
| bucket _time span=10m
| stats count, dc(src_ip) as SourceIPs, dc(user) as UsersTried by dest_host, _time
| where count >= 20 OR UsersTried >= 10
| sort -count
```

### QRadar AQL

```sql
SELECT destinationip AS "VPN Gateway", COUNT(*) AS "Failed Attempts",
    COUNT(DISTINCT sourceip) AS "Source IPs",
    COUNT(DISTINCT username) AS "Usernames Tried",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Window"
FROM events WHERE "LogSourceType" IN ('Cisco VPN','Fortinet','Palo Alto Networks')
    AND QIDNAME(qid) LIKE '%Authentication Failed%'
GROUP BY destinationip, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(*) >= 20
LAST 1 HOURS ORDER BY "Failed Attempts" DESC
```

### Response Actions
1. Block source IPs at the VPN gateway for the duration of investigation
2. Check if any usernames in the brute force list are valid accounts
3. Enable lockout after N failed attempts in VPN policy
4. Correlate with successful logins from the same source IP (burst then success)
5. Enforce MFA on all VPN accounts if not already enabled

---

## UC-090 — New User First VPN Login {#uc-090}

**Threat:** A user account authenticates to VPN for the first time ever. May indicate
account compromise, credential theft, or an attacker using a legitimate user's credentials.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 68 |
| **MITRE** | T1078 — Valid Accounts |
| **Data Sources** | VPN authentication logs |
| **Rule IDs** | SP-vpn-002 |

### Splunk SPL

```spl
index=vpn sourcetype IN ("cisco:asa","fortinet:vpn","paloalto:globalprotect")
| where match(_raw,"(?i)(authenticated|connected|session established|login successful)")
| stats min(_time) as FirstSeen, max(_time) as LastSeen, count by user, src_ip
| where FirstSeen >= relative_time(now(), "-1d@d")
| sort FirstSeen
```

### QRadar AQL

```sql
SELECT username AS "User", sourceip AS "Source IP",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "First VPN Login"
FROM events WHERE "LogSourceType" IN ('Cisco VPN','Fortinet','Palo Alto Networks')
    AND QIDNAME(qid) LIKE '%Authentication Successful%'
    AND username NOT IN (
        SELECT DISTINCT username FROM events
        WHERE "LogSourceType" IN ('Cisco VPN','Fortinet','Palo Alto Networks')
            AND QIDNAME(qid) LIKE '%Authentication Successful%'
            AND starttime < NOW()-86400000
        LAST 90 DAYS
    )
LAST 1 DAYS ORDER BY starttime ASC
```

### Response Actions
1. Verify with the user directly whether they initiated the VPN session
2. Check the source IP — is it a known corporate IP or a residential/VPS IP?
3. If the user did not initiate: force logout, reset password, invalidate MFA tokens
4. Review what was accessed during the VPN session (AD authentication events, file access)
5. Consider requiring manager approval for new VPN access requests

---

## UC-091 — VPN Login Outside Business Hours {#uc-091}

**Threat:** Attacker uses stolen VPN credentials at unusual hours (weekends, middle of night)
when the activity is less likely to be noticed. High-risk for accounts with no MFA.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 65 |
| **MITRE** | T1078 — Valid Accounts |
| **Data Sources** | VPN authentication logs |
| **Rule IDs** | SP-vpn-003 |

### Splunk SPL

```spl
index=vpn sourcetype IN ("cisco:asa","fortinet:vpn","paloalto:globalprotect")
| where match(_raw,"(?i)(authenticated|connected|session established)")
| eval hour=strftime(_time,"%H"), dow=strftime(_time,"%w")
| where (hour < 6 OR hour >= 22) OR dow IN ("0","6")
| table _time, user, src_ip, hour, dow
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "User", sourceip AS "Source IP",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Login Time",
    EXTRACT(HOUR FROM starttime) AS "Hour", EXTRACT(DOW FROM starttime) AS "Day of Week"
FROM events WHERE "LogSourceType" IN ('Cisco VPN','Fortinet','Palo Alto Networks')
    AND QIDNAME(qid) LIKE '%Authentication Successful%'
    AND (EXTRACT(HOUR FROM starttime) < 6
        OR EXTRACT(HOUR FROM starttime) >= 22
        OR EXTRACT(DOW FROM starttime) IN (0, 6))
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Correlate with HR records — is this person known to work outside hours?
2. Check source IP geolocation — consistent with the user's known location?
3. Alert low-risk accounts but investigate high-privilege accounts immediately
4. Consider time-of-day access controls in your VPN policy for privileged accounts
5. Implement adaptive MFA: step-up authentication for off-hours access

---

## UC-092 — VPN Login from Tor or Known VPS {#uc-092}

**Threat:** Attacker accesses VPN from a Tor exit node or commercial VPS to anonymize
their origin. Corporate users have no legitimate reason to use Tor for VPN access.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 90 |
| **MITRE** | T1090.003 — Proxy: Multi-hop Proxy |
| **Data Sources** | VPN logs + Threat Intelligence feed |
| **Rule IDs** | SP-vpn-004 |

### Splunk SPL

```spl
| inputlookup tor_exit_nodes.csv as tor
| join type=inner src_ip [search index=vpn match(_raw,"(?i)(authenticated|connected|session established)") | table _time, user, src_ip]
| table _time, user, src_ip
| eval source_type="Tor Exit Node"
| append
    [search index=vpn match(_raw,"(?i)(authenticated|connected|session established)")
     | lookup vpn_threat_intel.csv ip as src_ip OUTPUT category
     | where category IN ("VPS","Hosting","Proxy","Anonymizer")
     | table _time, user, src_ip, category]
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "User", sourceip AS "IP",
    "IPCategory" AS "IP Classification",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Login Time"
FROM events WHERE "LogSourceType" IN ('Cisco VPN','Fortinet','Palo Alto Networks')
    AND QIDNAME(qid) LIKE '%Authentication Successful%'
    AND "IPCategory" IN ('TOR','VPN Provider','Hosting','Anonymizer')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. **Near-zero FP** — terminate the session immediately
2. Force password reset and MFA re-enrollment for the account
3. Review all activity in the VPN session before termination
4. Block Tor exit nodes at the VPN gateway (use regularly-updated list)
5. Consider a named IP policy: only allow VPN access from known/registered IPs

---

## UC-093 — Concurrent VPN Sessions (Same User) {#uc-093}

**Threat:** An account authenticates to VPN from two different geographic locations
simultaneously, indicating credential sharing or account compromise.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 85 |
| **MITRE** | T1078 — Valid Accounts |
| **Data Sources** | VPN session logs |
| **Rule IDs** | SP-vpn-005 |

### Splunk SPL

```spl
index=vpn sourcetype IN ("cisco:asa","fortinet:vpn","paloalto:globalprotect")
| where match(_raw,"(?i)(session established|authenticated)")
| iplocation src_ip
| bucket _time span=30m
| stats dc(src_ip) as SessionCount, values(src_ip) as IPs, values(Country) as Countries by user, _time
| where SessionCount >= 2 AND mvcount(Countries) >= 2
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "User", COUNT(DISTINCT sourceip) AS "Concurrent IPs",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time Window"
FROM events WHERE "LogSourceType" IN ('Cisco VPN','Fortinet','Palo Alto Networks')
    AND QIDNAME(qid) LIKE '%Session Established%'
GROUP BY username, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(DISTINCT sourceip) >= 2
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Contact the user directly — do they know about both sessions?
2. Terminate both sessions and require re-authentication
3. If credential sharing: enforce policy violation procedures
4. If account compromise: full credential reset and IR
5. Consider max concurrent sessions policy in VPN configuration

---

## UC-094 — VPN Access to Sensitive Admin Systems {#uc-094}

**Threat:** VPN user directly connects to domain controllers, backup servers,
or other sensitive infrastructure without going through a jump server (PAW).
Indicates either insider threat or compromised VPN account.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 75 |
| **MITRE** | T1021.001 — Remote Services |
| **Data Sources** | VPN session logs + Windows Security 4624 (DCs) |
| **Rule IDs** | SP-vpn-006 |

### Splunk SPL

```spl
| join type=inner user
    [search index=vpn match(_raw,"(?i)(session established|authenticated)") | table _time, user, src_ip, vpn_assigned_ip]
    [search index=windows EventCode=4624 LogonType IN (3, 10)
     | where match(WorkstationName,"(?i)(dc|domaincontroller|backup|prd-sql|prod)")
     | table _time, user, IpAddress]
| where abs(strptime(_time, "%Y-%m-%dT%H:%M:%S") - strptime(vpn_time, "%Y-%m-%dT%H:%M:%S")) < 3600
| table _time, user, src_ip, vpn_assigned_ip, IpAddress
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "User", sourceip AS "VPN IP", destinationip AS "Accessed Server",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Microsoft Windows Security Event Log'
    AND EventID = '4624' AND "LogonType" IN ('3','10')
    AND destinationip IN (SELECT DISTINCT destinationip FROM reference_sets WHERE name='DC-IP-List')
    AND sourceip IN (SELECT DISTINCT sourceip FROM events
        WHERE "LogSourceType" IN ('Cisco VPN','Palo Alto Networks')
        AND starttime > NOW()-3600000
        LAST 1 HOURS)
LAST 1 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Identify whether this user normally has admin access to these systems
2. VPN users should not access DCs directly — require a PAW/jump server
3. If unauthorized: isolate the VPN session and initiate IR
4. Review what was done on the DC (authentication events, GPO changes, AD modifications)
5. Implement VPN split tunnel policies to restrict direct DC access from VPN clients

---

## UC-095 — Admin Account VPN Login (Non-PAW) {#uc-095}

**Threat:** A privileged admin account (Domain Admin, Exchange Admin, etc.) authenticates
to VPN from a non-privileged access workstation (PAW). Admin accounts should only
connect from dedicated hardened workstations.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 80 |
| **MITRE** | T1078.002 — Valid Accounts: Domain Accounts |
| **Data Sources** | VPN logs + AD group membership |
| **Rule IDs** | SP-vpn-007 |

### Splunk SPL

```spl
index=vpn match(_raw,"(?i)(authenticated|connected|session established)")
| rex field=_raw "user=(?P<vpn_user>[^\s]+)"
| lookup ad_privileged_accounts.csv user as vpn_user OUTPUT is_privileged, admin_type
| where is_privileged="true"
| table _time, vpn_user, admin_type, src_ip
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Privileged Account", sourceip AS "Source IP",
    "AccountType" AS "Admin Type", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Login Time"
FROM events WHERE "LogSourceType" IN ('Cisco VPN','Fortinet','Palo Alto Networks')
    AND QIDNAME(qid) LIKE '%Authentication Successful%'
    AND username IN (
        SELECT DISTINCT "MemberName" FROM reference_sets WHERE name='Privileged-Accounts'
    )
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Verify with the admin — are they connecting from their PAW?
2. If from a non-PAW: require immediate disconnection and reconnect from PAW
3. Implement VPN certificate-based authentication scoped to PAW machine certificates
4. Consider separate VPN gateway for admin accounts with additional controls
5. Enforce a policy: admin accounts must ONLY connect from registered PAW devices

---

## UC-096 — VPN Split Tunnel Bypass to Corporate Resources {#uc-096}

**Threat:** A VPN user accesses internal corporate resources while the device may also
have access to untrusted external networks (split tunneling). Indicates potential
for data leakage or attacker pivoting through a VPN client device.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 62 |
| **MITRE** | T1599 — Network Boundary Bridging |
| **Data Sources** | VPN session logs, endpoint network telemetry |
| **Rule IDs** | SP-vpn-008 |

### Splunk SPL

```spl
index=vpn match(_raw,"(?i)(split.tunnel|split_tunnel|partial.tunnel)")
| join type=inner user
    [search index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3)
     | where DestinationPort IN (445, 3389, 636, 389, 88)
     | stats count by user, DestinationIp, _time]
| table _time, user, src_ip, DestinationIp, DestinationPort
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "User", sourceip AS "VPN Client IP",
    COUNT(DISTINCT destinationip) AS "Internal Resources Accessed",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Microsoft Windows Security Event Log'
    AND EventID = '4624' AND "LogonType" = '3'
    AND sourceip IN (
        SELECT DISTINCT "VPNAssignedIP" FROM events
        WHERE "LogSourceType" = 'Cisco VPN' AND starttime > NOW()-3600000
        LAST 1 HOURS
    )
GROUP BY username, sourceip, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(DISTINCT destinationip) >= 10
LAST 1 HOURS ORDER BY "Internal Resources Accessed" DESC
```

### Response Actions
1. Disable split tunneling in VPN policy for all users with access to sensitive systems
2. Ensure full-tunnel VPN forces all traffic through corporate security controls
3. If split tunnel is required: enforce endpoint compliance checks before full access
4. Correlate with data exfiltration indicators from the same VPN client IP
5. Consider NAC (Network Access Control) for VPN clients: health checks before access
