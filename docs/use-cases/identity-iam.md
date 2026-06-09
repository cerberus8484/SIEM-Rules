# Identity & IAM

Use cases for detecting privileged account abuse, MFA bypass, and cloud identity attacks.

**Rule pack:** `identity` (SP-500xxx)

---

## UC-031 — AWS Root Account Login {#uc-031}

**Threat:** The AWS root account should never be used for day-to-day operations.
Any root login is a high-priority alert — either an attacker gained access or
an admin is violating least-privilege policy.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 99 |
| **MITRE** | T1078.004 — Valid Accounts: Cloud Accounts |
| **Data Sources** | AWS CloudTrail |
| **Rule IDs** | SP-500001 |

### Splunk SPL

```spl
index=aws sourcetype="aws:cloudtrail"
| where userIdentity.type="Root" AND eventName="ConsoleLogin"
| eval mfa=if(additionalEventData.MFAUsed="Yes", "MFA Used", "NO MFA — CRITICAL")
| table _time, sourceIPAddress, userAgent, responseElements.ConsoleLogin, mfa
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Source IP",
    username AS "Account",
    "UserAgent" AS "User Agent",
    "MFAUsed" AS "MFA",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    "LogSourceType" = 'Amazon AWS CloudTrail'
    AND "EventName" = 'ConsoleLogin'
    AND "UserType" = 'Root'
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. **No false positives expected** — investigate immediately
2. Check if MFA was used — if not, assume credential compromise
3. Verify with the account owner if they performed the login
4. If unauthorized: rotate root credentials, enable MFA, review IAM for changes
5. Check what API calls were made after the root login (CloudTrail next 1h)

---

## UC-032 — Privileged Account Login from New Location {#uc-032}

**Threat:** Admin or service account logs in from an IP that has never been seen before
for that account. May indicate credential theft or account takeover.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 78 |
| **MITRE** | T1078 — Valid Accounts |
| **Data Sources** | Windows Security 4624, Okta, Entra ID |
| **Rule IDs** | SP-500003, SP-500004 |

### Splunk SPL

```spl
index=windows EventCode=4624 LogonType IN (10, 3)
| where match(AccountName, "(?i)(admin|svc_|sa_|priv_|root|administrator)")
    AND IpAddress!="127.0.0.1" AND IpAddress!="-"
| stats values(IpAddress) as AllIPs, count by AccountName, host, _time
| streamstats window=30d values(IpAddress) as HistoricIPs by AccountName
| eval new_ip=mvmap(AllIPs, if(mvfind(HistoricIPs, AllIPs)>=0, null(), AllIPs))
| where isnotnull(new_ip)
| table _time, host, AccountName, new_ip, AllIPs
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Login IP",
    destinationip AS "Target Host",
    username AS "Account",
    "LogonType" AS "LogonType",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    EventID = '4624'
    AND "LogonType" IN ('3', '10')
    AND (
        LOWER(username) LIKE '%admin%'
        OR LOWER(username) LIKE '%svc_%'
        OR LOWER(username) LIKE '%sa_%'
    )
    AND sourceip NOT IN (
        SELECT DISTINCT sourceip FROM events
        WHERE EventID = '4624' AND starttime BETWEEN (NOW() - 30 DAYS) AND (NOW() - 1 DAYS)
    )
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Contact the account owner — did they log in from a new location?
2. Check the source IP against threat intel (VPN exit, Tor, hosting provider?)
3. If unauthorized: lock the account immediately, force password reset
4. Review all actions taken during the session
5. Check for persistence mechanisms created during the session

---

## UC-033 — MFA Bypass / Impossible Travel {#uc-033}

**Threat:** Attacker bypasses MFA (via SIM swap, AiTM phishing, or session hijacking)
or logs in from two geographic locations within an impossible timeframe.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 85 |
| **MITRE** | T1078 — Valid Accounts (AiTM Phishing: T1557) |
| **Data Sources** | Okta System Log, Entra ID Sign-in Logs |
| **Rule IDs** | SP-500005, SP-500006 |

### Splunk SPL

```spl
index=okta sourcetype="okta:system" eventType="user.authentication.sso"
| iplocation client.ipAddress
| eval lat=lat, lon=lon, city=City, country=Country
| sort 0 user, _time
| streamstats window=2 current=t values(lat) as lats, values(lon) as lons,
    values(Country) as countries, values(_time) as times by user
| eval
    lat1=mvindex(lats,0), lat2=mvindex(lats,1),
    lon1=mvindex(lons,0), lon2=mvindex(lons,1),
    time_diff_min=round((mvindex(times,1)-mvindex(times,0))/60, 0),
    dist_km=round(acos(sin(lat1*pi()/180)*sin(lat2*pi()/180)+cos(lat1*pi()/180)*cos(lat2*pi()/180)*cos((lon2-lon1)*pi()/180))*6371, 0)
| where dist_km > 500 AND time_diff_min < 120
| table _time, user, countries, dist_km, time_diff_min
```

### QRadar AQL

```sql
SELECT
    username AS "User",
    sourceip AS "Login IP",
    "City" AS "City",
    "Country" AS "Country",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    "LogSourceType" IN ('Okta', 'Microsoft Azure Active Directory Audit')
    AND QIDNAME(qid) LIKE '%authentication%'
    AND username IN (
        SELECT username FROM events
        WHERE "LogSourceType" IN ('Okta', 'Microsoft Azure Active Directory Audit')
        GROUP BY username
        HAVING COUNT(DISTINCT "Country") >= 2
    )
LAST 2 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Terminate all active sessions for the affected user immediately
2. Force MFA re-registration — assume the authenticator is compromised
3. Check email forwarding rules (→ UC-044) — common AiTM follow-up
4. Review what was accessed after the suspicious login
5. If AiTM phishing suspected: analyze the phishing page URL in threat intel

---

## UC-034 — Okta Admin Role Granted {#uc-034}

**Threat:** Attacker elevates a compromised account to Okta admin, enabling
full identity control over the organization. Often the final step before mass lockout.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 90 |
| **MITRE** | T1098 — Account Manipulation |
| **Data Sources** | Okta System Log |
| **Rule IDs** | SP-500007 |

### Splunk SPL

```spl
index=okta sourcetype="okta:system"
| where eventType IN ("user.account.privilege.grant", "group.user.membership.add")
    AND match(target{}.displayName, "(?i)(admin|super admin|org admin|app admin|read-only admin)")
| eval granter=actor.displayName, granted_to=target{0}.displayName, role=target{1}.displayName
| table _time, granter, granted_to, role, client.ipAddress
| sort -_time
```

### QRadar AQL

```sql
SELECT
    username AS "Granted By",
    "TargetUser" AS "Granted To",
    "Role" AS "Role Assigned",
    sourceip AS "Source IP",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    "LogSourceType" = 'Okta'
    AND QIDNAME(qid) LIKE '%privilege.grant%'
    AND (
        LOWER("Role") LIKE '%admin%'
        OR LOWER("Role") LIKE '%super admin%'
    )
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Verify with IT whether this role grant was authorized and expected
2. If unauthorized: revoke admin immediately from Okta Admin Console
3. Check what the newly-granted admin did in the minutes after receiving the role
4. Review all apps accessible via Okta for unauthorized access attempts
5. Audit all admin role grants in the last 30 days for scope creep

---

## UC-035 — Entra ID — Bulk User Deletion {#uc-035}

**Threat:** Attacker with Global Administrator access deletes multiple user accounts
to cause operational disruption or lock out defenders.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 88 |
| **MITRE** | T1531 — Account Access Removal |
| **Data Sources** | Entra ID Audit Logs |
| **Rule IDs** | SP-500008 |

### Splunk SPL

```spl
index=azure sourcetype="azure:audit"
| where operationName="Delete user" AND activityStatusValue="success"
| bin _time span=5m
| stats count as DeletedUsers, values(targetResources{}.userPrincipalName) as DeletedAccounts
    by initiatedBy.user.userPrincipalName, _time
| where DeletedUsers >= 5
| eval alert="Bulk user deletion — " . DeletedUsers . " accounts in 5 min"
| sort -DeletedUsers
```

### QRadar AQL

```sql
SELECT
    username AS "Performed By",
    "TargetUser" AS "Deleted Account",
    COUNT(*) OVER (PARTITION BY username) AS "DeletionCount",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    "LogSourceType" = 'Microsoft Azure Active Directory Audit'
    AND "OperationName" = 'Delete user'
    AND "ActivityStatus" = 'success'
GROUP BY username
HAVING COUNT(*) >= 5
LAST 5 MINUTES
ORDER BY DeletionCount DESC
```

### Response Actions

1. **Operational emergency** — contact IT leadership and service desk immediately
2. Restore deleted accounts from Azure Recycle Bin (30-day window)
3. Revoke admin credentials of the performing account immediately
4. Check what other destructive actions were taken (mail deletion, license removal)
5. Initiate incident response — this is an active attack
