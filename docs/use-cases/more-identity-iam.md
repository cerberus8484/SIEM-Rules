# Identity & IAM — Extended

Extended identity and IAM threat detection beyond UC-031–035.

**Rule packs:** `identity`

---

## UC-168 — Account Lockout Storm {#uc-168}

**Threat:** Attacker triggers mass account lockouts across many accounts — either from
a password spray that exceeded the lockout threshold, or deliberately to cause
a denial-of-service. Also occurs when a domain user's old password is cached on multiple devices.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 85 |
| **MITRE** | T1531 — Account Access Removal |
| **Data Sources** | Windows Security 4740 (DC) |
| **Rule IDs** | SP-identity-001 |

### Splunk SPL

```spl
index=windows EventCode=4740
| bucket _time span=5m
| stats count, dc(TargetUserName) as UniqueAccounts, values(CallerComputerName) as Sources by host, _time
| where UniqueAccounts >= 10
| sort -UniqueAccounts
```

### QRadar AQL

```sql
SELECT destinationip AS "DC", COUNT(DISTINCT "TargetAccount") AS "Locked Out Accounts",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "5-Minute Window"
FROM events WHERE EventID = '4740'
GROUP BY destinationip, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(DISTINCT "TargetAccount") >= 10
LAST 30 MINUTES ORDER BY "Locked Out Accounts" DESC
```

### Response Actions
1. Identify the CallerComputerName — the source of the bad passwords
2. If a single source: investigate the host for stale credential caches
3. If many sources: indicates active password spray or AD enumeration
4. Unlock accounts via DC: `Unlock-ADAccount -Identity <user>`
5. Enable Fine-Grained Password Policies to protect service accounts with different lockout thresholds

---

## UC-169 — Service Account Interactive Login {#uc-169}

**Threat:** A service account (identified by naming convention: svc-, sa_, _svc, etc.)
performs an interactive login — these accounts should only authenticate non-interactively
from specific services, never from a user session.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 85 |
| **MITRE** | T1078.002 — Valid Accounts: Domain Accounts |
| **Data Sources** | Windows Security 4624 |
| **Rule IDs** | SP-identity-002 |

### Splunk SPL

```spl
index=windows EventCode=4624
| where LogonType IN (2, 10)
    AND (match(TargetUserName,"(?i)^(svc[-_]|sa[-_]|service[-_]|srv[-_]|app[-_])")
        OR match(TargetUserName,"(?i)([-_](svc|sa|service|srv|app)$)"))
    AND NOT match(WorkstationName,"(?i)(jumpserver|pam|cyberark|thycotic)")
| table _time, host, TargetUserName, WorkstationName, IpAddress, LogonType
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Service Account", sourceip AS "Logged in From",
    "LogonType" AS "Type", destinationip AS "Target Host",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID = '4624'
    AND "LogonType" IN ('2','10')
    AND (LOWER(username) LIKE 'svc_%' OR LOWER(username) LIKE 'sa_%'
        OR LOWER(username) LIKE 'service_%' OR LOWER(username) LIKE '%_svc')
    AND sourceip NOT IN (SELECT DISTINCT ip FROM reference_sets WHERE name='PAM-IPs')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Investigate — service accounts should never log in interactively
2. This indicates either account compromise or admin misuse
3. Restrict service accounts via Group Policy: "Deny log on locally" / "Deny log on through RDS"
4. Consider Group Managed Service Accounts (gMSA) — cannot be used for interactive logon
5. Audit all service account privileges: `Get-ADUser -Filter {ServicePrincipalName -like "*"}`

---

## UC-170 — Admin Login from Non-PAW Workstation {#uc-170}

**Threat:** A Tier 0 (Domain Admin, Enterprise Admin) or Tier 1 account logs in
interactively from a regular workstation instead of a Privileged Access Workstation (PAW).
Violates the AD tiering model and exposes admin credentials to workstation-level threats.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 82 |
| **MITRE** | T1078 — Valid Accounts |
| **Data Sources** | Windows Security 4624 |
| **Rule IDs** | SP-identity-003 |

### Splunk SPL

```spl
index=windows EventCode=4624
| where LogonType IN (2, 10, 3)
| lookup ad_privileged_accounts.csv user as TargetUserName OUTPUT is_privileged, tier
| where is_privileged="true"
| lookup paw_workstations.csv workstation as WorkstationName OUTPUT is_paw
| where is_paw!="true"
| table _time, TargetUserName, tier, WorkstationName, IpAddress, LogonType
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Privileged Account", sourceip AS "Source Workstation",
    "WorkstationName" AS "Computer Name", "LogonType" AS "Logon Type",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID = '4624'
    AND "LogonType" IN ('2','10')
    AND username IN (SELECT DISTINCT "MemberName" FROM reference_sets WHERE name='Domain-Admin-List')
    AND "WorkstationName" NOT IN (SELECT DISTINCT name FROM reference_sets WHERE name='PAW-Hostnames')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Alert the admin and require immediate re-authentication from PAW
2. Check what was done during the session on the regular workstation
3. Review if the admin account was used on the non-PAW system for credential caching
4. Enforce via Group Policy Restricted Groups that admin accounts can only log on from PAWs
5. Consider implementing Microsoft's PAW architecture (phased approach)

---

## UC-171 — Stale Account Reactivated {#uc-171}

**Threat:** A dormant account that has not logged in for 90+ days is suddenly
re-enabled and authenticates. Often indicates an insider threat re-using an old account
or an attacker activating an account discovered during reconnaissance.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 82 |
| **MITRE** | T1078 — Valid Accounts |
| **Data Sources** | Windows Security 4722/4624 (DC) |
| **Rule IDs** | SP-identity-004 |

### Splunk SPL

```spl
| join type=inner TargetUserName
    [search index=windows EventCode=4722
     | table _time, TargetUserName, SubjectUserName | rename _time as EnableTime]
    [search index=windows EventCode=4624 LogonType IN (2, 3, 10)
     | table _time, TargetUserName, IpAddress | rename _time as LogonTime]
| where LogonTime > EnableTime AND LogonTime < EnableTime + 3600
| table EnableTime, LogonTime, TargetUserName, SubjectUserName, IpAddress
| sort EnableTime
```

### QRadar AQL

```sql
SELECT h2.username AS "Reactivated Account", h1.username AS "Enabled By",
    h1.starttime AS "Reactivation Time", h2.starttime AS "First Login After",
    h2.sourceip AS "Login Source"
FROM events h1
JOIN events h2 ON h1."TargetAccount" = h2.username
    AND h2.starttime > h1.starttime AND h2.starttime < h1.starttime + 3600000
WHERE h1.EventID = '4722' AND h2.EventID = '4624'
    AND h2."LogonType" IN ('2','3','10')
LAST 24 HOURS ORDER BY h1.starttime DESC
```

### Response Actions
1. Verify with the user and manager whether reactivation was authorized
2. If unauthorized: disable the account immediately and investigate who re-enabled it
3. Review what the account accessed after reactivation
4. Implement quarterly stale account reviews (disable after 90 days, delete after 180 days)
5. Require IT manager approval for account reactivation via ServiceNow/ITSM workflow

---

## UC-172 — Domain Admins Group Changed {#uc-172}

**Threat:** Members added to or removed from the Domain Admins group. Any change
to this group is high-risk and should be verified. Adding unauthorized accounts
to Domain Admins is the goal of many AD attacks.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 95 |
| **MITRE** | T1098 — Account Manipulation |
| **Data Sources** | Windows Security 4728/4729 (DC) |
| **Rule IDs** | SP-identity-005 |

### Splunk SPL

```spl
index=windows EventCode IN (4728, 4729, 4756, 4757)
| where match(GroupName,"(?i)(Domain Admins|Enterprise Admins|Schema Admins|Administrators|Domain Controllers)")
    AND NOT match(SubjectUserName,"(?i)(SYSTEM|\$$|admin_provisioning)")
| eval action=case(EventCode IN (4728,4756),"Member Added",EventCode IN (4729,4757),"Member Removed")
| table _time, host, SubjectUserName, TargetUserName, GroupName, action
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Actor", "TargetAccount" AS "Account Changed",
    "GroupName" AS "Group", QIDNAME(qid) AS "Action",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID IN ('4728','4729','4756','4757')
    AND ("GroupName" LIKE '%Domain Admins%' OR "GroupName" LIKE '%Enterprise Admins%'
        OR "GroupName" LIKE '%Schema Admins%')
    AND username NOT LIKE '%$' AND username != 'SYSTEM'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. **Verify immediately** — any unauthorized DA membership is a critical finding
2. Remove unauthorized member: `Remove-ADGroupMember -Identity "Domain Admins" -Members <user>`
3. Contact the person who made the change — was it authorized and ticketed?
4. Implement LAPS for local admin accounts to separate DA from workstation admin
5. Enable Protected Users security group for all DA accounts

---

## UC-173 — Password Never Expires Accounts (Newly Set) {#uc-173}

**Threat:** Attacker sets the "Password Never Expires" flag on a compromised account
to prevent the password from ever being forced to change — a subtle persistence mechanism
that can exist undetected for years.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 78 |
| **MITRE** | T1098 — Account Manipulation |
| **Data Sources** | Windows Security 4738 (DC) |
| **Rule IDs** | SP-identity-006 |

### Splunk SPL

```spl
index=windows EventCode=4738
| where match(UserAccountControl,"(?i)(DONT_EXPIRE_PASSWD)")
    AND NOT match(SubjectUserName,"(?i)(SYSTEM|\$$)")
| table _time, host, SubjectUserName, TargetUserName, UserAccountControl
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Modified By", "TargetAccount" AS "Account Modified",
    "UserAccountControl" AS "UAC Change",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE EventID = '4738'
    AND "UserAccountControl" LIKE '%DONT_EXPIRE_PASSWD%'
    AND username NOT LIKE '%$' AND username != 'SYSTEM'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Audit all accounts with Password Never Expires: `Get-ADUser -Filter {PasswordNeverExpires -eq $true}`
2. Remove the flag from all accounts that shouldn't have it
3. Service accounts with Password Never Expires should be replaced with gMSA
4. Implement a scheduled audit to detect new Password Never Expires accounts monthly
5. Correlate with other account manipulation events for the same target account

---

## UC-174 — Entra ID / Azure AD Privileged Role Assigned {#uc-174}

**Threat:** A high-privilege Azure AD role (Global Administrator, Privileged Role
Administrator, Application Administrator) is assigned to a user — especially if
assigned permanently rather than via PIM (just-in-time).

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 90 |
| **MITRE** | T1098.003 — Account Manipulation: Additional Cloud Roles |
| **Data Sources** | Entra ID Audit Log |
| **Rule IDs** | SP-identity-007 |

### Splunk SPL

```spl
index=azure sourcetype="azure:aad:audit"
| where OperationName IN ("Add member to role","Add eligible member to role")
    AND match(ModifiedProperties{}.newValue,"(?i)(Global Administrator|Privileged Role Administrator|Application Administrator|Exchange Administrator|Security Administrator)")
| table _time, InitiatedBy.user.userPrincipalName, TargetResources{}.userPrincipalName, ModifiedProperties{}.newValue
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Assigned By", "TargetAccount" AS "Recipient",
    "RoleName" AS "Role Assigned", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Microsoft Azure Active Directory'
    AND "OperationName" IN ('Add member to role','Add eligible member to role')
    AND ("RoleName" LIKE '%Global Administrator%' OR "RoleName" LIKE '%Privileged Role%'
        OR "RoleName" LIKE '%Application Administrator%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Verify with the identity team — was this role assignment authorized?
2. If unauthorized: remove the role assignment immediately
3. Require PIM (just-in-time) for all Tier 0 Azure roles — no permanent assignments
4. Enable Entra ID Privileged Identity Management access reviews
5. Implement Conditional Access policy requiring phishing-resistant MFA for all admin role activations

---

## UC-175 — Guest Account Added to Privileged Azure Resource {#uc-175}

**Threat:** An Azure AD Guest (B2B external user) is added as Owner or Contributor
to a subscription, resource group, or key resource — potentially providing an
external attacker persistent privileged access.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 88 |
| **MITRE** | T1098.003 — Account Manipulation: Additional Cloud Roles |
| **Data Sources** | Azure Activity Log, Entra ID Audit |
| **Rule IDs** | SP-identity-008 |

### Splunk SPL

```spl
index=azure sourcetype="azure:activitylog"
| where OperationName="Microsoft.Authorization/roleAssignments/write"
    AND match(Properties.principalType,"(?i)(Guest|ExternalMember)")
    AND match(Properties.roleDefinitionName,"(?i)(Owner|Contributor|User Access Administrator)")
| table _time, caller, Properties.principalName, Properties.principalType, Properties.roleDefinitionName, Properties.scope
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Assigned By", "PrincipalName" AS "Guest Account",
    "RoleName" AS "Role", "Scope" AS "Resource",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Microsoft Azure'
    AND "OperationName" = 'Microsoft.Authorization/roleAssignments/write'
    AND "PrincipalType" IN ('Guest','ExternalMember')
    AND "RoleName" IN ('Owner','Contributor','User Access Administrator')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Remove the guest role assignment immediately unless verified as authorized
2. Review what the guest account accessed during the assignment period
3. Implement Azure Policy to deny Owner role assignment to guests
4. Audit all existing guest role assignments across all subscriptions
5. Enable Entra ID access reviews for guest accounts on a quarterly basis
