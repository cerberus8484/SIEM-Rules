# Email & Database

Use cases for email-based threats and database exfiltration.

**Rule packs:** `email`, `database`

---

## UC-044 — Email — Mass Internal Forwarding Rule {#uc-044}

**Threat:** After account compromise, attacker creates an inbox rule to silently
forward all emails to an external address. Enables ongoing intelligence collection
and BEC (Business Email Compromise) support.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 88 |
| **MITRE** | T1114.003 — Email Collection: Email Forwarding Rule |
| **Data Sources** | Microsoft 365 Unified Audit Log, Exchange Online |
| **Rule IDs** | SP-email-001 |

### Splunk SPL

```spl
index=o365 OR index=exchange sourcetype IN ("o365:management:activity", "exchange")
| where Operation IN ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
    AND (
        match(Parameters, "(?i)ForwardTo|RedirectTo|ForwardAsAttachmentTo")
        AND match(Parameters, "(?i)@(?!yourdomain\.com)")
    )
| eval actor=UserId, target=ObjectId
| rex field=Parameters "ForwardTo=(?P<forward_address>[^\s,]+)"
| table _time, actor, forward_address, ClientIPAddress, Parameters
| sort -_time
```

### QRadar AQL

```sql
SELECT
    username AS "Account",
    "Parameters" AS "Rule Parameters",
    "ForwardTo" AS "Forward Address",
    sourceip AS "Source IP",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    "LogSourceType" = 'Microsoft Exchange'
    AND "Operation" IN ('New-InboxRule', 'Set-InboxRule', 'UpdateInboxRules')
    AND (
        LOWER("Parameters") LIKE '%forwardto%'
        OR LOWER("Parameters") LIKE '%redirectto%'
        OR LOWER("Parameters") LIKE '%forwardasattachmentto%'
    )
    AND "ForwardTo" NOT LIKE '%@yourdomain.com%'
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Disable the forwarding rule immediately via Exchange Admin Center or PowerShell:
   `Remove-InboxRule -Identity "<rule name>" -Mailbox <user>`
2. Check what emails were already forwarded — review mail flow logs
3. Change the compromised account password and invalidate all sessions
4. Check for other rules on the same mailbox (delete all rules, re-enable legitimate ones)
5. Enable MFA on the account (→ UC-033) if not already enabled

---

## UC-045 — Database — Privileged Bulk Export {#uc-045}

**Threat:** Attacker uses a privileged database account to export large amounts of data
(SELECT * on sensitive tables, mysqldump, pg_dump, bcp). Precedes exfiltration.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 76 |
| **MITRE** | T1005 — Data from Local System |
| **Data Sources** | Database audit log (PostgreSQL pgaudit, MySQL audit, MSSQL Audit) |
| **Rule IDs** | SP-database-001, SP-database-002 |

### Splunk SPL

```spl
index=database (sourcetype="postgresql:audit" OR sourcetype="mysql:audit" OR sourcetype="mssql:audit")
| where match(statement, "(?i)SELECT\s+\*\s+FROM\s+(users|customers|accounts|passwords|credentials|pii|personal|payment|credit_card)")
    OR match(application_name, "(?i)(mysqldump|pg_dump|sqlcmd|bcp)")
    OR match(statement, "(?i)INTO\s+OUTFILE|BULK\s+INSERT|OPENROWSET")
| stats count, sum(rows_affected) as TotalRows by host, db_user, database_name, _time
| where TotalRows >= 10000
| sort -TotalRows
```

### QRadar AQL

```sql
SELECT
    sourceip AS "DB Client IP",
    username AS "DB User",
    "database" AS "Database",
    "Statement" AS "SQL Statement",
    "RowsAffected" AS "Rows",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    "LogSourceType" IN ('PostgreSQL', 'MySQL Database', 'Microsoft SQL Server')
    AND (
        (LOWER("Statement") LIKE '%select * from%'
         AND (LOWER("Statement") LIKE '%users%' OR LOWER("Statement") LIKE '%customers%'
              OR LOWER("Statement") LIKE '%payment%' OR LOWER("Statement") LIKE '%credentials%'))
        OR LOWER("application_name") IN ('pg_dump', 'mysqldump', 'sqlcmd')
        OR LOWER("Statement") LIKE '%into outfile%'
    )
    AND CAST("RowsAffected" AS INTEGER) >= 10000
LAST 24 HOURS
ORDER BY CAST("RowsAffected" AS INTEGER) DESC
```

### Response Actions

1. Identify the DB user — was this a service account or human account?
2. Check if the query originated from the application server (expected) or a new host (suspicious)
3. Check network traffic for large outbound transfers from the DB server in the same timeframe
4. Review DB user permissions — does this account need SELECT on all rows?
5. Enable row-level security (RLS) on sensitive tables to limit future blast radius
