# Database Security — Extended

Extended database threat detection beyond UC-045. Covers xp_cmdshell, SQL injection, and privileged abuse.

**Rule packs:** `database`

---

## UC-103 — xp_cmdshell Enabled or Called {#uc-103}

**Threat:** SQL Server's `xp_cmdshell` stored procedure enables direct OS command execution
from T-SQL. Disabled by default; attackers enable it via `sp_configure` to achieve
command execution on the SQL Server host.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 95 |
| **MITRE** | T1059.003 — Command and Scripting Interpreter: Windows Command Shell |
| **Data Sources** | SQL Server Audit, MSSQL Error Log |
| **Rule IDs** | SP-database-003 |

### Splunk SPL

```spl
index=mssql sourcetype IN ("mssql:audit","mssql:errorlog","WinEventLog:Application")
| where match(Statement,"(?i)(xp_cmdshell|sp_configure.*xp_cmdshell|EXEC\s+xp_cmd)")
    OR match(Message,"(?i)(xp_cmdshell enabled|xp_cmdshell.*configuration)")
| table _time, host, db_user, Statement, Message, client_ip
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Client IP", username AS "DB User",
    "Statement" AS "SQL Statement", destinationip AS "SQL Server",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Microsoft SQL Server'
    AND (LOWER("Statement") LIKE '%xp_cmdshell%'
        OR LOWER("Statement") LIKE '%sp_configure%xp_cmdshell%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. **Zero FP** — xp_cmdshell should never be called in production
2. Disable immediately: `EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;`
3. Identify the attacker's IP and user account
4. Review Windows Event Log for commands executed via xp_cmdshell
5. Check if the SA account was used — rotate all SQL Server credentials

---

## UC-104 — Database Admin Account Created via SQL {#uc-104}

**Threat:** Attacker creates a new sysadmin-level SQL account to maintain persistent
database access, even after the original compromise vector is closed.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 92 |
| **MITRE** | T1136 — Create Account |
| **Data Sources** | SQL Server Audit, PostgreSQL pgaudit |
| **Rule IDs** | SP-database-004 |

### Splunk SPL

```spl
index=database sourcetype IN ("mssql:audit","postgresql:audit","mysql:audit")
| where match(Statement,"(?i)(CREATE\s+(LOGIN|USER|ROLE)|sp_addsrvrolemember|GRANT\s+(SYSADMIN|DBA|SUPERUSER))")
    AND NOT match(db_user,"(?i)(sa|postgres|dbo|SYSTEM)")
| table _time, host, db_user, Statement, client_ip
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Client", username AS "Executing User",
    "Statement" AS "DDL Statement", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" IN ('Microsoft SQL Server','PostgreSQL','MySQL Database')
    AND (LOWER("Statement") LIKE '%create login%' OR LOWER("Statement") LIKE '%create user%'
        OR LOWER("Statement") LIKE '%sp_addsrvrolemember%sysadmin%'
        OR LOWER("Statement") LIKE '%grant%sysadmin%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Drop the newly created account immediately
2. Identify which account created it — was it the sa account? If so, the sa account is compromised
3. Audit all database accounts: `SELECT name, type_desc, is_disabled FROM sys.server_principals`
4. Review the backup history — was the DB backed up before this change?
5. Rotate all SQL Server credentials and review connection strings in applications

---

## UC-105 — SQL Injection Burst {#uc-105}

**Threat:** Automated SQL injection attack detected via a burst of error messages
or anomalous query patterns (UNION SELECT, OR 1=1, SLEEP, WAITFOR DELAY, --).

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 85 |
| **MITRE** | T1190 — Exploit Public-Facing Application |
| **Data Sources** | Web Application Firewall, Application logs, SQL Server error log |
| **Rule IDs** | SP-database-005 |

### Splunk SPL

```spl
index=waf OR index=webserver OR index=mssql
| where match(_raw,"(?i)(UNION\s+SELECT|OR\s+1=1|OR\s+'1'='1|SLEEP\(\d+\)|WAITFOR\s+DELAY|EXEC\s*\(|CAST\s*\(.*INT|xp_cmdshell|sys\.tables|information_schema)")
| bucket _time span=5m
| stats count, dc(src_ip) as Sources, dc(uri) as Paths by dest_host, _time
| where count >= 20
| sort -count
```

### QRadar AQL

```sql
SELECT sourceip AS "Attacker IP", destinationip AS "Target Server",
    COUNT(*) AS "Injection Attempts", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Window"
FROM events WHERE "LogSourceType" IN ('Web Application Firewall','Apache HTTP Server','Microsoft IIS')
    AND (LOWER("Message") LIKE '%union select%' OR LOWER("Message") LIKE '%or 1=1%'
        OR LOWER("Message") LIKE '%sleep(%' OR LOWER("Message") LIKE '%waitfor delay%'
        OR LOWER("Message") LIKE '%information_schema%')
GROUP BY sourceip, destinationip, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(*) >= 20
LAST 1 HOURS ORDER BY "Injection Attempts" DESC
```

### Response Actions
1. Block the source IP at the WAF/firewall immediately
2. Check if any queries succeeded — review application and DB error logs
3. Check if the application uses parameterized queries or string concatenation
4. Run a DAST scan on the application to identify all injection points
5. Deploy WAF rules for SQLi patterns if not already enabled

---

## UC-106 — Database Backup Exported to External Share {#uc-106}

**Threat:** Database backup is created and copied to an external or non-standard
location (network share, cloud storage, user desktop). Common in data theft scenarios.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 82 |
| **MITRE** | T1005 — Data from Local System |
| **Data Sources** | SQL Server Audit, Sysmon Event 11 |
| **Rule IDs** | SP-database-006 |

### Splunk SPL

```spl
| union
    [search index=mssql sourcetype="mssql:audit"
     | where match(Statement,"(?i)BACKUP\s+(DATABASE|LOG)\s+.*\s+TO\s+DISK")
     | rex field=Statement "TO\s+DISK\s*=\s*'(?P<backup_path>[^']+)'"
     | where NOT match(backup_path,"(?i)^[A-Z]:\\SQLBackup|^[A-Z]:\\Backup|^[A-Z]:\\Program Files\\Microsoft SQL Server")
     | eval detection="DB Backup to Non-Standard Path"]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
     | where match(TargetFilename,"(?i)\.(bak|sql|dump|dmp)$")
         AND (match(TargetFilename,"(?i)(\\\\|\\Users\\|\\Desktop\\|\\Downloads\\)")
             OR match(TargetFilename,"(?i)^[D-Z]:"))
     | eval detection="Database File Created in Suspicious Location"]
| table _time, host, db_user, backup_path, TargetFilename, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "DB Server", username AS "DB User",
    "BackupPath" AS "Backup Destination", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Microsoft SQL Server'
    AND LOWER("Statement") LIKE '%backup database%to disk%'
    AND "BackupPath" NOT LIKE 'C:\\SQLBackup%'
    AND "BackupPath" NOT LIKE 'C:\\Backup%'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Identify where the backup was written — is it still accessible?
2. Delete the backup from the unauthorized location after forensic copy
3. Correlate with outbound transfers from the DB server
4. Restrict BACKUP DATABASE permission to the backup service account only
5. Audit SQL Server permissions: who has `db_backupoperator` or `sysadmin` access?

---

## UC-107 — Linked Server Used for Lateral Movement {#uc-107}

**Threat:** Attacker uses an existing SQL Server Linked Server to pivot to another
SQL Server instance in the network without re-authenticating.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 80 |
| **MITRE** | T1021 — Remote Services |
| **Data Sources** | SQL Server Audit |
| **Rule IDs** | SP-database-007 |

### Splunk SPL

```spl
index=mssql sourcetype="mssql:audit"
| where match(Statement,"(?i)(OPENQUERY\s*\(|EXEC\s*\(\s*@query|EXEC\s+\[.*\]\.\.|EXEC\s+AT\s+\[)")
    OR match(Statement,"(?i)(SELECT\s+\*\s+FROM\s+OPENQUERY|INSERT\s+INTO.*OPENQUERY)")
| table _time, host, db_user, Statement, client_ip, linked_server
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Source Client", username AS "DB User",
    "Statement" AS "SQL", destinationip AS "Target SQL Server",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Microsoft SQL Server'
    AND (LOWER("Statement") LIKE '%openquery%'
        OR LOWER("Statement") LIKE '%exec at%'
        OR LOWER("Statement") LIKE '%exec(%)%openquery%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Identify which linked servers are configured: `SELECT * FROM sys.servers WHERE is_linked=1`
2. Remove unused linked server connections
3. Review the credentials used for linked server connections — are they privileged?
4. Restrict linked server execution to specific accounts via EXECUTE AS
5. Log all linked server queries via SQL Server Audit

---

## UC-108 — Database Brute Force Login {#uc-108}

**Threat:** Attacker attempts rapid failed logins against a database server
(SQL Server, PostgreSQL, MySQL) from an external or unexpected host.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 88 |
| **MITRE** | T1110.001 — Brute Force: Password Guessing |
| **Data Sources** | SQL Server Error Log, PostgreSQL pg_log, MySQL error log |
| **Rule IDs** | SP-database-008 |

### Splunk SPL

```spl
index=database sourcetype IN ("mssql:errorlog","postgresql:log","mysql:error")
| where match(_raw,"(?i)(login failed|authentication failed|Access denied for user|FATAL.*password authentication failed)")
| bucket _time span=5m
| stats count, dc(client_ip) as Sources, dc(username) as Accounts by host, _time
| where count >= 20 OR Accounts >= 5
| sort -count
```

### QRadar AQL

```sql
SELECT destinationip AS "DB Server", sourceip AS "Attacker IP",
    COUNT(*) AS "Failed Logins", COUNT(DISTINCT username) AS "Accounts Tried",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Window"
FROM events WHERE "LogSourceType" IN ('Microsoft SQL Server','PostgreSQL','MySQL Database')
    AND QIDNAME(qid) LIKE '%Authentication Failed%'
GROUP BY destinationip, sourceip, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(*) >= 20
LAST 1 HOURS ORDER BY "Failed Logins" DESC
```

### Response Actions
1. Block the source IP at the firewall — databases should not be reachable from the internet
2. Enable account lockout on the database server if supported
3. Check if the sa account (MSSQL) or postgres superuser was targeted
4. Verify the database port is not exposed in security groups/ACLs
5. Implement fail2ban or equivalent for database ports on Linux

---

## UC-109 — Sensitive Table Queried by New Account {#uc-109}

**Threat:** A database account that has never previously accessed sensitive tables
(PII, payment, credentials) suddenly queries them — indicates account compromise
or insider threat.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 78 |
| **MITRE** | T1078 — Valid Accounts |
| **Data Sources** | Database audit log (pgaudit, MSSQL Audit) |
| **Rule IDs** | SP-database-009 |

### Splunk SPL

```spl
index=database sourcetype IN ("mssql:audit","postgresql:audit","mysql:audit")
| where match(table_accessed,"(?i)(users|customers|payments|passwords|credit_card|pii|ssn|personal_data)")
| stats min(_time) as FirstAccess, max(_time) as LastAccess, count by db_user, table_accessed
| where FirstAccess >= relative_time(now(),"-1d@d")
| sort FirstAccess
```

### QRadar AQL

```sql
SELECT username AS "DB User", "TableName" AS "Table",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "First Access Time"
FROM events WHERE "LogSourceType" IN ('PostgreSQL','Microsoft SQL Server')
    AND ("TableName" LIKE '%users%' OR "TableName" LIKE '%customers%'
        OR "TableName" LIKE '%payment%' OR "TableName" LIKE '%password%')
    AND username NOT IN (
        SELECT DISTINCT username FROM events
        WHERE "LogSourceType" IN ('PostgreSQL','Microsoft SQL Server')
            AND starttime < NOW()-86400000
        LAST 90 DAYS
    )
LAST 1 DAYS ORDER BY starttime ASC
```

### Response Actions
1. Verify whether the account was explicitly granted access to this table recently
2. If not expected — the account may be compromised or misused
3. Check the query itself — full table export or targeted rows?
4. Review who granted SELECT permissions on this table
5. Implement row-level security (RLS) as an additional control layer
