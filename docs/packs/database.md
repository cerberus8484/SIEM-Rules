# Database Pack

**20 rules — Splunk — SQL Server, MySQL, PostgreSQL**

The Database pack detects SQL injection in query logs, dangerous stored procedure
execution, mass data extraction, and encryption bypass attempts.

---

## Pack Summary

| Property | Value |
|---|---|
| Pack Directory | `database/` |
|  ID Range | SP-760001 – SP-760020 |
| Platforms | Splunk |
| Rules | 20 |
| Key Sources | mssql:audit, mysql:general_query, pgsql:log |
| MITRE Tactics | Execution, Exfiltration, Impact |

---

## Rule Inventory

| Rule ID | Name | Severity | Confidence | Technique |
|---|---|---|---|---|
| SP-760001 | xp_cmdshell Enabled or Executed | CRITICAL | 95 | T1059.003 |
| SP-760002 | SQL Injection Pattern in Query Log | CRITICAL | 88 | T1190 |
| SP-760003 | Mass SELECT from Sensitive Table | HIGH | 80 | T1213 |
| SP-760004 | TDE Encryption Disabled | CRITICAL | 92 | T1486 |
| SP-760005 | Database Backup to Unexpected Location | HIGH | 82 | T1048 |
| SP-760006 | SA (sysadmin) Account Login | CRITICAL | 90 | T1078 |
| SP-760007 | Linked Server Created | HIGH | 78 | T1021 |
| SP-760008 | SQL Server Agent Job Modified | HIGH | 80 | T1053 |
| SP-760009 | Sensitive Data Exported via bcp | HIGH | 85 | T1048 |
| SP-760010 | DB Audit Log Cleared | CRITICAL | 92 | T1070 |
| SP-760011 | New Database User Created | MEDIUM | 65 | T1136 |
| SP-760012 | DBCC TRACEON Command Executed | HIGH | 78 | T1059 |
| SP-760013 | Stored Procedure Accessing OS (OLE Automation) | CRITICAL | 90 | T1059 |
| SP-760014 | Database Role Granted to Guest | HIGH | 85 | T1078 |
| SP-760015 | MySQL FILE Privilege Abused | HIGH | 82 | T1083 |
| SP-760016 | PostgreSQL COPY TO (File Write) | HIGH | 85 | T1083 |
| SP-760017 | Database Service Account Password Reset | HIGH | 80 | T1098 |
| SP-760018 | Large Result Set to Client (>10MB) | MEDIUM | 65 | T1213 |
| SP-760019 | Database Schema Enumeration | MEDIUM | 62 | T1082 |
| SP-760020 | Ransomware: Database Files Renamed | CRITICAL | 92 | T1486 |

---

## Test Fixtures

| Fixture | Type | Scenario |
|---|---|---|
| `tp_xp_cmdshell_enabled.json` | TRUE POSITIVE | xp_cmdshell enabled via sp_configure then EXEC xp_cmdshell |
| `fp_dba_maintenance.json` | FALSE POSITIVE | DBA enables xp_cmdshell in approved maintenance window |
