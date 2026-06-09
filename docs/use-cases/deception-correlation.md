# Deception & Correlation

Use cases for canary-based detection and multi-stage correlation rules.

**Rule packs:** `deception`, `correlation`

---

## UC-046 — Canary Document Accessed {#uc-046}

**Threat:** A honeypot document placed in a high-value share is opened. Any access
is malicious — legitimate users have no reason to open these files. Zero false positives
when canary documents are properly deployed.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 99 |
| **MITRE** | T1083 — File and Directory Discovery |
| **Data Sources** | Windows Security 4663, File Server audit logs |
| **Rule IDs** | SP-deception-001, SP-deception-002 |

### Splunk SPL

```spl
index=windows EventCode=4663
| where match(ObjectName, "(?i)(canary|honey|_do_not_open|decoy|trap|lure|_beacon_)")
    OR match(ObjectName, "(?i)(_canary\.|\.canary\.|honeypot|_secret_backup_|_passwords_|_vpn_credentials_)")
| where AccessMask IN ("0x1", "0x80", "0x100")
| eval actor=SubjectUserName . "\\" . SubjectDomainName
| table _time, host, actor, ObjectName, IpAddress, AccessMask
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Source IP",
    username AS "User",
    "objectname" AS "Canary File",
    "AccessMask" AS "Access Type",
    destinationip AS "File Server",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    EventID = '4663'
    AND (
        LOWER("objectname") LIKE '%canary%'
        OR LOWER("objectname") LIKE '%honey%'
        OR LOWER("objectname") LIKE '%_do_not_open%'
        OR LOWER("objectname") LIKE '%_passwords_%'
        OR LOWER("objectname") LIKE '%_vpn_credentials_%'
    )
LAST 24 HOURS
ORDER BY starttime DESC
```

### Canary Deployment Guide

Place these files in high-value locations where an attacker would naturally browse:

```
\\fileserver\Finance\_passwords_backup_2024.xlsx
\\fileserver\IT\Admin\_vpn_credentials_old.txt
\\fileserver\HR\_employee_ssn_export.csv
C:\Users\Administrator\Documents\_secret_backup_keys.txt
```

Enable auditing on these files via Group Policy:
```
Computer Configuration → Windows Settings → Security Settings →
Advanced Audit Policy → Object Access → Audit File System: Success
```

### Response Actions

1. **No false positives** — this is a confirmed malicious access
2. Identify the user account and workstation immediately
3. Isolate the workstation — attacker is likely already inside the network
4. Check all SMB/file access in the 30 minutes before the canary trigger
5. Begin full incident response — lateral movement likely already occurred
