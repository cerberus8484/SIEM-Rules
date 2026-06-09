# Correlation Rules — Extended

Multi-stage attack chain detection beyond UC-046. Combines signals across multiple data sources.

**Rule packs:** `correlation`

---

## UC-156 — Full Attack Chain: Recon → Cred → Lateral → DC {#uc-156}

**Threat:** Complete AD attack kill chain: Initial reconnaissance → credential theft →
lateral movement → domain controller compromise. Correlating all four stages from the
same source provides near-zero FP confidence.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 98 |
| **MITRE** | T1087+T1003+T1021+T1003.006 — Multi-Stage AD Attack |
| **Data Sources** | Sysmon, Windows Security (all stages) |
| **Rule IDs** | SP-correlation-001 |

### Splunk SPL

```spl
| union
    [search index=windows (EventCode=1 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
     | where match(CommandLine,"(?i)(nltest|Get-ADDomainController|BloodHound|SharpHound)")
     | eval stage="1_recon", host_key=host | table _time, host_key, stage, user]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
     | where match(TargetImage,"(?i)lsass\.exe") AND match(GrantedAccess,"0x1010|0x1410|0x143A")
     | eval stage="2_cred_theft", host_key=host | table _time, host_key, stage, user]
    [search index=windows EventCode=4624
     | where LogonType=3 AND NOT match(TargetUserName,"(?i)(\$$)")
     | eval stage="3_lateral", host_key=WorkstationName | table _time, host_key, stage, user=SubjectUserName]
    [search index=windows EventCode=4662
     | where match(ObjectName,"(?i)(1131f6aa|9923a32a|DS-Replication)")
     | eval stage="4_dcsync", host_key=host | table _time, host_key, stage, user=SubjectUserName]
| bucket _time span=2h
| stats dc(stage) as StageCount, values(stage) as Stages by user, _time
| where StageCount >= 3
| sort -StageCount
```

### QRadar AQL

```sql
SELECT username AS "Attacker", COUNT(DISTINCT "stage") AS "Stages Completed",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Chain Window"
FROM (
    SELECT username, '1_recon' AS stage, starttime FROM events
        WHERE QIDNAME(qid) = 'Sysmon - Process creation' AND LOWER("Command") LIKE '%sharphound%'
    UNION
    SELECT username, '2_lsass' AS stage, starttime FROM events
        WHERE QIDNAME(qid) = 'Sysmon - Process accessed' AND LOWER("TargetImage") = 'lsass.exe'
    UNION
    SELECT username, '3_lateral' AS stage, starttime FROM events
        WHERE EventID = '4624' AND "LogonType" = '3'
    UNION
    SELECT username, '4_dcsync' AS stage, starttime FROM events
        WHERE EventID = '4662' AND "ObjectType" LIKE '%domainDNS%'
    LAST 2 HOURS
) combined
GROUP BY username, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(DISTINCT "stage") >= 3
LAST 2 HOURS ORDER BY "Stages Completed" DESC
```

### Response Actions
1. **Full IR immediately** — multi-stage AD attack chain is in progress
2. Isolate all identified hosts from the network
3. Begin DFIR engagement — forensic preservation of all involved hosts
4. Reset krbtgt password (twice if DCSync confirmed)
5. Activate IR playbook — domain-wide password reset may be required

---

## UC-157 — Brute Force then Successful Login {#uc-157}

**Threat:** An account experiences multiple failed logins followed shortly by a
successful one from the same source — the classic "brute force succeeded" pattern.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 93 |
| **MITRE** | T1110 — Brute Force |
| **Data Sources** | Windows Security 4625/4624 |
| **Rule IDs** | SP-correlation-002 |

### Splunk SPL

```spl
| join type=inner TargetUserName
    [search index=windows EventCode=4625
     | bucket _time span=30m
     | stats count as Failures, min(_time) as StartFailure by TargetUserName, IpAddress, _time
     | where Failures >= 5]
    [search index=windows EventCode=4624 LogonType IN (3, 10)
     | table TargetUserName, IpAddress, _time]
| where _time >= StartFailure AND _time <= StartFailure + 1800
| table _time, TargetUserName, IpAddress, Failures
| sort -Failures
```

### QRadar AQL

```sql
SELECT username AS "Account", sourceip AS "Source",
    COUNT(*) AS "Failures Before Success",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Success Time"
FROM events WHERE EventID = '4624'
    AND sourceip IN (
        SELECT DISTINCT sourceip FROM events WHERE EventID = '4625'
            AND starttime > NOW()-1800000 AND COUNT(*) >= 5
        LAST 30 MINUTES GROUP BY sourceip HAVING COUNT(*) >= 5
    )
LAST 30 MINUTES ORDER BY starttime DESC
```

### Response Actions
1. **Force logout** the session immediately
2. Reset the account password
3. Review what was accessed during the successful session
4. Block the source IP
5. Enable Smart Lockout with MFA enforcement

---

## UC-158 — Recon then Lateral Movement (Same Host) {#uc-158}

**Threat:** Host that ran reconnaissance commands (BloodHound, net commands, nmap)
shortly afterward initiates lateral movement (PsExec, WMI, RDP) — confirms that
the recon was performed to support active attack planning.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 88 |
| **MITRE** | T1087 + T1021 |
| **Data Sources** | Sysmon, Windows Security |
| **Rule IDs** | SP-correlation-003 |

### Splunk SPL

```spl
| union
    [search index=windows (EventCode=1 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
     | where match(CommandLine,"(?i)(BloodHound|SharpHound|nmap|nltest|net\s+group|Get-ADUser)")
     | eval stage="recon" | table _time, host, user, stage]
    [search index=windows (EventCode IN (4688, 7045, 4624) OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (1, 17))
     | where match(CommandLine,"(?i)(psexec|wmic.*process.*call|winrm|net use)") OR EventCode=7045
     | eval stage="lateral" | table _time, host, user, stage]
| stats min(eval(if(stage=="recon",_time,null()))) as ReconTime, min(eval(if(stage=="lateral",_time,null()))) as LateralTime by host, user
| where isnotnull(ReconTime) AND isnotnull(LateralTime) AND LateralTime > ReconTime AND LateralTime - ReconTime < 3600
| eval TimeDelta=LateralTime - ReconTime
| sort TimeDelta
```

### QRadar AQL

```sql
SELECT h1.sourceip AS "Host", h1.username AS "User",
    DATEFORMAT(h1.starttime,'yyyy-MM-dd HH:mm:ss') AS "Recon Time",
    DATEFORMAT(h2.starttime,'yyyy-MM-dd HH:mm:ss') AS "Lateral Movement Time"
FROM events h1, events h2
WHERE h1.sourceip = h2.sourceip AND h1.username = h2.username
    AND LOWER(h1."Command") LIKE '%sharphound%'
    AND (LOWER(h2."Command") LIKE '%psexec%' OR LOWER(h2."Command") LIKE '%wmic%process%call%')
    AND h2.starttime > h1.starttime AND h2.starttime < h1.starttime + 3600000
LAST 2 HOURS ORDER BY h1.starttime DESC
```

### Response Actions
1. Isolate the source host immediately
2. Treat all hosts visited during lateral movement as potentially compromised
3. Begin full IR — recon + lateral from same host implies active attacker presence
4. Check what the recon revealed and plan defensive response accordingly
5. Rotate credentials for all accounts accessed on lateral movement targets

---

## UC-159 — BEC Attack Chain {#uc-159}

**Threat:** Business Email Compromise chain: external phishing email → inbox forwarding rule
created → outbound financial request emails detected. Combines email and identity signals.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 92 |
| **MITRE** | T1566.001 + T1114.003 + T1078 |
| **Data Sources** | Exchange Audit, M365 Unified Log |
| **Rule IDs** | SP-correlation-004 |

### Splunk SPL

```spl
| union
    [search index=o365 sourcetype="o365:management:activity"
     | where Operation IN ("New-InboxRule","UpdateInboxRules")
         AND match(Parameters,"(?i)(ForwardTo|RedirectTo)")
     | eval stage="1_forward_rule" | table _time, UserId, stage]
    [search index=o365 sourcetype="o365:management:activity"
     | where Operation IN ("Send","SendAs")
         AND match(Subject,"(?i)(invoice|payment|wire.*transfer|urgent|W-2|payroll)")
     | eval stage="2_financial_email" | table _time, UserId, stage]
| stats dc(stage) as Stages, values(stage) as StageList by UserId
| where Stages >= 2
| sort -Stages
```

### QRadar AQL

```sql
SELECT username AS "Compromised Account", COUNT(DISTINCT "stage") AS "BEC Stages",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM (
    SELECT UserId AS username, 'forward_rule' AS stage, starttime FROM events
        WHERE "Operation" IN ('New-InboxRule','UpdateInboxRules') AND "Parameters" LIKE '%ForwardTo%'
    UNION
    SELECT UserId AS username, 'financial_send' AS stage, starttime FROM events
        WHERE "Operation" = 'Send' AND ("Subject" LIKE '%invoice%' OR "Subject" LIKE '%payment%')
    LAST 24 HOURS
) bec_chain
GROUP BY username, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(DISTINCT "stage") >= 2
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Immediately disable the forwarding rule and block the external forwarding address
2. Check if any financial transactions were initiated — contact Finance/Treasury
3. Force logout, reset credentials, revoke all M365 sessions
4. Run a search for all emails sent to the forwarding address
5. Notify the recipient of the financial request — "do not process this request"

---

## UC-160 — Credential Theft then Domain Controller Access {#uc-160}

**Threat:** After credential theft on a workstation, the stolen credentials are used
to authenticate to a Domain Controller — indicating the attacker has escalated to
the most critical system.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 92 |
| **MITRE** | T1003 + T1021 |
| **Data Sources** | Sysmon Event 10, Windows Security 4624 (DC) |
| **Rule IDs** | SP-correlation-005 |

### Splunk SPL

```spl
| join type=inner host
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
     | where match(TargetImage,"(?i)lsass\.exe") AND match(GrantedAccess,"0x1010|0x1410|0x143A")
     | table _time, host, user, GrantedAccess | rename _time as CredTime]
    [search index=windows EventCode=4624 LogonType=3
     | where match(TargetServerName,"(?i)(dc|domaincontroller|domain-controller)")
     | table _time, host, TargetUserName, IpAddress | rename _time as DCTime, host as DCHost]
| where DCTime > CredTime AND DCTime < CredTime + 3600
| table CredTime, DCTime, host, user, TargetUserName, DCHost
| sort CredTime
```

### QRadar AQL

```sql
SELECT h1.sourceip AS "Attacker Host", h1.username AS "Attacker",
    h2.destinationip AS "Domain Controller",
    DATEFORMAT(h1.starttime,'yyyy-MM-dd HH:mm:ss') AS "LSASS Access",
    DATEFORMAT(h2.starttime,'yyyy-MM-dd HH:mm:ss') AS "DC Logon"
FROM events h1
JOIN events h2 ON h1.username = h2.username
    AND h2.starttime > h1.starttime AND h2.starttime < h1.starttime + 3600000
WHERE QIDNAME(h1.qid) = 'Sysmon - Process accessed'
    AND h1."TargetImage" = 'lsass.exe'
    AND h2.EventID = '4624' AND h2."LogonType" = '3'
    AND h2.destinationip IN (SELECT DISTINCT ip FROM reference_sets WHERE name='DC-IP-List')
LAST 2 HOURS ORDER BY h1.starttime DESC
```

### Response Actions
1. **Critical** — attacker has progressed from workstation to domain controller
2. Immediately revoke the stolen credentials
3. Check DC Event Log for any privileged operations (GPO changes, account creation)
4. Reset krbtgt if DCSync was attempted from the DC session
5. Begin domain-wide IR — the attacker may already have persistent access

---

## UC-161 — Supply Chain Attack Indicator {#uc-161}

**Threat:** A recently updated software package (via legitimate update mechanism)
exhibits post-installation behavior consistent with backdoor activity — unexpected
network connection, process spawning, or registry changes right after the update.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 78 |
| **MITRE** | T1195.002 — Supply Chain Compromise |
| **Data Sources** | Sysmon Events 1/3/11, Windows Installer events |
| **Rule IDs** | SP-correlation-006 |

### Splunk SPL

```spl
| join type=inner host
    [search index=windows EventCode=1033
     | where match(Message,"(?i)(update|version|patch|build)")
     | eval InstallTime=_time | table host, InstallTime, Message | head 100]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
     | where Initiated="true" AND NOT match(DestinationIp,"(?i)^(10\.|192\.168\.|127\.)")
     | table _time, host, Image, DestinationIp, DestinationPort]
| where _time BETWEEN InstallTime AND InstallTime+3600
| table InstallTime, _time, host, Image, DestinationIp, DestinationPort
| sort _time
```

### QRadar AQL

```sql
SELECT "Product" AS "Updated Software", destinationip AS "C2 IP",
    destinationport AS "Port", "process" AS "Process",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Post-Update Connection"
FROM events h1
JOIN events h2 ON h1.sourceip = h2.sourceip
    AND h2.starttime > h1.starttime AND h2.starttime < h1.starttime + 3600000
WHERE h1.EventID = '1033'
    AND h2."Initiated" = 'true'
    AND h2.destinationip NOT LIKE '10.%' AND h2.destinationip NOT LIKE '192.168.%'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Isolate affected hosts immediately — supply chain backdoors spread via trusted software
2. Identify the specific software version — check vendor advisories and CISA KEV
3. Check other hosts that installed the same update version
4. Block the C2 IP/domain across the entire environment
5. Contact the software vendor and notify CISA/CERT-Bund if confirmed

---

## UC-162 — Insider Threat Pattern (Anomalous Data Access) {#uc-162}

**Threat:** Employee with access suddenly accesses significantly more data than
their historical baseline — unusual file server access volume, large email attachments,
or cloud uploads outside normal patterns. Could indicate data theft before resignation.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 70 |
| **MITRE** | T1005 — Data from Local System |
| **Data Sources** | File server audit 4663, DLP, email logs |
| **Rule IDs** | SP-correlation-007 |

### Splunk SPL

```spl
index=windows EventCode=4663
| where NOT match(SubjectUserName,"(?i)(SYSTEM|\$$)")
| bucket _time span=1d
| stats count as DailyAccessCount by SubjectUserName, _time
| eventstats avg(DailyAccessCount) as AvgAccess, stdev(DailyAccessCount) as StdDev by SubjectUserName
| where DailyAccessCount > AvgAccess + (3 * StdDev)
| sort -DailyAccessCount
```

### QRadar AQL

```sql
SELECT username AS "User",
    COUNT(*) AS "File Accesses Today",
    AVG(COUNT(*)) OVER (PARTITION BY username ORDER BY DATEFORMAT(starttime,'yyyy-MM-dd')
        ROWS BETWEEN 30 PRECEDING AND 1 PRECEDING) AS "30-Day Average",
    DATEFORMAT(starttime,'yyyy-MM-dd') AS "Date"
FROM events WHERE EventID = '4663'
    AND username NOT LIKE '%$' AND username != 'SYSTEM'
GROUP BY username, DATEFORMAT(starttime,'yyyy-MM-dd')
HAVING COUNT(*) > 3 * AVG(COUNT(*)) OVER (PARTITION BY username ORDER BY DATEFORMAT(starttime,'yyyy-MM-dd')
    ROWS BETWEEN 30 PRECEDING AND 1 PRECEDING)
LAST 1 DAYS ORDER BY "File Accesses Today" DESC
```

### Response Actions
1. Correlate with HR data — recent resignation notice, performance review, disciplinary action?
2. Check if accessed files were then uploaded (cloud storage, email, USB)
3. Preserve audit logs for potential legal proceedings
4. Engage HR and Legal before directly confronting the employee
5. Consider implementing UEBA (User and Entity Behavior Analytics) for baseline anomaly detection

---

## UC-163 — Zero-Day Proxy Exploitation Chain {#uc-163}

**Threat:** Attack chain targeting an internet-facing proxy or load balancer:
anomalous traffic pattern → exploit attempt → post-exploitation execution.
Detectable as: external IP → unusual HTTP methods/paths → internal lateral movement.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 82 |
| **MITRE** | T1190 — Exploit Public-Facing Application |
| **Data Sources** | WAF/Proxy logs, Windows Security |
| **Rule IDs** | SP-correlation-008 |

### Splunk SPL

```spl
| union
    [search index=proxy OR index=waf
     | where match(uri,"(?i)(\.\./|%2e%2e|JNDI:|exec\(|eval\(|/cgi-bin/|\.asp;\.jpg|%00)")
         AND status IN (200, 201, 301)
     | eval stage="exploit_success" | table _time, src_ip, dest_host, uri, stage]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
     | where match(ParentImage,"(?i)(w3wp|httpd|nginx|proxy|haproxy)")
         AND match(Image,"(?i)(cmd|powershell|bash|sh|python)")
     | eval stage="post_exploit" | table _time, host, Image, ParentImage, stage]
| stats dc(stage) as Stages, values(stage) as StageList by host
| where Stages >= 2
| sort -Stages
```

### QRadar AQL

```sql
SELECT destinationip AS "Web Server", "URI" AS "Exploit Path",
    "StatusCode" AS "HTTP Status", COUNT(*) AS "Attempts",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" IN ('Web Application Firewall','Apache HTTP Server','Nginx')
    AND ("URI" LIKE '%../%' OR "URI" LIKE '%jndi:%' OR "URI" LIKE '%eval(%'
        OR "URI" LIKE '%JNDI%' OR "URI" LIKE '%;%whoami%')
    AND "StatusCode" IN ('200','201','301')
GROUP BY destinationip, "URI", "StatusCode", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
LAST 24 HOURS ORDER BY "Attempts" DESC
```

### Response Actions
1. **Emergency patch deployment** if a known CVE is identified
2. Isolate the exploited web server from internal network access
3. Review web server process memory and spawned child processes
4. Check for webshells: `find /var/www -name "*.php" -newer /etc/passwd`
5. Take offline, rebuild from known-good image after forensic investigation
