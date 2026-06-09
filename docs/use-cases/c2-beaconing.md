# C2 & Beaconing

Use cases for detecting Command & Control communication patterns.

**Rule packs:** `windows_sysmon`, `network` (correlation)

---

## UC-027 — C2 Beaconing — Periodic Outbound {#uc-027}

**Threat:** Malware beacons to a C2 server at regular intervals (jitter ±10–30%).
Detected by analyzing outbound connection frequency from unusual processes.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 78 |
| **MITRE** | T1071 — Application Layer Protocol |
| **Data Sources** | Sysmon Event 3, Firewall/Proxy logs |
| **Rule IDs** | SP-810001, SP-810002 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| where NOT match(Image, "(?i)(chrome|msedge|firefox|svchost|lsass|SearchApp)")
| bucket _time span=1h
| stats count as connections, dc(DestinationIp) as UniqueIPs, values(DestinationPort) as Ports
    by host, Image, _time
| where connections >= 10 AND UniqueIPs <= 3
| eval beacon_score=round((connections/UniqueIPs),1)
| sort -beacon_score
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Source Host",
    "process" AS "Process",
    destinationip AS "Destination IP",
    destinationport AS "Port",
    COUNT(*) AS "ConnectionCount",
    MIN(DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss')) AS "First",
    MAX(DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss')) AS "Last"
FROM events
WHERE
    "Event Category" = 'Network Connection'
    AND "process" NOT IN ('chrome.exe', 'msedge.exe', 'firefox.exe', 'svchost.exe')
GROUP BY sourceip, "process", destinationip, destinationport
HAVING COUNT(*) >= 10
LAST 1 HOURS
ORDER BY ConnectionCount DESC
```

### Response Actions

1. Identify the C2 IP — check threat intel (VirusTotal, Shodan, MISP)
2. Block the IP at firewall — monitor for failover to backup C2
3. Identify the beaconing process — dump memory for payload analysis
4. Check process parent — how was the malware installed?
5. Look for lateral movement from the beaconing host (→ UC-012, UC-013)

---

## UC-028 — DNS Tunneling {#uc-028}

**Threat:** Attacker uses DNS queries to exfiltrate data or tunnel C2 traffic.
Indicators: very long subdomains, high query frequency, unusual TXT/NULL record queries.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 82 |
| **MITRE** | T1071.004 — Application Layer Protocol: DNS |
| **Data Sources** | Sysmon Event 22, DNS Server logs |
| **Rule IDs** | SP-810003, SP-810004 |

### Splunk SPL

```spl
| union
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22
     | eval domain_len=len(QueryName)
     | where domain_len > 50 AND NOT match(QueryName, "(?i)(microsoft|windows|akamai|cloudfront|amazonaws)")
     | eval detection="Long subdomain (DGA/tunnel)"]
    [search index=dns OR index=network sourcetype IN ("dns", "stream:dns")
     | stats count by src_ip, query
     | where count >= 50
     | eval detection="High frequency DNS"]
| table _time, host, user, QueryName, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Host",
    "QueryName" AS "Domain",
    LENGTH("QueryName") AS "DomainLength",
    COUNT(*) AS "QueryCount",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    QIDNAME(qid) LIKE '%DNS%'
    AND LENGTH("QueryName") > 50
    AND "QueryName" NOT LIKE '%.microsoft.com%'
    AND "QueryName" NOT LIKE '%.windows.com%'
    AND "QueryName" NOT LIKE '%.akamaiedge.net%'
LAST 24 HOURS
ORDER BY DomainLength DESC
```

### Response Actions

1. Extract the parent domain (strip long subdomain) — check in threat intel
2. Capture a DNS packet trace for the tunnel traffic
3. Block the resolver domain at your DNS firewall
4. Check if data is being encoded in the subdomain labels (base32/hex patterns)
5. Review NXDOMAIN volume from same host — tunneling tools generate many NXDOMAINs

---

## UC-029 — Cobalt Strike Named Pipe {#uc-029}

**Threat:** Cobalt Strike Beacon uses named pipes for internal communication between
injected processes. Pipe names follow predictable patterns based on Malleable C2 profiles.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 95 |
| **MITRE** | T1090 — Proxy |
| **Data Sources** | Sysmon Events 17/18 |
| **Rule IDs** | SP-810005 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (17,18)
| where match(PipeName, "(?i)(\\msagent_|\\MSSE-|\\postex_|\\status_|\\halfduplexpipe|\\fullduplexpipe|\\mypipe-|\\meterpreter|\\empire_|\\pwshnet|\\RemCom|\\PSEXESVC|\\mimikatz)")
| eval pipe_type=case(
    match(PipeName,"(?i)\\msagent_|\\MSSE-|\\postex_|\\status_"), "Cobalt Strike default",
    match(PipeName,"(?i)\\meterpreter"), "Meterpreter",
    match(PipeName,"(?i)\\PSEXESVC"), "PsExec",
    match(PipeName,"(?i)\\mimikatz"), "Mimikatz",
    match(PipeName,"(?i)\\empire_"), "PowerShell Empire",
    1=1, "Unknown C2"
  )
| table _time, host, user, PipeName, pipe_type, Image
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Host",
    username AS "User",
    "PipeName" AS "Pipe Name",
    "process" AS "Process",
    QIDNAME(qid) AS "Event Type",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    QIDNAME(qid) IN ('Sysmon - Pipe Created', 'Sysmon - Pipe Connected')
    AND (
        LOWER("PipeName") LIKE '%msagent_%' OR LOWER("PipeName") LIKE '%msse-%'
        OR LOWER("PipeName") LIKE '%postex_%' OR LOWER("PipeName") LIKE '%status_%'
        OR LOWER("PipeName") LIKE '%meterpreter%' OR LOWER("PipeName") LIKE '%psexesvc%'
        OR LOWER("PipeName") LIKE '%mimikatz%' OR LOWER("PipeName") LIKE '%empire_%'
    )
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. **Critical** — Cobalt Strike Beacon confirmed. Begin full IR immediately
2. Identify the injected process (Image field) and the host process
3. Memory dump the process containing the beacon for payload extraction
4. Check network connections from the injected process for C2 IP
5. Cobalt Strike uses SMB beaconing internally — check for lateral movement via named pipes

---

## UC-030 — Known C2 Port Outbound {#uc-030}

**Threat:** Malware connects to standard C2 ports that have no legitimate outbound
use. Metasploit (4444), Netcat (1234, 9999), Cobalt Strike (50050), IRC botnets (6667).

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 85 |
| **MITRE** | T1571 — Non-Standard Port |
| **Data Sources** | Sysmon Event 3, Firewall logs |
| **Rule IDs** | SP-810006, SP-810007 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| where DestinationPort IN ("4444","1234","8888","9999","31337","1337","50050","8443","6667","6697","9001","9002","4899","12345")
    AND NOT match(DestinationIp, "^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)")
| eval known_tool=case(
    DestinationPort="4444", "Metasploit default",
    DestinationPort IN ("1234","9999"), "Netcat/common RAT",
    DestinationPort="31337", "Back Orifice / ElitE",
    DestinationPort="50050", "Cobalt Strike teamserver",
    DestinationPort IN ("6667","6697"), "IRC botnet",
    DestinationPort="9001", "Tor OR port",
    1=1, "Suspicious port"
  )
| table _time, host, user, Image, DestinationIp, DestinationPort, known_tool
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Source Host",
    destinationip AS "Destination IP",
    destinationport AS "Port",
    "process" AS "Process",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    destinationport IN (4444, 1234, 8888, 9999, 31337, 1337, 50050, 6667, 6697, 9001, 12345)
    AND destinationip NOT LIKE '10.%'
    AND destinationip NOT LIKE '192.168.%'
    AND destinationip NOT LIKE '172.1%'
    AND destinationip NOT IN ('127.0.0.1', '::1')
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Identify the process — is it a system binary (unusual) or unknown binary?
2. Block the destination IP and port at firewall
3. Check VirusTotal / Shodan for the destination IP
4. Look for process injection — legitimate processes should not connect to these ports
5. If Cobalt Strike port 50050: check for other team server indicators (→ UC-029)
