# C2 & Beaconing — Extended

Extended C2 detection beyond UC-027–030. Covers LOLBin C2, cloud-based C2, and domain fronting.

**Rule packs:** `correlation`

---

## UC-139 — C2 via Living-Off-the-Land Binary {#uc-139}

**Threat:** Attacker uses legitimate Windows binaries (bitsadmin, certutil, msiexec,
regsvr32, rundll32, wmic) to download or execute C2 payloads, bypassing
application whitelisting.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 85 |
| **MITRE** | T1218 — System Binary Proxy Execution |
| **Data Sources** | Sysmon Event 1/3, Windows Security 4688 |
| **Rule IDs** | SP-c2-001 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| where (EventCode=3 AND match(Image,"(?i)(bitsadmin|certutil|msiexec|regsvr32|rundll32|wmic|cscript|wscript|mshta)\.exe")
    AND Initiated="true"
    AND NOT match(DestinationIp,"(?i)^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)"))
OR (EventCode=1 AND match(CommandLine,"(?i)(bitsadmin.*\/transfer|certutil.*-(urlcache|decode)|regsvr32.*\/s.*http|rundll32.*,.*javascript|wmic.*call.*create)"))
| table _time, host, user, Image, CommandLine, DestinationIp, DestinationPort
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "process" AS "LOLBin", "DestinationAddress" AS "C2 IP",
    "Command" AS "CommandLine", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Network connection detected'
    AND LOWER("process") IN ('bitsadmin.exe','certutil.exe','regsvr32.exe','rundll32.exe',
        'mshta.exe','wmic.exe','cscript.exe','wscript.exe')
    AND "Initiated" = 'true'
    AND "DestinationAddress" NOT LIKE '10.%' AND "DestinationAddress" NOT LIKE '192.168.%'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Identify the external IP and check threat intelligence
2. Determine the full command line to understand what payload was fetched
3. Block the destination IP and domain at the firewall/proxy
4. Check for any downloaded payload on disk (Sysmon Event 11)
5. Apply ASR rules to block LOLBin abuse from Office processes

---

## UC-140 — C2 via Cloud Storage API {#uc-140}

**Threat:** Attacker routes C2 communications through legitimate cloud APIs
(S3, Azure Blob, Google Drive, Dropbox API) to blend with normal business traffic
and bypass URL category filtering.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 72 |
| **MITRE** | T1102 — Web Service: Bidirectional Communication |
| **Data Sources** | Proxy logs, DNS logs, Sysmon Event 3 |
| **Rule IDs** | SP-c2-002 |

### Splunk SPL

```spl
index=proxy OR index=dns
| where match(dest_host,"(?i)(s3\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com|api\.dropboxapi\.com|graph\.microsoft\.com)")
| stats count, sum(bytes_out) as TotalOut, sum(bytes_in) as TotalIn by src_ip, dest_host, user
| where TotalOut >= 1048576 AND TotalIn >= 1048576
| eval ratio=round(TotalOut/TotalIn, 2)
| where ratio BETWEEN 0.5 AND 2.0
| sort -TotalOut
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "hostname" AS "Cloud Provider",
    SUM(CAST("BytesOut" AS BIGINT)) / 1024 AS "KB Out",
    SUM(CAST("BytesIn" AS BIGINT)) / 1024 AS "KB In",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Web Proxy'
    AND ("hostname" LIKE '%s3.amazonaws.com%' OR "hostname" LIKE '%blob.core.windows.net%'
        OR "hostname" LIKE '%storage.googleapis.com%' OR "hostname" LIKE '%dropboxapi.com%')
GROUP BY sourceip, username, "hostname", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING SUM(CAST("BytesOut" AS BIGINT)) >= 1048576 AND SUM(CAST("BytesIn" AS BIGINT)) >= 1048576
LAST 24 HOURS ORDER BY "KB Out" DESC
```

### Response Actions
1. Identify the specific bucket/blob/drive resource being accessed
2. Examine the content if accessible — does it look like C2 tasking?
3. Correlate with process name making the connection (should be specific app, not generic)
4. Correlate with other C2 indicators: periodic beaconing, low unique IPs
5. Consider CASB to inspect cloud API traffic for C2 patterns

---

## UC-141 — Domain Fronting via CDN {#uc-141}

**Threat:** Attacker uses a CDN (Cloudflare, Fastly, AWS CloudFront) where the SNI/Host header
in the request points to a legitimate domain but the backend request goes to the C2 server.
The proxy sees traffic to e.g. `www.microsoft.com` but it reaches the attacker's backend.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 68 |
| **MITRE** | T1090.004 — Proxy: Domain Fronting |
| **Data Sources** | Proxy logs, TLS inspection logs |
| **Rule IDs** | SP-c2-003 |

### Splunk SPL

```spl
index=proxy
| where match(dest_host,"(?i)(cloudfront\.net|fastly\.net|azureedge\.net|akamaihd\.net)")
    AND match(http_host,"(?i)(microsoft|google|amazon|cloudflare|office365)")
    AND dest_host!=http_host
| stats count, sum(bytes_out) as TotalOut by src_ip, dest_host, http_host, user
| where TotalOut >= 102400
| sort -TotalOut
```

### QRadar AQL

```sql
SELECT sourceip AS "Client", "destinationHostname" AS "SNI Domain",
    "HTTPHost" AS "HTTP Host Header", SUM(CAST("BytesOut" AS BIGINT)) / 1024 AS "KB",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Web Proxy'
    AND "destinationHostname" LIKE '%.cloudfront.net%'
    AND "HTTPHost" NOT LIKE '%.cloudfront.net%'
    AND "destinationHostname" != "HTTPHost"
GROUP BY sourceip, "destinationHostname", "HTTPHost", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING SUM(CAST("BytesOut" AS BIGINT)) >= 102400
LAST 24 HOURS ORDER BY "KB" DESC
```

### Response Actions
1. This technique evades most URL filtering — requires TLS inspection to detect reliably
2. Identify the backend IP by resolving the CDN hostname
3. If TLS inspection is not available, look for behavioral indicators (beaconing pattern)
4. Block the specific CDN subdomain/path if identifiable
5. Enable TLS/SSL inspection at the proxy for high-risk categories

---

## UC-142 — Fast-Flux DNS (C2 Infrastructure) {#uc-142}

**Threat:** Attacker's C2 domain rapidly cycles through many different IP addresses (fast-flux)
to evade IP blocklists and complicate takedown. Detectable by unusually low TTL
and rapidly changing DNS resolution results.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 78 |
| **MITRE** | T1568.001 — Dynamic Resolution: Fast Flux DNS |
| **Data Sources** | DNS logs, Sysmon Event 22 |
| **Rule IDs** | SP-c2-004 |

### Splunk SPL

```spl
index=dns sourcetype IN ("cisco:umbrella","windows:dns","bind:query")
| stats dc(answer) as UniqueIPs, values(answer) as IPs, min(ttl) as MinTTL by query, src_ip
| where UniqueIPs >= 5 AND MinTTL <= 300
| sort -UniqueIPs
```

### QRadar AQL

```sql
SELECT "QueryDomain" AS "Domain", COUNT(DISTINCT "Answer") AS "Unique IPs",
    MIN(CAST("TTL" AS INTEGER)) AS "Min TTL",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'DNS'
    AND "Answer" != 'NXDOMAIN'
GROUP BY "QueryDomain", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(DISTINCT "Answer") >= 5 AND MIN(CAST("TTL" AS INTEGER)) <= 300
LAST 6 HOURS ORDER BY "Unique IPs" DESC
```

### Response Actions
1. Block the fast-flux domain in your DNS resolver (RPZ/blocklist)
2. Check which internal hosts resolved the domain and initiated connections
3. Submit the domain to threat intelligence platforms for tracking
4. Look for other fast-flux domains queried by the same hosts
5. Enable Protective DNS (e.g., Cisco Umbrella, NextDNS) for threat-intel-based blocking
