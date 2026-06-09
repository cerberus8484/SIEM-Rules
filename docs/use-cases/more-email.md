# Email Security — Extended

Extended email threat detection beyond UC-044. Covers BEC, impersonation, and rule-based attacks.

**Rule packs:** `email`

---

## UC-097 — BEC / CEO Impersonation Email {#uc-097}

**Threat:** Business Email Compromise where attacker sends emails impersonating senior
executives (CEO, CFO) to trick employees into wire transfers or credential disclosure.
Sender domain is spoofed or uses a lookalike domain.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 85 |
| **MITRE** | T1566.002 — Phishing: Spearphishing Link |
| **Data Sources** | Microsoft 365 Unified Audit Log, Exchange message trace |
| **Rule IDs** | SP-email-002 |

### Splunk SPL

```spl
index=o365 OR index=exchange sourcetype IN ("o365:management:activity","exchange","microsoft:365:messagetrace")
| where Operation IN ("MessageDelivered","MessageReceived","Receive")
    AND (
        (match(SenderAddress,"(?i)(ceo|cfo|president|managing.director|md@)")
            AND NOT match(SenderAddress,"(?i)@yourdomain\.com"))
        OR (match(SenderDisplayName,"(?i)(ceo|cfo|president|chief)")
            AND NOT match(SenderAddress,"(?i)@yourdomain\.com"))
    )
| table _time, SenderAddress, SenderDisplayName, RecipientAddress, Subject
| sort -_time
```

### QRadar AQL

```sql
SELECT "SenderAddress" AS "Sender", "RecipientAddress" AS "Recipient",
    "Subject" AS "Email Subject", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Microsoft Exchange'
    AND "Operation" IN ('MessageDelivered','MessageReceived')
    AND (LOWER("SenderDisplayName") LIKE '%ceo%' OR LOWER("SenderDisplayName") LIKE '%cfo%'
        OR LOWER("SenderDisplayName") LIKE '%president%')
    AND "SenderAddress" NOT LIKE '%@yourdomain.com%'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Quarantine the email and remove from all mailboxes if delivered
2. Alert the impersonated executive and relevant security/finance teams
3. If a wire transfer or credential submission was requested — check if it was completed
4. Run a mail trace to identify all recipients of this email
5. Enable DMARC enforcement on your domain to block spoofed sender domains

---

## UC-098 — Inbox Rule Deleting Security Alerts {#uc-098}

**Threat:** Compromised account creates an inbox rule to automatically delete or move
security alert emails (IT security team, helpdesk notifications, SIEM alerts) to
prevent the legitimate user from seeing them.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 88 |
| **MITRE** | T1564.008 — Hide Artifacts: Email Hiding Rules |
| **Data Sources** | Microsoft 365 Unified Audit Log |
| **Rule IDs** | SP-email-003 |

### Splunk SPL

```spl
index=o365 sourcetype="o365:management:activity"
| where Operation IN ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| where (match(Parameters,"(?i)(security|soc|helpdesk|it.alert|suspicious|phishing|breach|incident)")
    AND match(Parameters,"(?i)(DeleteMessage|MoveToFolder.*Deleted|MarkAsRead)"))
| eval actor=UserId
| table _time, actor, ClientIPAddress, Parameters
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Account", sourceip AS "Source IP",
    "Parameters" AS "Rule Details", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Microsoft Exchange'
    AND "Operation" IN ('New-InboxRule','UpdateInboxRules')
    AND (LOWER("Parameters") LIKE '%delete%' OR LOWER("Parameters") LIKE '%deleted items%')
    AND (LOWER("Parameters") LIKE '%security%' OR LOWER("Parameters") LIKE '%phishing%'
        OR LOWER("Parameters") LIKE '%soc%' OR LOWER("Parameters") LIKE '%alert%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Remove the rule immediately
2. Check what emails were deleted — review the Deleted Items folder and litigation hold
3. This strongly indicates account compromise — the attacker is maintaining access
4. Force sign-out all sessions, reset password, invalidate MFA tokens
5. Review all inbox rules on the account for other suspicious rules

---

## UC-099 — Domain Lookalike Registration Alert {#uc-099}

**Threat:** Attacker registers a domain resembling your company domain
(yourcompany-security.com, yourcornpany.com, yourcompany-ceo.com) to launch
phishing campaigns targeting your employees.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 80 |
| **MITRE** | T1566 — Phishing |
| **Data Sources** | DNS logs, Email gateway, Threat Intelligence |
| **Rule IDs** | SP-email-004 |

### Splunk SPL

```spl
index=dns OR index=proxy OR index=email_gateway
| where match(query,"(?i)(yourcompan[^.]*\.(com|net|org|io|de|co\.uk)|yourc0mpany|y0urcompany)")
    AND NOT match(query,"(?i)^yourcompany\.com$")
| stats count by query, src_ip, user
| sort -count
```

### QRadar AQL

```sql
SELECT "hostname" AS "Lookalike Domain", sourceip AS "Source",
    COUNT(*) AS "Query Count", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'DNS'
    AND ("hostname" LIKE '%yourcompany%' OR "hostname" LIKE '%yourc0mpany%')
    AND "hostname" != 'yourcompany.com'
GROUP BY "hostname", sourceip, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
LAST 24 HOURS ORDER BY "Query Count" DESC
```

### Response Actions
1. Submit the lookalike domain to your registrar, hosting provider, and ICANN for takedown
2. Warn employees about the lookalike domain via security awareness communication
3. Block the domain at DNS/proxy level: add to deny list
4. Submit to Google/Microsoft Safe Browsing feeds for browser-level blocking
5. Monitor for emails from the lookalike domain arriving at your email gateway

---

## UC-100 — External Sender with Internal Display Name {#uc-100}

**Threat:** Email arrives from an external domain but the display name matches an
internal employee name exactly — designed to trick recipients into thinking it's an
internal email. Classic BEC setup.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 82 |
| **MITRE** | T1566.001 — Phishing: Spearphishing Attachment |
| **Data Sources** | Exchange message trace, M365 Unified Audit |
| **Rule IDs** | SP-email-005 |

### Splunk SPL

```spl
| inputlookup internal_employees.csv as emp
| join DisplayName [search index=exchange OR index=o365 sourcetype IN ("exchange","o365:management:activity")
  | where Operation IN ("MessageDelivered","MessageReceived")
      AND NOT match(SenderAddress,"(?i)@yourdomain\.com")
  | rex field=SenderAddress "\"(?P<DisplayName>[^\"]+)\"\s+<"
  | table _time, DisplayName, SenderAddress, RecipientAddress, Subject]
| table _time, DisplayName, SenderAddress, RecipientAddress, Subject
| sort -_time
```

### QRadar AQL

```sql
SELECT "SenderDisplayName" AS "Display Name", "SenderAddress" AS "Real Sender",
    "RecipientAddress" AS "Recipient", "Subject" AS "Subject",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Microsoft Exchange'
    AND "Operation" = 'MessageDelivered'
    AND "SenderAddress" NOT LIKE '%@yourdomain.com%'
    AND "SenderDisplayName" IN (
        SELECT DISTINCT "DisplayName" FROM reference_sets WHERE name='Internal-Employee-Names'
    )
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Configure Exchange Transport Rules to add "EXTERNAL" header to all external emails
2. Enable display name spoofing protection in Exchange/Defender for Office
3. Quarantine the email and warn the recipient
4. Add the sender address to the block list
5. Train employees to always check the actual sender address, not just the display name

---

## UC-101 — Executable Attachment Delivered {#uc-101}

**Threat:** Email with executable attachment (.exe, .bat, .ps1, .hta, .js, .vbs, .lnk)
delivered to a user mailbox. Most mail gateways should block this but it can
bypass via password-protected archives, renamed extensions, or inline URLs.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 90 |
| **MITRE** | T1566.001 — Phishing: Spearphishing Attachment |
| **Data Sources** | Exchange message trace, Email gateway logs |
| **Rule IDs** | SP-email-006 |

### Splunk SPL

```spl
index=exchange OR index=email_gateway
| where match(AttachmentName,"(?i)\.(exe|bat|ps1|hta|js|vbs|lnk|scr|pif|cmd|dll|msi|jar|reg|vba)$")
    OR match(AttachmentName,"(?i)\.(exe|bat|ps1)\.(zip|rar|7z|gz)$")
| table _time, SenderAddress, RecipientAddress, Subject, AttachmentName, DeliveryStatus
| sort -_time
```

### QRadar AQL

```sql
SELECT "SenderAddress" AS "Sender", "RecipientAddress" AS "Recipient",
    "Subject" AS "Subject", "AttachmentName" AS "Attachment",
    "DeliveryStatus" AS "Status", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" IN ('Microsoft Exchange','Proofpoint','Mimecast')
    AND (LOWER("AttachmentName") LIKE '%.exe' OR LOWER("AttachmentName") LIKE '%.bat'
        OR LOWER("AttachmentName") LIKE '%.ps1' OR LOWER("AttachmentName") LIKE '%.hta'
        OR LOWER("AttachmentName") LIKE '%.vbs' OR LOWER("AttachmentName") LIKE '%.lnk')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Remove the email from all mailboxes: `Search-Mailbox -ContentMatchQuery "subject:..." -DeleteContent`
2. Check if the attachment was opened (correlate with Sysmon process creation on recipient's host)
3. Block the sender domain/IP at the mail gateway
4. Scan the attachment in a sandbox (any.run, VirusTotal, Hybrid Analysis)
5. Strengthen attachment filtering policy: block all executable types and archives with executables

---

## UC-102 — Phishing Link Clicked (Internal Alert) {#uc-102}

**Threat:** User clicked a link in a phishing email, connecting to a known phishing domain,
credential harvester, or malware distribution site. Detectable via proxy/DNS logs.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 88 |
| **MITRE** | T1566.002 — Phishing: Spearphishing Link |
| **Data Sources** | Web proxy logs, DNS logs, M365 ATP click telemetry |
| **Rule IDs** | SP-email-007 |

### Splunk SPL

```spl
| union
    [search index=proxy
     | where match(dest_host,"(?i)(phish|credential.harvest|malware.download|fake.login)")
         OR category IN ("phishing","malware","suspicious")
     | eval detection="Proxy Block - Phishing"]
    [search index=o365 sourcetype="o365:management:activity"
     | where Operation="AtpDetonationCompleted" OR (Operation="SafeLinksAction" AND Verdict="Blocked")
     | eval detection="ATP Safe Links Block"]
| table _time, src_ip, user, dest_host, category, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "User Host", username AS "User",
    "hostname" AS "Phishing Site", "URLCategory" AS "Category",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Web Proxy'
    AND ("URLCategory" IN ('Phishing','Malware','Suspicious','CredentialHarvesting')
        OR "Action" = 'Blocked')
    AND "URLCategory" NOT IN ('Shopping','Social Media')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Check if credentials were submitted — review what page was shown (login form?)
2. If credentials entered: reset password immediately and revoke all sessions
3. Scan the endpoint for any malware drop from the visit (Sysmon Event 11)
4. Run endpoint AV scan and check for browser extension installations
5. Report the phishing URL to your email gateway provider's threat intel team
