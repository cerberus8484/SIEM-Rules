# QRadar Integration Guide

The Enterprise Hunt Pack provides ~200 QRadar AQL custom rules covering core Windows
packs (A–F), Identity/IAM, and Cloud. This guide covers DSM setup, custom rule
creation, and AQL query deployment.

---

## Prerequisites

- IBM QRadar SIEM 7.5+ (Community or Enterprise)
- DSMs deployed for your log sources
- `Admin` role for custom rule creation
- Network Hierarchy configured for accurate `localnetwork()` evaluation

---

## Rule File Format

QRadar rules use AQL with a structured comment header:

```sql
/* QR-700001 | AWS Root Account Console Login
   tactic=Initial Access | technique=T1078.004
   severity=CRITICAL | confidence=95
   platform=qradar | status=stable | version=1.0 */
SELECT
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS event_time,
    sourceip,
    username,
    devicetype,
    'SP-700021' AS rule_id,
    'CRITICAL'  AS severity,
    95          AS confidence
FROM events
WHERE qid = 29034512          -- AWS CloudTrail: ConsoleLogin
    AND username = 'root'
    AND LOGSOURCETYPENAME(devicetype) = 'Amazon AWS CloudTrail'
LAST 15 MINUTES
```

---

## Creating Custom Rules

1. Navigate to **Offenses → Rules → Add Rule**
2. Select **Event Rule** for event-based rules
3. Enter the rule name (e.g., `HT-QR-700001 AWS Root Login`)
4. Set **Test** conditions using the AQL-based event filter
5. Set **Actions**: Create Offense, Annotate, Email, or Custom Action
6. Set **Responses**: Link to an offense category

For AQL-based custom properties, use the **Custom Event Properties** wizard under
**Admin → Custom Event Properties**.

---

## AQL Saved Searches

Save frequently-used AQL queries for hunt operations:

1. Go to **Log Activity → Advanced Search**
2. Paste your AQL query
3. Click **Save Criteria** with a descriptive name

---

## DSM Requirements

| Pack | Required DSM | Log Source Type |
|---|---|---|
| Cloud AWS | Amazon AWS CloudTrail | `aws:cloudtrail` |
| Identity IAM (Okta) | Okta | `okta:system:log` |
| Windows | Microsoft Windows Security Event Log | `WinEventLog:Security` |
| Linux | Linux OS | `linux:audit` |
| Network | Cisco ASA | `cisco:asa` |

Install missing DSMs from **Admin → Extension Management → Auto Update**.

---

## Mapping QIDs to Rules

QRadar QIDs identify specific event types. Each AQL rule uses a `WHERE qid = XXXXXXX`
clause. Find QIDs with:

```sql
SELECT QIDNAME(qid), qid
FROM events
WHERE LOGSOURCETYPENAME(devicetype) = 'Amazon AWS CloudTrail'
    AND QIDNAME(qid) ILIKE '%ConsoleLogin%'
LAST 1 HOURS
```

---

## Tuning

Add exclusions directly in the `WHERE` clause:

```sql
WHERE qid = 29034512
    AND username = 'root'
    AND sourceip NOT IN ('10.0.0.0/8', '192.168.0.0/16')   -- trusted networks
    AND NOT (username = 'root' AND sourceip = '203.0.113.5') -- break-glass
```

---

## Limitations vs Splunk

| Feature | QRadar | Splunk |
|---|---|---|
| Multi-pack correlation | Limited (no subsearches) | Full (subsearches, join) |
| Dynamic field extraction | Via custom properties only | Flexible spath/rex |
| Available packs | A–F, Identity, Cloud | All 28 |
| Scheduled alert | Via Custom Actions | Native saved search scheduling |

QRadar AQL equivalents for packs G–R are planned for a future release.
