# Splunk Integration Guide

The Enterprise Hunt Pack provides ~987 Splunk SPL detection rules across all 28 packs.
This guide covers installation, index configuration, saved search deployment, and
tuning recommendations.

---

## Prerequisites

- Splunk Enterprise 8.2+ or Splunk Cloud
- Appropriate source data indexed (see [Data Sources](#data-sources))
- `search` capability for the service account running the rules
- Optionally: [Enterprise Security](https://splunkbase.splunk.com/app/263/) for Risk-Based Alerting

---

## Installation

### Option 1: Per-Platform ZIP

Download and extract the latest Splunk ZIP from [Releases](../releases.md):

```bash
# Download
wget https://github.com/cerberus8484/SIEM-Rules/releases/latest/download/huntingthreats-splunk-v0.2.0.zip

# Verify SHA-256
sha256sum -c huntingthreats-splunk-v0.2.0.zip.sha256

# Extract
unzip huntingthreats-splunk-v0.2.0.zip -d huntingthreats-splunk/
```

### Option 2: Clone and Run

```bash
git clone https://github.com/cerberus8484/SIEM-Rules.git
cd SIEM-Rules/splunk/
```

---

## Rule File Format

Each `.spl` file contains one or more detection rules. The rule structure:

```splunk-spl
`comment("
SP-XXXXXX | Rule Name
tactic=<MITRE Tactic> | technique=<T-number>
severity=<CRITICAL|HIGH|MEDIUM|LOW|INFO> | confidence=<0-100>
platform=splunk | status=<stable|testing|experimental> | version=<N.N>
")`
<SPL search query>
| eval rule_id="SP-XXXXXX"
| eval tactic="<tactic>", technique="<technique>"
| eval severity="<severity>", confidence=<0-100>
| table _time host user <relevant_fields> rule_id severity confidence
```

---

## Data Sources

Configure these sourcetypes in your `inputs.conf`:

| Pack | Required Sourcetypes | Index |
|---|---|---|
| Windows / Sysmon | `WinEventLog:Security`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | `windows` |
| Cloud AWS | `aws:cloudtrail` | `aws` |
| Cloud Azure | `azure:activity`, `o365:management:activity` | `azure` |
| Linux | `linux:audit`, `syslog` | `linux` |
| Identity / IAM | `okta:system:log` | `identity` |
| Container | `kubernetes:apiserver` | `kubernetes` |
| Email | `o365:management:activity`, `proofpoint:email` | `email` |
| Database | `mssql:audit`, `mysql:general_query` | `db` |
| VPN | `cisco:asa`, `paloalto:vpn` | `network` |

---

## Deploying as Saved Searches

Convert rules to Splunk saved searches via the REST API:

```python
import splunklib.client as client

service = client.connect(host="splunk.corp.local", port=8089,
                         username="admin", password="...")

with open("splunk/identity/001_iam_rules.spl") as f:
    spl = f.read()

service.saved_searches.create(
    name="HT-SP-700021-AWS-Root-Login",
    search=spl,
    **{
        "alert.severity": "2",          # CRITICAL
        "alert.type": "number of events",
        "alert.condition": "count > 0",
        "cron_schedule": "*/15 * * * *",  # every 15 minutes
        "dispatch.earliest_time": "-15m",
        "dispatch.latest_time": "now",
        "is_scheduled": "1",
        "actions": "email"
    }
)
```

---

## Scheduling Recommendations

| Severity | Recommended Schedule | Lookback |
|---|---|---|
| CRITICAL | Every 5 minutes | `-5m` |
| HIGH | Every 15 minutes | `-15m` |
| MEDIUM | Every hour | `-1h` |
| LOW / INFO | Every 4 hours or daily | `-4h` |

---

## Risk-Based Alerting (Enterprise Security)

For Splunk Enterprise Security, add rules to the Risk Index:

```splunk-spl
| eval risk_message="HT: ".rule_id." — ".severity
| eval risk_object=host, risk_object_type="system"
| eval risk_score=case(severity="CRITICAL",100,severity="HIGH",75,severity="MEDIUM",50,1=1,25)
| collect index=risk_index sourcetype=stash
```

Then use `SP-810020` (Kill Chain Scorer) to correlate individual risk events into
high-confidence kill chain findings.

---

## Tuning

### Adding Suppressions

```splunk-spl
`comment("SP-700021 — suppress for known break-glass account")`
index=aws sourcetype=aws:cloudtrail eventName=ConsoleLogin
| spath userIdentity.type | where 'userIdentity.type'="Root"
| where sourceIPAddress != "10.0.0.100"   # break-glass jump host
| where NOT match(userAgent, "AWS Internal")
```

### Global Allowlist

Create a lookup table `ht_allowlist.csv` with columns `rule_id, entity, reason` and
join it in rules:

```splunk-spl
| lookup ht_allowlist.csv rule_id, host AS entity OUTPUT reason
| where isnull(reason)
```

---

## Verifying a Rule Fires

Use `makeresults` to simulate an event and verify your rule logic:

```splunk-spl
| makeresults
| eval CommandLine="C:\\Windows\\System32\\cmd.exe /c vssadmin delete shadows /all /quiet"
| eval EventCode="4688"
<paste SP-730001 logic here>
```

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| No results despite known events | Wrong index or sourcetype | Check `index=*` first, then scope down |
| `spath` returns null | Nested JSON not extracted | Enable `KV_MODE = json` or use `spath` explicitly |
| High execution time | Broad time range or no index filter | Add earliest/latest bounds, start with index filter |
| Rule fires on legitimate activity | Missing suppression | Scope suppression to specific user/host/IP, not global |
