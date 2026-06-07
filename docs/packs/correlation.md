# Correlation / Multi-Stage Kill Chain Pack

**20 rules — Splunk only — risk score formula**

The Correlation pack detects multi-stage attack chains that individual rules cannot
catch. It aggregates signals from other packs and fires when a specific sequence of
events occurs within a time window — turning individual weak signals into high-confidence
findings.

---

## Pack Summary

| Property | Value |
|---|---|
| Pack Directory | `correlation/` |
| ID Range | SP-810001 – SP-810020 |
| Platforms | Splunk |
| Rules | 20 |
| MITRE Tactics | Multiple (full kill chain) |
| Confidence | 75–95 (dynamic, risk score derived) |

---

## How Correlation Rules Work

Most SIEM rules are atomic: they evaluate a single event. Correlation rules are different —
they join events across time using `stats` / `eval` and produce a finding only when a
minimum number of correlated signals are present.

```splunk-spl
`comment("
SP-810001 | Account Takeover Chain
tactic=Credential Access | technique=T1078
severity=CRITICAL | confidence=85
platform=splunk | status=stable | version=1.0
")`
index=* sourcetype IN ("o365:management:activity","aws:cloudtrail","okta:system:log")
| eval stage=case(
    (sourcetype="okta:system:log" AND action="user.session.start" AND outcome.result="FAILURE"),
    "auth_failure",
    (sourcetype="o365:management:activity" AND Operation="UserLoginFailed"),
    "auth_failure",
    (sourcetype="okta:system:log" AND action="user.mfa.factor.activate"),
    "mfa_change",
    (sourcetype="aws:cloudtrail" AND eventName="GetCallerIdentity"),
    "aws_recon"
  )
| stats dc(stage) AS stage_count, values(stage) AS stages,
         values(sourceIPAddress) AS src_ips by user _time span=2h
| where stage_count >= 3
| eval risk_score=stage_count*25
| eval confidence=if(risk_score>=95,95,risk_score)
| eval rule_id="SP-810001", severity="CRITICAL"
```

---

## Rule Inventory

| Rule ID | Name | Severity | Confidence | Chain |
|---|---|---|---|---|
| SP-810001 | Account Takeover Chain | CRITICAL | dynamic | Auth fail → MFA change → Cloud recon |
| SP-810002 | Ransomware Prep Chain | CRITICAL | 90 | Cred dump → Lateral move → Shadow copy delete |
| SP-810003 | C2 Beacon Chain | HIGH | 82 | Encoded exec → Outbound beacon → Interval regularity |
| SP-810004 | BEC Chain | HIGH | 85 | Mailbox rules + external forward + finance access |
| SP-810005 | Full Kill Chain Scorer | CRITICAL | dynamic | All 12 tactics, risk score 0–100 |
| SP-810006 | Initial Access → Persistence | HIGH | 78 | Phishing open → Office macro → Reg run key |
| SP-810007 | Credential Harvest → Reuse | CRITICAL | 88 | LSASS dump → New auth from harvested account |
| SP-810008 | Container Escape Chain | CRITICAL | 85 | Priv pod → nsenter → Host root access |
| SP-810009 | Cloud Data Exfil Chain | HIGH | 80 | Storage discovery → Mass S3/Blob read → External copy |
| SP-810010 | DevOps Supply Chain Attack | CRITICAL | 88 | Pipeline manipulation → Build artifact modification |
| SP-810011 | Living Off the Land (LOLBin) Chain | HIGH | 78 | certutil download → regsvr32 exec → Outbound |
| SP-810012 | Insider Threat — Data Staging | HIGH | 75 | Mass file copy → Compression → USB/Cloud write |
| SP-810013 | Kerberoast → LM Chain | CRITICAL | 85 | SPN enum → AS-REP roast → Admin login |
| SP-810014 | VPN Anomaly → Lateral Move | HIGH | 80 | VPN impossible travel → New service install |
| SP-810015 | Email → Exec → Beacon | HIGH | 82 | Email attachment open → Encoded cmd → C2 |
| SP-810016 | Database → Exfil Chain | CRITICAL | 90 | xp_cmdshell enable → SQL dump → HTTPS upload |
| SP-810017 | Hypervisor Takeover Chain | CRITICAL | 90 | SSH to ESXi → SAML cert mod → VM snapshot |
| SP-810018 | Okta Session Hijack → Reuse | CRITICAL | 92 | Impossible travel → New session → Admin action |
| SP-810019 | Backup Wiper Chain | CRITICAL | 92 | VSS delete → Backup svc kill → File rename |
| SP-810020 | Multi-Source Kill Chain Scorer | CRITICAL | 85 | Risk score across all packs |

---

## Kill Chain Scorer (SP-810020)

The Kill Chain Scorer is the most comprehensive rule. It ingests risk signals from all
28 packs and computes a composite score:

```splunk-spl
`comment("
SP-810020 | Multi-Source Kill Chain Scorer
tactic=Multiple | technique=T1059/T1078/T1003/T1486
severity=CRITICAL | confidence=85
platform=splunk | status=stable | version=1.0
")`
index=risk_index
| stats sum(risk_score) AS total_risk, dc(tactic) AS tactics_seen,
         values(technique) AS techniques, values(rule_id) AS fired_rules
         by src_host user _time span=24h
| where total_risk >= 150 OR tactics_seen >= 5
| eval severity=case(total_risk>=250,"CRITICAL",total_risk>=150,"HIGH",1=1,"MEDIUM")
| eval confidence=85
| eval confidence=if(total_risk>=300,95,confidence)
| eval rule_id="SP-810020"
| table _time src_host user total_risk tactics_seen techniques fired_rules severity confidence rule_id
```

---

## Test Fixtures

| Fixture | Type | Scenario |
|---|---|---|
| `tp_correlation_ato_chain.json` | TRUE POSITIVE | 3-stage ATO: auth fail → MFA enroll → cloud recon |
| `tp_ransomware_prep_chain.json` | TRUE POSITIVE | Cred dump + lateral move + VSS delete in 4h |
| `fp_legitimate_admin_chain.json` | FALSE POSITIVE | Planned maintenance: MFA reset + admin login + backup |
| `fp_pentest_correlation.json` | FALSE POSITIVE | Authorized red team with time-boxed exemption |
