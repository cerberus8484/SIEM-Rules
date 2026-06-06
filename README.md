# 🛡️ SIEM Hunt Rules — Enterprise Detection Pack

> **1,500 production-ready detection rules** for 3 major SIEM platforms — mapped to 11 MITRE ATT&CK tactics.

![Rules](https://img.shields.io/badge/Rules-1500-00d4ff?style=flat-square)
![Platforms](https://img.shields.io/badge/Platforms-3-00ff88?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-11%20Tactics-ff8c00?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-556677?style=flat-square)

---

## Overview

The **HuntingThreats Enterprise Hunt Pack** is a curated collection of threat hunting and detection rules for Security Information and Event Management (SIEM) systems. Every rule is mapped to a specific [MITRE ATT&CK](https://attack.mitre.org/) technique and written for production deployment.

**What this pack is:**
- Threat hunting rules for SOC analysts
- Detection logic for known attacker techniques and tools
- Multi-platform: same coverage across all three SIEMs

**What this pack is not:**
- An antivirus or EDR replacement
- Automated response / remediation
- A guarantee of complete threat coverage

---

## Platforms

| Platform | Format | Rules | Status |
|---|---|---|---|
| **Wazuh** | XML / PCRE2 | 500 | ✅ Batch 1 |
| **QRadar** | AQL (Ariel Query Language) | 500 | ✅ Batch 1 |
| **Google SecOps** | YARA-L 2.0 (Chronicle SIEM) | 500 | ✅ Batch 1 |
| **Splunk** | SPL + CIM | 500 | 🔜 Planned |

---

## MITRE ATT&CK Coverage

| Tactic | Directory | Rules per Platform |
|---|---|---|
| Initial Access | `initial_access/` | 40 |
| Execution | `execution/` | 100 |
| Persistence | `persistence/` | 80 |
| Privilege Escalation | `privilege_escalation/` | 40 |
| Defense Evasion | `defense_evasion/` | 35 |
| Credential Access | `credential_access/` | 35 |
| Discovery | `discovery/` | 35 |
| Lateral Movement | `lateral_movement/` | 40 |
| Command & Control | `c2/` | 35 |
| Exfiltration | `exfiltration/` | 30 |
| Impact | `impact/` | 30 |
| **Total** | | **500 per platform** |

---

## Directory Structure

```
SIEM-Rules/
├── README.md
├── ARCHITECTURE.md          ← Rule architecture & design decisions
├── ARCHITECTURE.html        ← HTML version (dark theme)
├── DEVELOPER_GUIDE.md       ← How to write, test and deploy rules
├── DEVELOPER_GUIDE.html     ← HTML version (dark theme)
│
├── wazuh/                   ← Wazuh 4.x — XML / PCRE2
│   ├── initial_access/001_phishing.xml
│   ├── execution/
│   │   ├── 001_powershell.xml
│   │   ├── 002_lolbins.xml
│   │   └── 003_wmi_office.xml
│   ├── persistence/
│   │   ├── 001_registry.xml
│   │   ├── 002_scheduled_tasks.xml
│   │   └── 003_services.xml
│   ├── privilege_escalation/001_privesc.xml
│   ├── defense_evasion/001_process_injection.xml
│   ├── credential_access/001_lsass.xml
│   ├── discovery/001_enumeration.xml
│   ├── lateral_movement/001_lateral_movement.xml
│   ├── c2/001_c2_ports.xml
│   ├── exfiltration/001_exfiltration.xml
│   └── impact/001_ransomware.xml
│
├── qradar/                  ← QRadar 7.4+ — AQL
│   └── (same structure, .aql files)
│
└── secops/                  ← Google SecOps / Chronicle — YARA-L 2.0
    └── (same structure, .yaral files)
```

---

## Quick Start

### Wazuh

1. Copy rules to your Wazuh manager:
```bash
rsync -av wazuh/ user@wazuh-manager:/var/ossec/rules/huntingthreats/
chown ossec:ossec /var/ossec/rules/huntingthreats/*.xml
chmod 640 /var/ossec/rules/huntingthreats/*.xml
```

2. Register in `ossec.conf`:
```xml
<ruleset>
  <rule_dir>rules/huntingthreats</rule_dir>
</ruleset>
```

3. Reload:
```bash
/var/ossec/bin/ossec-control reload
```

**Requirements:** Wazuh 4.3+, Sysmon 13+, Script Block Logging (Event 4104) enabled.

---

### QRadar AQL

Rules are standalone AQL queries — no import required.

```
QRadar UI → Log Activity → Advanced Search → paste rule → Search
```

For persistent monitoring, save as **Custom Rule** via the CRE:
```
Offenses → Rules → Add Rule → Event → use rule condition
```

**Requirements:** QRadar 7.4+, WinCollect Agent or Microsoft Windows DSM, Sysmon 13+.

---

### Google SecOps (Chronicle SIEM)

1. Open **Security Operations → Detection Engine → Rules → New Rule**
2. Select **YARA-L 2.0**
3. Paste the rule content from `secops/<tactic>/<file>.yaral`
4. Click **Validate** → **Run Test** → **Create**

Set alerting mode:
- `LIVE` — real-time alerts (use for high-confidence rules)
- `ALERTING DISABLED` — run silent first, measure FP rate
- `RETROSPECTIVE` — historical analysis only

**Requirements:** Google SecOps / Chronicle SIEM, Sysmon → Chronicle Forwarder or Bindplane, UDM normalization enabled.

---

## Rule Format Examples

### Wazuh (XML / PCRE2)
```xml
<rule id="100001" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID" type="pcre2">^1$|^4688$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)-enc(odedcommand)?</field>
  <description>PowerShell: EncodedCommand — obfuscated execution (T1059.001)</description>
  <mitre><id>T1059.001</id></mitre>
  <group>execution,powershell,encoded,high_confidence,</group>
</rule>
```

### QRadar (AQL)
```sql
-- QR-100001 | T1059.001 | PowerShell EncodedCommand
-- Severity: High | Confidence: High
SELECT DATEFORMAT(startTime,'yyyy-MM-dd HH:mm:ss') AS EventTime,
       LOGSOURCENAME(logsourceid) AS Host, username, UTF8(payload) AS EventPayload
FROM events
WHERE (LOGSOURCETYPENAME(logsourceid) ILIKE '%Windows%'
    OR LOGSOURCETYPENAME(logsourceid) ILIKE '%Sysmon%')
  AND (UTF8(payload) ILIKE '%-EncodedCommand%' OR UTF8(payload) ILIKE '%-enc %')
LAST 1440 MINUTES;
```

### Google SecOps (YARA-L 2.0)
```yaral
rule ht_gs_100001_powershell_encoded_command {
  meta:
    rule_id         = "GS-100001"
    author          = "HuntingThreats"
    description     = "PowerShell: -EncodedCommand flag — obfuscated script execution"
    mitre_tactic    = "Execution"
    mitre_technique = "T1059.001"
    severity        = "HIGH"
    confidence      = "HIGH"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e.target.process.command_line, `(?i)-enc(odedcommand)?\s`) nocase

  condition:
    $e
}
```

---

## Rule ID Namespaces

| Tactic | ID Range | Wazuh | QRadar | Google SecOps |
|---|---|---|---|---|
| Initial Access | 110000–110999 | XML | QR-110xxx | GS-110xxx |
| Execution | 100000–100999 | XML | QR-100xxx | GS-100xxx |
| Persistence | 101000–101999 | XML | QR-101xxx | GS-101xxx |
| Privilege Escalation | 109000–109999 | XML | QR-109xxx | GS-109xxx |
| Defense Evasion | 102000–102999 | XML | QR-102xxx | GS-102xxx |
| Credential Access | 103000–103999 | XML | QR-103xxx | GS-103xxx |
| Discovery | 106000–106999 | XML | QR-106xxx | GS-106xxx |
| Lateral Movement | 105000–105999 | XML | QR-105xxx | GS-105xxx |
| C2 & Network | 104000–104999 | XML | QR-104xxx | GS-104xxx |
| Exfiltration | 107000–107999 | XML | QR-107xxx | GS-107xxx |
| Impact | 108000–108999 | XML | QR-108xxx | GS-108xxx |

---

## Design Principles

- **No panic wording** — rules detect patterns, not "malware" or "infections"
- **False-positive aware** — parent process, path and flags combined; legitimate tools explicitly excluded
- **MITRE-complete** — every rule references at least one sub-technique (T1xxx.yyy)
- **Threshold before single-event** — beaconing, scanning and brute-force always use frequency thresholds
- **Portable** — no deployment-specific custom properties or DSM mappings required

---

## Data Sources Required

| Source | Channel | Key Event IDs |
|---|---|---|
| Sysmon | `Microsoft-Windows-Sysmon/Operational` | 1, 3, 6, 7, 8, 10, 11, 13, 22, 25 |
| Windows Security | `Security` | 4624/25, 4648, 4672, 4688, 4698, 4720, 4728 |
| Windows System | `System` | 7036, 7040, 7045 |
| PowerShell | `Microsoft-Windows-PowerShell/Operational` | 4103, 4104 |

---

## Versioning

| Version | Date | Content |
|---|---|---|
| 0.1.0 | 2026-06-06 | Wazuh Batch 1 — 500 rules |
| 0.2.0 | 2026-06-06 | QRadar AQL Batch 1 — 500 rules |
| 0.3.0 | 2026-06-07 | Google SecOps YARA-L 2.0 Batch 1 — 500 rules |
| 0.4.0 | planned | Splunk SPL Batch 1 — 500 rules |
| 1.0.0 | planned | All 4 platforms — 2,000 rules + Tuning Guide |

---

## Documentation

| Document | Description |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Rule architecture, language reference, design decisions |
| [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) | How to write, test and deploy rules (all 3 platforms) |

---

## License

MIT License — free to use, modify and distribute. Attribution appreciated.

---

*By [HuntingThreats](https://huntingthreats.de) — Cybersecurity News & Tools*
