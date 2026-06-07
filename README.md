# HuntingThreats — Enterprise Hunt Pack

**Production-ready SIEM detection rules for Splunk, QRadar, Google SecOps, and Wazuh.**

> Focus: Threat hunting, triage, and incident response for enterprise environments.
> Not a replacement for your EDR — a force multiplier on top of it.

---

## Quick Start

```bash
# Clone
git clone https://github.com/cerberus8484/SIEM-Rules.git
cd SIEM-Rules/hunts

# Validate rules (Python 3.9+)
pip install -r tools/requirements.txt
python tools/rule_linter.py

# Generate coverage matrix
python tools/coverage_matrix.py
```

---

## Rule Packs

| Pack | Dir | Description | Splunk | QRadar | SecOps | Wazuh |
|---|---|---|---|---|---|---|
| ⚙️ Windows Execution | `splunk/execution/` | PowerShell, LOLBins, WMI, Office Macros | ✅ | ✅ | — | — |
| 🔒 Windows Persistence | `splunk/persistence/` | Registry Run, Scheduled Tasks, Services | ✅ | ✅ | — | — |
| 🛡️ Defense Evasion | `splunk/defense_evasion/` | Process Injection, Masquerading, AMSI bypass | ✅ | ✅ | — | — |
| 🔑 Credential Access | `splunk/credential_access/` | LSASS dump, DCSync, Kerberoasting | ✅ | ✅ | — | — |
| 📡 Command & Control | `splunk/c2/` | Beaconing, DNS tunneling, C2 ports | ✅ | ✅ | — | — |
| ↔️ Lateral Movement | `splunk/lateral_movement/` | PsExec, WMI remote, Pass-the-Hash | ✅ | ✅ | — | — |
| 🔍 Discovery | `splunk/discovery/` | AD enumeration, network scan, BloodHound | ✅ | ✅ | — | — |
| 📤 Exfiltration | `splunk/exfiltration/` | Large POST, DNS exfil, cloud upload | ✅ | ✅ | — | — |
| 💥 Impact | `splunk/impact/` | Ransomware execution, wiper, service kill | ✅ | ✅ | — | — |
| ⬆️ Privilege Escalation | `splunk/privilege_escalation/` | Token manipulation, UAC bypass | ✅ | ✅ | — | — |
| 🚪 Initial Access | `splunk/initial_access/` | Spearphishing, drive-by, exploit public-facing | ✅ | ✅ | — | — |
| ☁️ Cloud | `splunk/cloud/` | AWS CloudTrail, Azure AD, M365, GCP | ✅ | ✅ | ✅ | — |
| 🐧 Linux | `splunk/linux/` | Persistence, privesc, defense evasion | ✅ | — | — | — |
| 🌐 Network | `splunk/network/` | Firewall anomalies, protocol abuse | ✅ | — | — | — |
| 🕸️ Web Application | `splunk/web/` | SQLi, LFI/RFI, RCE, WAF evasion | ✅ | — | — | — |
| 🎯 Threat Intel | `splunk/threat_intel/` | IOC matching, TI feed correlation | ✅ | — | — | — |
| 👤 Identity / IAM | `splunk/identity/` | Entra ID, AWS IAM, Okta, Generic IdP | ✅ | ✅ | ✅ | ✅ |
| 📦 Container / K8s | `splunk/container/` | Kubernetes audit, container escape, RBAC | ✅ | — | — | — |
| 🔧 DevOps / CI-CD | `splunk/devops/` | GitHub Actions, supply chain, secrets in logs | ✅ | — | — | — |
| 💾 Backup / Resilience | `splunk/backup/` | VSS deletion, backup kill, ransomware prep | ✅ | — | — | — |
| 🖥️ Hypervisor / VMware | `splunk/hypervisor/` | ESXi, vCenter, Proxmox attacks | ✅ | — | — | — |
| 📧 Email Security | `splunk/email/` | DMARC fail, macro attachments, BEC | ✅ | — | — | — |
| 🗄️ Database | `splunk/database/` | SQL injection, xp_cmdshell, mass SELECT | ✅ | — | — | — |
| 🔐 VPN / Remote Access | `splunk/vpn/` | Impossible travel, concurrent sessions, ZTNA | ✅ | — | — | — |
| 🍎 macOS | `splunk/macos/` | LaunchAgent, TCC bypass, Gatekeeper disabled | ✅ | — | — | — |
| 🚨 DLP / Exfiltration | `splunk/dlp/` | Multi-vector exfil chains, staging, rclone | ✅ | — | — | — |
| 🍯 Deception / Canary | `splunk/deception/` | Canary files, honey credentials, honeypot traps | ✅ | — | — | — |
| 🔗 Correlation | `splunk/correlation/` | Multi-stage kill chains, risk scoring | ✅ | — | — | — |
| 📋 Analyst Queries | `analyst_queries/` | Ad-hoc hunt queries for live investigations | ✅ | ✅ | ✅ | ✅ |

---

## Directory Structure

```
hunts/
├── splunk/                     # Splunk SPL rules
│   ├── execution/              │  Packs A–F: Windows Execution / Persistence / C2 / ...
│   ├── persistence/            │
│   ├── defense_evasion/        │
│   ├── credential_access/      │
│   ├── c2/                     │
│   ├── lateral_movement/       │
│   ├── discovery/              │
│   ├── exfiltration/           │
│   ├── impact/                 │
│   ├── privilege_escalation/   │
│   ├── initial_access/         │
│   ├── cloud/                  │  Pack B–E: AWS, Azure, M365, GCP
│   ├── linux/                  │  Pack F: Linux
│   ├── network/                │
│   ├── web/                    │
│   ├── threat_intel/           │
│   ├── identity/               │  Pack G: Identity/IAM (Entra ID, AWS IAM, Okta)
│   ├── container/              │  Pack H: Container/Kubernetes
│   ├── devops/                 │  Pack I: DevOps/CI-CD
│   ├── backup/                 │  Pack J: Backup/Ransomware-Resilience
│   ├── hypervisor/             │  Pack K: Hypervisor/VMware/ESXi
│   ├── email/                  │  Pack L: Email Security
│   ├── database/               │  Pack M: Database
│   ├── vpn/                    │  Pack N: VPN/ZTNA/Remote Access
│   ├── macos/                  │  Pack O: macOS
│   ├── dlp/                    │  Pack P: Data Exfiltration/DLP
│   ├── deception/              │  Pack Q: Deception/Canary
│   └── correlation/            │  Pack R: Correlation/Multi-Stage Kill Chain
├── qradar/                     # QRadar AQL rules (identity + core packs)
├── secops/                     # Google SecOps UDM rules
├── wazuh/                      # Wazuh KQL rules
├── analyst_queries/            # Ad-hoc queries for live hunting (all 4 platforms)
├── playbooks/                  # Analyst response playbooks
├── schema/
│   └── rule_metadata.yaml      # S1: Canonical rule metadata schema
├── tools/
│   ├── rule_linter.py          # S2: Python rule validator
│   ├── coverage_matrix.py      # S4: Coverage matrix generator
│   └── requirements.txt
└── tests/
    └── fixtures/               # S3: Synthetic test events (TP + FP per rule)
        ├── splunk/
        └── wazuh/
```

---

## Rule ID Namespaces

| Prefix | Platform | Range | Pack |
|---|---|---|---|
| `SP-1xxxxx` | Splunk | 100000–199999 | Windows (Execution, Persistence, Evasion, ...) |
| `SP-2xxxxx` | Splunk | 200000–299999 | Cloud (AWS=200, Azure=201, M365=202, GCP=203) |
| `SP-3xxxxx` | Splunk | 300000–399999 | Linux |
| `SP-4xxxxx` | Splunk | 400000–499999 | Network Infrastructure |
| `SP-5xxxxx` | Splunk | 500000–599999 | Web Application |
| `SP-6xxxxx` | Splunk | 600000–699999 | Threat Intelligence |
| `SP-7xxxxx` | Splunk | 700000–709999 | Identity/IAM (Entra=700, AWS IAM=701, Okta=702) |
| `SP-71xxxx` | Splunk | 710000–719999 | Container / Kubernetes |
| `SP-72xxxx` | Splunk | 720000–729999 | DevOps / CI-CD |
| `SP-73xxxx` | Splunk | 730000–739999 | Backup / Resilience |
| `SP-74xxxx` | Splunk | 740000–749999 | Hypervisor / VMware |
| `SP-75xxxx` | Splunk | 750000–759999 | Email Security |
| `SP-76xxxx` | Splunk | 760000–769999 | Database |
| `SP-77xxxx` | Splunk | 770000–779999 | VPN / Remote Access |
| `SP-78xxxx` | Splunk | 780000–789999 | macOS |
| `SP-79xxxx` | Splunk | 790000–799999 | DLP / Exfiltration |
| `SP-80xxxx` | Splunk | 800000–809999 | Deception / Canary |
| `SP-81xxxx` | Splunk | 810000–819999 | Correlation / Multi-Stage |
| `QR-xxxxxx` | QRadar | same sub-ranges | QRadar AQL equivalents |
| `GS-xxxxxx` | Google SecOps | same sub-ranges | UDM Search equivalents |
| `WZ-xxxxxx` | Wazuh | same sub-ranges | KQL equivalents |
| `PB-xxx` | All | playbooks/ | Analyst Response Playbooks |
| `AQ-xxx-xxx` | All | analyst_queries/ | Live Hunt Queries |

---

## Platform Integration Guides

### Splunk

1. Copy `.spl` files from `splunk/<pack>/` to your Splunk environment
2. Create a saved search or alert for each `comment()` block
3. Each rule uses `eval rule_id=`, `tactic=`, `technique=`, `severity=`, `confidence=` fields
4. Replace `<COMPANY_DOMAIN>`, `<HONEYPOT_*>` placeholders with your actual values

```spl
`comment("SP-700001 | Identity | Entra ID Global Admin direkt zugewiesen")`
index=azure:aad:audit operationName="Add member to role"
| ...
| eval rule_id="SP-700001", tactic="Privilege Escalation", severity="CRITICAL", confidence=90
```

### QRadar AQL

1. Import `.aql` files from `qradar/<pack>/` as Custom Rules
2. AQL queries use `logsourcetypename(logsourceid) ILIKE` for log source filtering
3. Rule metadata is embedded as `/* SP-XXXXXX | ... */` comment blocks

### Google SecOps (Chronicle)

1. UDM Search queries from `secops/<pack>/` work in the Chronicle Search UI
2. Use `metadata.product_name`, `metadata.product_event_type`, `target.user.*` fields
3. Rule IDs use `GS-` prefix

### Wazuh

1. KQL queries from `wazuh/<pack>/` work in Wazuh Dashboard (OpenSearch KQL)
2. Uses `rule.groups: "azure"/"amazon"/"okta"`, `data.aws.*`, `data.okta.*` fields
3. Wazuh `rule.level` >= 10 for HIGH, >= 12 for CRITICAL

---

## Rule Quality & Linting

### Run the Linter

```bash
# Lint all rules
python tools/rule_linter.py

# JSON output for CI
python tools/rule_linter.py --json

# Strict mode (fail on warnings too)
python tools/rule_linter.py --strict

# Filter by platform or pack
python tools/rule_linter.py --platform splunk --pack identity
```

### Linter Checks

| Check | Level | Description |
|---|---|---|
| Missing `rule_id` | ERROR | Every rule block must have a rule_id |
| Missing `tactic` | ERROR | MITRE tactic required |
| Missing `severity` | ERROR | Severity must be CRITICAL/HIGH/MEDIUM/LOW/INFO |
| Missing `confidence` | ERROR | 0–100 confidence score required |
| Invalid severity value | ERROR | Must match enum |
| Confidence out of range | ERROR | Must be 0–100 |
| CRITICAL + low confidence | WARNING | CRITICAL should have confidence >= 85 |
| Duplicate rule ID | ERROR | IDs must be globally unique |
| Bug placeholder (TODO/FIXME) | WARNING | Unresolved development marker |
| Invalid ID format | WARNING | Must match SP/QR/GS/WZ-[0-9]{6,} |

### Generate Coverage Matrix

```bash
# Write COVERAGE.md + coverage.json
python tools/coverage_matrix.py

# Markdown only, print to stdout
python tools/coverage_matrix.py --md-only --stdout
```

---

## Authoring New Rules

### 1. Pick the right rule ID

See the namespace table above. Next available IDs are tracked in `schema/rule_metadata.yaml`.

### 2. Required metadata (Splunk)

```spl
`comment("SP-XXXXXX | <Pack> | <Short Title>")`
<your search>
| eval rule_id="SP-XXXXXX"
| eval tactic="<MITRE Tactic>"
| eval technique="<T-Number>"
| eval severity="<CRITICAL|HIGH|MEDIUM|LOW|INFO>"
| eval confidence=<0-100>
```

### 3. Confidence Calibration

| Confidence | When to use | Analyst action |
|---|---|---|
| 90–100 | Known bad pattern, zero/near-zero FP | Immediate escalation |
| 75–89 | Very likely malicious, rare FP | Review within 1 hour |
| 55–74 | Suspicious, some FP expected | Ticket, shift review |
| 30–54 | Weak signal, high FP rate | Log only |
| < 30 | Too noisy for production | Do not use |

### 4. Add a test fixture

Add at least one TP fixture in `tests/fixtures/splunk/<pack>/tp_<description>.json`.
For rules with known FP patterns: add `fp_<description>.json` with tuning recommendation.

### 5. Run the linter

```bash
python tools/rule_linter.py --pack <your_pack>
```

---

## MITRE ATT&CK Coverage

The hunt pack covers **all 12 MITRE ATT&CK tactics**:

| Tactic | Key Techniques |
|---|---|
| Initial Access | T1566 (Phishing), T1195 (Supply Chain), T1190 (Exploit Public App) |
| Execution | T1059 (PowerShell/Cmd), T1047 (WMI), T1204 (User Execution) |
| Persistence | T1547 (Registry Run), T1053 (Scheduled Tasks), T1543 (Services) |
| Privilege Escalation | T1134 (Token), T1548 (UAC), T1611 (Container Escape) |
| Defense Evasion | T1055 (Process Injection), T1562 (Impair Defenses), T1218 (LOLBins) |
| Credential Access | T1003 (LSASS), T1558 (Kerberoasting), T1621 (MFA Fatigue) |
| Discovery | T1087 (Account Discovery), T1069 (Permission Groups), T1046 (Netscan) |
| Lateral Movement | T1021 (Remote Services), T1550 (Pass-the-Hash) |
| Collection | T1114 (Email Collection), T1213 (Data from Repos) |
| Command & Control | T1071 (App Layer), T1095 (Non-App Layer), T1571 (Non-Standard Port) |
| Exfiltration | T1041 (Exfil over C2), T1048 (Exfil Alt Protocol), T1567 (Cloud Storage) |
| Impact | T1486 (Ransomware), T1490 (Inhibit Recovery), T1531 (Account Access Removal) |

Extended coverage (beyond Windows):
- **Identity/IAM:** T1078.004, T1556.006, T1528 (Token Theft), T1098 (Account Manipulation)
- **Cloud:** T1537, T1530, T1619 (Cloud Enumeration)
- **Container:** T1611, T1552.007 (K8s Secrets), T1543 (Container as Service)
- **Deception (Detection):** All Q-pack rules confidence 97–98 (zero FP when properly deployed)

---

## Repository Statistics

| Metric | Count |
|---|---|
| Total rule files | 81 |
| Splunk SPL rules | ~987 |
| QRadar AQL rules | ~200 |
| Google SecOps rules | ~100 |
| Wazuh KQL rules | ~200 |
| Test fixtures (TP+FP) | 11 |
| MITRE techniques covered | 80+ |
| MITRE tactics covered | 12 / 12 |

---

## License

MIT — see [LICENSE](../LICENSE).
Rules are provided as-is. Test in your environment before production deployment.

---

*Built by [HuntingThreats](https://huntingthreats.de) — Threat Hunting for the Modern SOC.*
