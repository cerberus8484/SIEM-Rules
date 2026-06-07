# HuntingThreats — Enterprise Hunt Pack

**Production-ready SIEM detection rules for Splunk, QRadar, Google SecOps, and Wazuh.**

---

## v0.2.0 — Quality Snapshot

<div class="ht-stats-grid">
  <div class="ht-stat-card">
    <span class="ht-stat-number">1029</span>
    <span class="ht-stat-label">Validated Rules</span>
  </div>
  <div class="ht-stat-card">
    <span class="ht-stat-number">28</span>
    <span class="ht-stat-label">Hunt Packs</span>
  </div>
  <div class="ht-stat-card">
    <span class="ht-stat-number">4</span>
    <span class="ht-stat-label">SIEM Platforms</span>
  </div>
  <div class="ht-stat-card">
    <span class="ht-stat-number">30</span>
    <span class="ht-stat-label">Test Fixtures</span>
  </div>
  <div class="ht-stat-card">
    <span class="ht-stat-number">0</span>
    <span class="ht-stat-label">Linter Errors</span>
  </div>
  <div class="ht-stat-card">
    <span class="ht-stat-number">0</span>
    <span class="ht-stat-label">Linter Warnings</span>
  </div>
  <div class="ht-stat-card">
    <span class="ht-stat-number">80+</span>
    <span class="ht-stat-label">MITRE Techniques</span>
  </div>
  <div class="ht-stat-card">
    <span class="ht-stat-number">12/12</span>
    <span class="ht-stat-label">MITRE Tactics</span>
  </div>
</div>

Every rule ships with a validated numeric confidence score, a MITRE ATT&CK technique, and
a severity level. Every number above is enforced by CI on every push — not self-reported.

---

## What Is This?

The **Enterprise Hunt Pack** is a curated library of detection rules for production SIEM
environments. Unlike raw rule dumps, every rule here has passed:

- **Linter validation** — required fields, ID uniqueness, format correctness
- **Confidence scoring** — numeric 0–100, severity-derived, pack-adjusted
- **Fixture testing** — at least one True Positive and one False Positive scenario

The pack covers the full MITRE ATT&CK matrix across Windows, Linux, Cloud, Container,
and speciality domains like Email, Database, VPN, and Deception.

---

## Quick Navigation

=== "First time here?"

    Start with [Getting Started](getting-started.md) to understand the directory layout,
    rule format, and how to deploy rules to your SIEM.

=== "Looking for specific rules?"

    Browse by domain in [Rule Packs](packs/index.md). Each pack page has a rule table
    with severity, confidence, and MITRE technique.

=== "Integrating into CI?"

    See [Quality Standards](quality.md) for linter usage, fixture format, and how to
    run the Rule QA Framework locally.

=== "Contributing rules?"

    Read [Rule Format](authoring/rule-format.md) and [Contribution Guide](authoring/contributing.md)
    before opening a PR. All contributions must pass `--strict` linter mode.

---

## Platform Support

| Platform | Rules | Format | Integration Guide |
|---|---|---|---|
| **Splunk** | ~987 | SPL (`.spl`) | [Splunk Guide](platforms/splunk.md) |
| **QRadar** | ~200 | AQL (`.aql`) | [QRadar Guide](platforms/qradar.md) |
| **Google SecOps** | ~100 | UDM (`.udm`) | [SecOps Guide](platforms/secops.md) |
| **Wazuh** | ~200 | KQL (`.kql`) | [Wazuh Guide](platforms/wazuh.md) |

---

## Rule Pack Overview

| Pack | Domain | Splunk | QRadar | SecOps | Wazuh |
|---|---|:---:|:---:|:---:|:---:|
| Execution | Windows process execution | OK | OK | — | — |
| Persistence | Registry, tasks, services | OK | OK | — | — |
| Defense Evasion | Injection, masquerading | OK | OK | — | — |
| Credential Access | LSASS, Kerberos, DCSync | OK | OK | — | — |
| C2 / Beaconing | Beaconing, DNS tunneling | OK | OK | — | — |
| Lateral Movement | PsExec, WMI, PTH | OK | OK | — | — |
| Discovery | AD enum, network scans | OK | OK | — | — |
| Exfiltration | DNS/HTTP exfil | OK | OK | — | — |
| Impact | Ransomware, wipers | OK | OK | — | — |
| Privilege Escalation | Token, UAC, pipes | OK | OK | — | — |
| Initial Access | Phishing, Office exploits | OK | OK | — | — |
| Cloud | AWS/Azure/M365/GCP | OK | OK | OK | OK |
| Linux | Persistence, privesc | OK | OK | — | — |
| Network | Firewall, scanning | OK | — | — | — |
| Web Application | SQLi, LFI, web shells | OK | — | — | — |
| Threat Intelligence | IOC feed matching | OK | — | — | — |
| **Identity / IAM** | Entra ID, AWS IAM, Okta | OK | OK | OK | OK |
| **Container / K8s** | Privileged pods, RBAC | OK | — | — | — |
| **DevOps / CI-CD** | Supply chain, PAT abuse | OK | — | — | — |
| **Backup / Resilience** | VSS, immutable bypass | OK | — | — | — |
| **Hypervisor / VMware** | ESXi, vCenter | OK | — | — | — |
| **Email Security** | DMARC, quishing, BEC | OK | — | — | — |
| **Database** | xp_cmdshell, SQLi | OK | — | — | — |
| **VPN / Remote Access** | Impossible travel, Tor | OK | — | — | — |
| **macOS** | LaunchAgent, TCC, SIP | OK | — | — | — |
| **DLP / Exfiltration** | Multi-vector exfil | OK | — | — | — |
| **Deception / Canary** | Honey tokens, canary docs | OK | — | — | — |
| **Correlation** | Multi-stage kill chains | OK | — | — | — |

---

## License & Attribution

MIT License — free to use, modify, and distribute.  
Built and maintained by [HuntingThreats](https://huntingthreats.de).
