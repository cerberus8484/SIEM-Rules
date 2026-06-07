# Changelog

All notable changes to the HuntingThreats Enterprise Hunt Pack are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [v0.1.0] — 2026-06-07

### Summary

First production-ready release of the Enterprise Hunt Pack.  
~1,500 detection rules across 28 packs, 4 SIEM platforms, with full Rule QA Framework.

### Rule Packs Added

#### A–F: Windows / Cloud / Linux Foundation
- **Execution** — PowerShell, LOLBins (mshta/regsvr32/certutil), WMI, Office Macro chains
- **Persistence** — Registry Run keys, Scheduled Tasks, Services, COM hijack
- **Defense Evasion** — Process injection (hollowing, APC, reflective DLL), masquerading, AMSI bypass
- **Credential Access** — LSASS dump (Mimikatz/procdump), DCSync, Kerberoasting, AS-REP roasting
- **Command & Control** — Beaconing detection, DNS tunneling, non-standard C2 ports
- **Lateral Movement** — PsExec, WMI remote exec, Pass-the-Hash, RDP abuse
- **Discovery** — AD enumeration (BloodHound/ldapsearch), network scans, Group Policy reads
- **Exfiltration** — Large POST, DNS exfil patterns, cloud storage uploads
- **Impact** — Ransomware execution indicators, wiper patterns, mass service kill
- **Privilege Escalation** — Token manipulation, UAC bypass, named pipe impersonation
- **Initial Access** — Spearphishing, drive-by, Office exploit chains
- **Cloud (AWS/Azure/M365/GCP)** — CloudTrail anomalies, Azure AD events, M365 admin actions, GCP IAM
- **Linux** — Persistence (crontab, systemd unit), privesc (SUID, sudo), evasion (timestomping, log clear)
- **Network** — Firewall policy changes, port scanning, protocol abuse
- **Web Application** — SQLi, LFI/RFI, RCE, WAF evasion, web shell indicators
- **Threat Intelligence** — IOC feed matching (IP/domain/hash), TI correlation rules

#### G–R: Enterprise Specialty Packs
- **Identity / IAM (G)** — Entra ID (20 rules), AWS IAM (20 rules), Okta (20 rules), Generic IdP (15 rules); 4-platform coverage (Splunk + QRadar + SecOps + Wazuh)
- **Container / Kubernetes (H)** — 20 K8s audit rules: privileged pods, RBAC wildcard, container escape, API server abuse
- **DevOps / CI-CD (I)** — 20 rules: GitHub Actions workflow manipulation, supply chain, PAT abuse, force push
- **Backup / Resilience (J)** — 20 rules: VSS deletion, backup service kill, immutable storage bypass, ransomware prep chains
- **Hypervisor / VMware (K)** — 20 rules: ESXi SSH, vCenter SAML tampering, ESXiArgs ransomware indicator (confidence 95)
- **Email Security (L)** — 20 rules: DMARC/SPF fail, macro attachments, lookalike domains, QR code quishing, BEC chain
- **Database (M)** — 20 rules: xp_cmdshell (confidence 95), SQL injection in query log, mass SELECT, TDE disabled
- **VPN / Remote Access (N)** — 20 rules: impossible travel, Tor source, concurrent sessions, ZTNA policy change
- **macOS (O)** — 20 rules: LaunchAgent/Daemon, TCC database modified (CRITICAL), Gatekeeper/SIP disabled
- **DLP / Exfiltration (P)** — 20 rules: multi-vector exfil chain, DNS tunneling (>50 char subdomain), rclone to external
- **Deception / Canary (Q)** — 15 rules: canary docs, honey credentials, AWS honey tokens, honeypot RDP/SSH; confidence 97–98
- **Correlation / Multi-Stage Kill Chain (R)** — 20 rules: ATO chain, ransomware prep chain, C2 beacon chain, BEC chain, full kill chain scorer (risk score formula)

#### Analyst Queries
- 200 ad-hoc hunt queries across Splunk, QRadar, SecOps, Wazuh

### Rule QA Framework (S-Block)

- **S1** `schema/rule_metadata.yaml` — Canonical metadata schema: required fields, ID namespaces, severity/confidence guide
- **S2** `tools/rule_linter.py` — Python rule validator: required fields, severity/confidence, ID uniqueness, placeholder detection; `--json/--strict/--platform` CLI
- **S3** `tests/fixtures/` — 11 synthetic test events (TP + FP) for identity, backup, container, correlation, deception (Splunk + Wazuh)
- **S4** `tools/coverage_matrix.py` — Generates `COVERAGE.md` + `coverage.json` with tactic heatmap, severity distribution, technique coverage
- **S5** `README.md` — Complete authoring guide, platform integration docs, ID namespace reference

### CI / Release Infrastructure (T-Block)

- **T1/T2** `.github/workflows/ci.yml` — Rule linter + coverage matrix check on every push/PR
- **T3** `tools/fixture_validator.py` — CI gate: validates fixture rule_ids against rule files
- **T4** `tools/release_package.py` — Builds per-platform ZIP archives with SHA-256 checksums
- **T5** `CHANGELOG.md` — This file; `v0.1.0` tag

### Platform Coverage

| Platform | Rules | Notes |
|---|---|---|
| Splunk SPL | ~987 | Full pack coverage (A–R) |
| QRadar AQL | ~200 | Core packs A–F + Identity/Cloud |
| Google SecOps UDM | ~100 | Cloud + Identity packs |
| Wazuh KQL | ~200 | Identity/IAM full coverage + core packs |

### Statistics

- Total rule files: 81
- Unique MITRE techniques covered: 80+
- MITRE tactics covered: 12 / 12
- Test fixtures: 11 (TP + FP pairs)

---

## [Unreleased]

### Planned

- QRadar AQL equivalents for H–R packs (currently Splunk-only)
- Google SecOps UDM for H–R packs
- More test fixtures (target: 1 TP + 1 FP per pack minimum)
- Rule status lifecycle enforcement (`experimental` → `testing` → `stable`)
- SBOM integration for DevOps pack
- Pro-tier: API endpoint for live rule updates

---

[v0.1.0]: https://github.com/cerberus8484/SIEM-Rules/releases/tag/v0.1.0
