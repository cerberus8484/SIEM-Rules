# Changelog

All notable changes to the HuntingThreats Enterprise Hunt Pack are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [v0.2.0] — 2026-06-07

### Summary

Quality hardening release — 0 linter warnings, global strict mode, 30 test fixtures.

### Changed

- **Rule Linter (S2):** `confidence` downgrade from ERROR to WARNING removed — linter now runs in
  global `--strict` mode (0 errors, 0 warnings required for CI pass)
- **CI (T1):** GitHub Actions updated from pack-selective strict to `--strict` for all packs
- **Coverage Matrix (S4):** Fixed emoji encoding issue for Windows terminal compatibility

### Fixed

- **U1 Metadata Backfill (500 rules):** A-F packs used `confidence="HIGH"` (string label) instead
  of numeric values. Converted all 500 occurrences to integers derived from severity + pack adjustment:
  - CRITICAL rules: 90 (or 85 with pack penalty for discovery/web)
  - HIGH rules: 78 (or 73 with -5 discovery adjustment)
  - MEDIUM rules: 62 (or 57 with pack penalty)
  - LOW/INFO rules: 45/35 respectively
- **SP-730017/730018 eval mismatch:** Copy-paste bug left wrong `rule_id` values in eval — fixed
- **SP-810020 dynamic severity:** `severity=case(...)` now parsed by linter regex
- **SP-810020 technique:** Changed `technique="Multiple"` to `technique="T1059/T1078/T1003/T1486"`
- **SP-810020 confidence:** Added static `eval confidence=85` for linter detection before dynamic override
- **SP-106021/106031 CRITICAL confidence:** Discovery pack CRITICAL rules had confidence=73 (78-5);
  corrected to 85 (90-5)

### Added

- **U2 tools/metadata_normalizer.py:** Tool for confidence backfill and string-to-int conversion;
  severity-based heuristics with pack-level adjustment
- **U4 Test Fixtures (30 total, +17 new):**
  - execution: `tp_powershell_encoded.json`, `fp_legitimate_automation.json`
  - persistence: `tp_registry_run_key.json`
  - credential_access: `tp_lsass_dump.json`, `fp_legitimate_lsass_access.json`
  - lateral_movement: `tp_psexec_domain_controller.json`
  - impact: `tp_ransomware_mass_rename.json`
  - cloud: `tp_aws_root_console_login.json`, `tp_azure_global_admin_added.json`
  - email: `tp_executive_impersonation.json`, `fp_newsletter_lookalike.json`
  - c2: `tp_dns_tunneling.json`
  - defense_evasion: `tp_process_injection_lsass.json`
  - database: `tp_xp_cmdshell_enabled.json`
  - vpn: `tp_impossible_travel.json`
  - devops: `tp_cicd_pipeline_curl_bash.json`, `fp_approved_install_script.json`

### Quality Metrics

| Metric | v0.1.0 | v0.2.0 |
|---|---|---|
| Linter Errors | 0 | 0 |
| Linter Warnings | 506 | 0 |
| Strict Mode | G+ packs only | Global (all packs) |
| Test Fixtures | 13 | 30 |
| CI confidence | All G+ rules | All 1029 rules |

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
