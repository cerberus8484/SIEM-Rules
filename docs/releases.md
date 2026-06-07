# Releases

All releases are available on [GitHub Releases](https://github.com/cerberus8484/SIEM-Rules/releases).
Each release includes per-platform ZIP archives with SHA-256 checksums.

---

## Download Links

### v0.2.0 — Quality Hardening Release

| Package | Download | Checksum |
|---|---|---|
| All platforms (complete) | [huntingthreats-all-v0.2.0.zip](https://github.com/cerberus8484/SIEM-Rules/releases/download/v0.2.0/huntingthreats-all-v0.2.0.zip) | [.sha256](https://github.com/cerberus8484/SIEM-Rules/releases/download/v0.2.0/huntingthreats-all-v0.2.0.zip.sha256) |
| Splunk SPL only | [huntingthreats-splunk-v0.2.0.zip](https://github.com/cerberus8484/SIEM-Rules/releases/download/v0.2.0/huntingthreats-splunk-v0.2.0.zip) | [.sha256](https://github.com/cerberus8484/SIEM-Rules/releases/download/v0.2.0/huntingthreats-splunk-v0.2.0.zip.sha256) |
| QRadar AQL only | [huntingthreats-qradar-v0.2.0.zip](https://github.com/cerberus8484/SIEM-Rules/releases/download/v0.2.0/huntingthreats-qradar-v0.2.0.zip) | [.sha256](https://github.com/cerberus8484/SIEM-Rules/releases/download/v0.2.0/huntingthreats-qradar-v0.2.0.zip.sha256) |
| Google SecOps UDM only | [huntingthreats-secops-v0.2.0.zip](https://github.com/cerberus8484/SIEM-Rules/releases/download/v0.2.0/huntingthreats-secops-v0.2.0.zip) | [.sha256](https://github.com/cerberus8484/SIEM-Rules/releases/download/v0.2.0/huntingthreats-secops-v0.2.0.zip.sha256) |
| Wazuh KQL only | [huntingthreats-wazuh-v0.2.0.zip](https://github.com/cerberus8484/SIEM-Rules/releases/download/v0.2.0/huntingthreats-wazuh-v0.2.0.zip) | [.sha256](https://github.com/cerberus8484/SIEM-Rules/releases/download/v0.2.0/huntingthreats-wazuh-v0.2.0.zip.sha256) |

**Verify before use:**
```bash
sha256sum -c huntingthreats-splunk-v0.2.0.zip.sha256
```

---

## v0.2.0 — 2026-06-07

**Quality hardening release: 0 linter errors, 0 linter warnings, global strict mode, 30 test fixtures.**

### What changed

| Area | Change |
|---|---|
| **Metadata backfill** | 500 rules converted from `confidence="HIGH"` string to numeric integers |
| **Strict mode** | CI now requires 0 errors AND 0 warnings on all 28 packs |
| **Fixtures** | Expanded from 13 to 30 synthetic test events |
| **Linter fixes** | Fixed dynamic `severity=case(...)` parsing, example.com FP in analyst_queries |
| **Rule fixes** | SP-730017/730018 eval mismatch, SP-810020 technique and confidence |

### Quality metrics

| Metric | v0.1.0 | v0.2.0 |
|---|---|---|
| Linter Errors | 0 | 0 |
| Linter Warnings | 506 | **0** |
| Strict Mode | G+ packs only | **Global** |
| Test Fixtures | 13 | **30** |
| Rules with numeric confidence | ~529 | **1029** |

---

## v0.1.0 — 2026-06-07

**First production-ready release. ~1500 detection rules across 28 packs, 4 SIEM platforms.**

### Included

- 16 Foundation packs (A–F range): Windows, Cloud, Linux, Network, Web, TI
- 12 Enterprise Specialty packs (G–R range): Identity/IAM, Container/K8s, DevOps, Backup, Hypervisor, Email, Database, VPN, macOS, DLP, Deception, Correlation
- Rule QA Framework (linter, fixture validator, coverage matrix)
- CI pipeline (GitHub Actions)
- 11 initial test fixtures (TP + FP pairs)

---

## Versioning Policy

This project follows [Semantic Versioning](https://semver.org/):

- **Patch** (`0.2.x`) — Bug fixes, linter corrections, fixture updates, no new rules
- **Minor** (`0.x.0`) — New rules, new packs, new platforms, backward-compatible
- **Major** (`x.0.0`) — Breaking changes to rule format, ID namespace, or schema

---

## Verifying Release Integrity

All release artifacts are signed with SHA-256 checksums generated during the CI
release pipeline. To verify:

```bash
# Download the ZIP and its checksum file
wget https://github.com/cerberus8484/SIEM-Rules/releases/download/v0.2.0/huntingthreats-splunk-v0.2.0.zip
wget https://github.com/cerberus8484/SIEM-Rules/releases/download/v0.2.0/huntingthreats-splunk-v0.2.0.zip.sha256

# Verify
sha256sum -c huntingthreats-splunk-v0.2.0.zip.sha256
# Expected: huntingthreats-splunk-v0.2.0.zip: OK
```

---

## Changelog

See [CHANGELOG.md](https://github.com/cerberus8484/SIEM-Rules/blob/main/CHANGELOG.md) for the full detailed change history.
