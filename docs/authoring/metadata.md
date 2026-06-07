# Metadata Reference

The canonical metadata schema is defined in `schema/rule_metadata.yaml`. This page
is the human-readable reference for all metadata fields.

---

## Required Fields

### rule_id

**Format:** `{SP|QR|GS|WZ}-\d{6}`  
**Examples:** `SP-700021`, `QR-100005`, `GS-700001`, `WZ-700006`

- Must be unique across ALL files for the same platform prefix
- Once assigned, never changes (even if the rule is refactored)
- If a rule is retired, the ID is retired with it — never reused

### tactic

**Format:** Free text (MITRE ATT&CK tactic name)  
**Examples:** `Initial Access`, `Execution`, `Credential Access`, `Impact`

Use the exact MITRE ATT&CK tactic name. Multi-tactic rules: use the primary tactic in
the metadata block; document secondary tactics in the description.

### technique

**Format:** `T\d{4}` or `T\d{4}\.\d{3}`  
**Examples:** `T1078`, `T1078.004`, `T1059.001`

Use the most specific technique that applies. For correlation rules covering multiple
techniques: use slash-separated format: `T1059/T1078/T1003`.

### severity

**Format:** `CRITICAL | HIGH | MEDIUM | LOW | INFO`

| Value | When to use | Typical confidence |
|---|---|---|
| `CRITICAL` | Confirmed attack, near-zero FP, immediate response required | 85–100 |
| `HIGH` | Strong indicator, low FP, analyst review required | 70–89 |
| `MEDIUM` | Suspicious, needs context, may be FP | 50–74 |
| `LOW` | Weak signal, environmental factors dominate | 30–55 |
| `INFO` | Telemetry enrichment, baselining, no action needed | 1–40 |

### confidence (0–100)

**Format:** Integer 0–100  
**Derivation:** Use severity as the baseline, then adjust for pack and environmental factors:

| Severity | Base | Pack adjustments |
|---|---|---|
| CRITICAL | 90 | +0 to +5 for deception/canary |
| HIGH | 78 | -5 for discovery, web, threat_intel packs |
| MEDIUM | 62 | ±5 depending on FP rate |
| LOW | 45 | — |
| INFO | 35 | — |

Deception rules: always 97–98 (any access is true positive by design).  
Do not artificially inflate confidence — it misleads analysts.

### platform

**Format:** `splunk | qradar | secops | wazuh`

One platform per rule block. Multi-platform coverage means the same detection logic
is written in each platform's format in the appropriate directory.

### status

**Format:** `stable | testing | experimental`

- `experimental` — new rule, not yet validated in production
- `testing` — running in a test environment, FP rate being measured
- `stable` — production-ready, FP rate confirmed < 5%

All rules in the current pack are `stable`.

### version

**Format:** `N.N` (major.minor)  
**Example:** `1.0`, `1.1`, `2.0`

Increment minor for tuning changes. Increment major for logic changes that alter
detection behavior.

---

## Optional Fields

### description

A single sentence explaining what this rule detects. Used in the docs and in SIEM
alert descriptions. Should be human-readable without SIEM-specific jargon.

### reference

URL to MITRE ATT&CK technique page, CVE, threat intel report, or vendor advisory.

---

## Metadata in the Linter

The linter extracts metadata from rule files using regex patterns:

| Field | Splunk extraction pattern |
|---|---|
| `rule_id` | `SP-\d{6}` in comment block |
| `tactic` | `tactic=([^\|]+)` |
| `technique` | `technique=(T\d{4}(?:\.\d{3})?)` |
| `severity` | `severity=(?:"([^"]+)"\|case\([^)]*"(CRITICAL\|HIGH\|...)` |
| `confidence` | `confidence\s*=\s*([0-9]+)` |
