# Rule Format

Every rule file must follow the standard format to pass the linter and be included
in the coverage matrix. This page describes the full format for all four platforms.

---

## Splunk SPL Format

```splunk-spl
`comment("
SP-XXXXXX | Human-Readable Rule Name
tactic=<MITRE Tactic Name> | technique=<T-number>
severity=<CRITICAL|HIGH|MEDIUM|LOW|INFO> | confidence=<0-100>
platform=splunk | status=<stable|testing|experimental> | version=<N.N>
")`
<your SPL search>
| eval rule_id="SP-XXXXXX"
| eval tactic="<tactic>", technique="<technique>"
| eval severity="<severity>", confidence=<integer>
| table _time host user <relevant_fields> rule_id severity confidence
```

### Required Fields

| Field | Location | Format |
|---|---|---|
| `rule_id` | Comment block + eval | `SP-\d{6}` |
| `tactic` | Comment block + eval | Free text |
| `technique` | Comment block + eval | `T\d{4}(\.\d{3})?` |
| `severity` | Comment block + eval | `CRITICAL\|HIGH\|MEDIUM\|LOW\|INFO` |
| `confidence` | eval | Integer 0–100 |
| `platform` | Comment block | `splunk` |
| `status` | Comment block | `stable\|testing\|experimental` |

### Dynamic Severity (Correlation Rules)

For rules where severity depends on a score, use `case()` and add a static
`confidence` eval before the dynamic override so the linter can detect it:

```splunk-spl
| eval severity=case(risk_score>=90,"CRITICAL",risk_score>=70,"HIGH",1=1,"MEDIUM")
| eval confidence=85                          ← static line for linter detection
| eval confidence=if(total_risk>=300,95,confidence)   ← dynamic override
```

---

## QRadar AQL Format

```sql
/* QR-XXXXXX | Human-Readable Rule Name
   tactic=<MITRE Tactic> | technique=<T-number>
   severity=<CRITICAL|HIGH|MEDIUM|LOW|INFO> | confidence=<0-100>
   platform=qradar | status=stable | version=1.0 */
SELECT
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS event_time,
    sourceip,
    username,
    'QR-XXXXXX' AS rule_id,
    'HIGH'       AS severity,
    82           AS confidence
FROM events
WHERE <your conditions>
LAST 15 MINUTES
```

---

## Google SecOps UDM Format

```yaml
/* GS-XXXXXX | Human-Readable Rule Name
   tactic=<MITRE Tactic> | technique=<T-number>
   severity=<CRITICAL|HIGH|MEDIUM|LOW|INFO> | confidence=<0-100>
   platform=secops | status=stable | version=1.0 */

rule gs_short_rule_name {
  meta:
    id         = "GS-XXXXXX"
    author     = "HuntingThreats"
    severity   = "HIGH"
    confidence = 82
    tactic     = "<tactic>"
    technique  = "<T-number>"
    description = "One sentence describing what this rule detects"

  events:
    $e.<udm_field> = "<value>"

  condition:
    $e
}
```

---

## Wazuh KQL Format

```
/* WZ-XXXXXX | Human-Readable Rule Name
   tactic=<MITRE Tactic> | technique=<T-number>
   severity=<CRITICAL|HIGH|MEDIUM|LOW|INFO> | confidence=<0-100>
   platform=wazuh | status=stable | version=1.0 */
rule.groups: <group> AND <field>: <value> AND rule.level >= <N>
```

---

## File Naming Convention

- One file per sub-pack or logical grouping (max ~20 rules per file)
- File name: `NNN_descriptive_name.{spl|aql|udm|kql}` where NNN starts at 001
- Examples: `001_iam_rules.spl`, `002_aws_cloudtrail.aql`

---

## Rule ID Assignment

Before creating a new rule, check the [namespace table](../packs/index.md#id-namespace-reference)
and find the next available ID in your range.

Check for ID conflicts:

```bash
python tools/rule_linter.py --platform splunk --strict 2>&1 | grep "Duplicate"
```

Never reuse a retired rule ID — use the next sequential number.

---

## Multi-Rule Files

A single file can contain multiple rules. Separate them with the comment block header
for each rule. The linter parses blocks by the `` `comment("` `` delimiter for Splunk
and `/* QR-` / `/* GS-` / `/* WZ-` for other platforms.

```splunk-spl
`comment("
SP-700021 | AWS Root Login
...
")`
<rule 1 SPL>

`comment("
SP-700022 | IAM Policy Change
...
")`
<rule 2 SPL>
```
