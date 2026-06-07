# Severity & Confidence Guide

Severity and confidence are the two most impactful fields in a detection rule.
Analysts use them to prioritize their queue. Getting them wrong burns analyst time
on noise or misses real attacks.

---

## Severity

Severity answers: **"How bad is it if this fires on a real attack?"**

| Severity | Response expectation | Example |
|---|---|---|
| **CRITICAL** | Immediate response, possible isolation | Root account login, ransomware prep chain |
| **HIGH** | Agent escalates within 15 minutes | Admin role granted, LSASS dump |
| **MEDIUM** | Create ticket, investigate same day | Suspicious PowerShell, unusual login time |
| **LOW** | Review in batch, weekly hunt | Minor enumeration, single failed login |
| **INFO** | No action, used for enrichment | Asset inventory, baseline capture |

### Severity vs Confidence

Severity and confidence are independent:

- A rule can be `CRITICAL` severity with `confidence=65` — the attack is catastrophic
  if real, but there is meaningful FP risk (e.g., VSS deletion could be backup maintenance)
- A rule can be `MEDIUM` severity with `confidence=95` — the event is definitely happening
  but its impact is limited (e.g., a canary document opened in a read-only share)

---

## Confidence

Confidence answers: **"How sure are we that this is a real attack, not a false positive?"**

| Score | Interpretation | Recommended analyst action |
|---|---|---|
| 90–100 | Confirmed attack pattern, near-zero FP by design | Immediate escalation, possible isolation |
| 75–89 | Strong indicator, low FP rate | Agent escalates to analyst within 15 min |
| 55–74 | Suspicious, context-dependent | Create ticket, investigate same day |
| 30–54 | Weak signal, high FP potential | Log-only mode, weekly batch review |
| < 30 | Informational only | Enrichment use, no alert action |

### The Pack Adjustment System

Each pack has a confidence adjustment based on environmental noise characteristics:

| Pack | Adjustment | Reason |
|---|---|---|
| `deception` | +7 | Honey resources have zero legitimate access |
| `correlation` | +5 | Multi-signal correlation reduces FP rate |
| `credential_access` | +3 | LSASS access patterns are distinctive |
| `discovery` | -5 | AD enumeration tools are common in IT |
| `web` | -3 | WAF and scanner traffic creates noise |
| `threat_intel` | -5 | IOC feeds have variable quality |

The `tools/metadata_normalizer.py` applies these adjustments automatically when
backfilling confidence scores.

---

## Setting Confidence for a New Rule

Use this decision tree:

```
1. What is the severity?
   → Start with the base score: CRITICAL=90, HIGH=78, MEDIUM=62, LOW=45, INFO=35

2. What is the pack?
   → Apply pack adjustment (see table above)

3. Is this a new rule with no production data?
   → Subtract 5–10 for uncertainty, set status=experimental

4. Do you have FP data from testing?
   → If FP rate < 1%: +5. If FP rate > 10%: -10 or reconsider the rule

5. Is this a deception/canary rule?
   → Always set confidence=97 or 98 (by design, any access is TP)
```

### Examples

| Rule | Severity | Pack | Base | Adjustment | Final |
|---|---|---|---|---|---|
| SP-800001 Canary Doc | CRITICAL | deception | 90 | +7+1 | 98 |
| SP-730001 VSS Delete | CRITICAL | backup | 90 | +3 | 93 |
| SP-700021 Root Login | CRITICAL | identity | 90 | +5 | 95 |
| SP-710001 Priv Pod | CRITICAL | container | 90 | 0 | 90 |
| SP-100001 PS Encoded | HIGH | execution | 78 | 0 | 78 → 82 (prod data) |
| SP-106021 AD Enum | MEDIUM | discovery | 62 | -5 | 57 |

---

## When NOT to Use CRITICAL Severity

!!! warning "CRITICAL is not for 'important' — it is for 'confirmed attack'"

    Using CRITICAL for everything that seems serious causes alert fatigue.
    Reserve CRITICAL for rules where:

    - The technique is only used in attacks (not in any legitimate admin workflow)
    - A real positive requires immediate response, not just investigation
    - The detection is specific enough that FP rate is demonstrably low

    If you are uncertain, use HIGH. CRITICAL severity creates a mandatory response
    expectation on the analyst side — they cannot defer it.
