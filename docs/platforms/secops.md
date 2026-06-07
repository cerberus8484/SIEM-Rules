# Google SecOps (Chronicle) Integration Guide

The Enterprise Hunt Pack provides ~100 Google SecOps UDM rules for Cloud and Identity
packs. Rules use the Chronicle YARA-L 2.0 rule format and UDM (Unified Data Model)
normalized fields.

---

## Prerequisites

- Google SecOps (formerly Chronicle) tenant with YARA-L 2.0 support
- Log ingestion configured for supported sources
- `Chronicle API` access for rule deployment

---

## Rule File Format

Google SecOps rules use the YARA-L 2.0 syntax with a comment header:

```yaml
/* GS-700001 | AWS Root Account Console Login
   tactic=Initial Access | technique=T1078.004
   severity=CRITICAL | confidence=95
   platform=secops | status=stable | version=1.0 */

rule gs_iam_aws_root_console_login {
  meta:
    id          = "GS-700001"
    author      = "HuntingThreats"
    severity    = "CRITICAL"
    confidence  = 95
    tactic      = "Initial Access"
    technique   = "T1078.004"
    description = "AWS root account used for console login — no legitimate use in production"
    reference   = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"

  events:
    $e.metadata.product_name = "AWS CloudTrail"
    $e.metadata.event_type   = "USER_LOGIN"
    $e.target.user.userid    = "root"
    $e.metadata.vendor_name  = "AMAZON"

  condition:
    $e
}
```

---

## UDM Field Mapping

Chronicle normalizes events into the UDM schema. Key mappings for supported log sources:

### AWS CloudTrail → UDM

| CloudTrail Field | UDM Field |
|---|---|
| `userIdentity.type` | `principal.user.user_role` |
| `sourceIPAddress` | `principal.ip` |
| `eventName` | `metadata.product_event_type` |
| `userIdentity.userName` | `principal.user.userid` |
| `awsRegion` | `metadata.ingested_labels["region"]` |

### Okta System Log → UDM

| Okta Field | UDM Field |
|---|---|
| `actor.id` | `principal.user.userid` |
| `client.ipAddress` | `principal.ip` |
| `eventType` | `metadata.product_event_type` |
| `outcome.result` | `security_result.action` |

---

## Deploying Rules

Use the Chronicle API:

```bash
# List existing rules
curl -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://backstory.googleapis.com/v2/detect/rules"

# Create a new rule
curl -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  --data-binary @gs-700001.rule \
  "https://backstory.googleapis.com/v2/detect/rules"
```

Or use the Chronicle UI: **Detection → Rules → New Rule** → paste YARA-L content.

---

## Multi-Event Rules (Correlation)

Chronicle supports multi-event YARA-L rules using `match` + `over`:

```yaml
rule gs_impossible_travel {
  meta:
    id = "GS-770001"
    severity = "HIGH"

  events:
    $login1.metadata.event_type = "USER_LOGIN"
    $login1.security_result.action = "ALLOW"
    $login2.metadata.event_type = "USER_LOGIN"
    $login2.security_result.action = "ALLOW"

    $login1.principal.user.userid = $login2.principal.user.userid

    // Different countries
    $login1.principal.location.country_or_region !=
    $login2.principal.location.country_or_region

  match:
    $login1.principal.user.userid over 1h

  condition:
    $login1 and $login2
}
```

---

## Coverage in This Pack

| Sub-Pack | Rules | Key Detections |
|---|---|---|
| AWS IAM | 20 | Root login, CloudTrail stop, KMS delete |
| Entra ID / Azure | 20 | Global admin add, CA policy disable, Key Vault access |
| Okta | 15 | Admin role, MFA enroll, session hijack |
| Generic IdP | 15 | Normalized across providers |
| Cloud Infra | 30 | S3 public, GCP IAM, M365 forward |
