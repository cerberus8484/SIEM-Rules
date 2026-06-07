# Cloud Pack (AWS / Azure / GCP / M365)

**~80 rules — Splunk, QRadar, Google SecOps, Wazuh**

The Cloud pack detects threats across the four major cloud platforms using their
native audit log formats. Each platform has its own sub-directory under `cloud/`.

---

## Pack Summary

| Property | Value |
|---|---|
| Pack Directory | `cloud/` |
| ID Range | SP-200001 – SP-299999 |
| Platforms | Splunk, QRadar, Google SecOps, Wazuh |
| Key Sources | aws:cloudtrail, azure:activity, gcp:audit, o365:management:activity |

---

## Sub-Platform Coverage

### AWS CloudTrail

| Rule ID | Name | Severity | Technique |
|---|---|---|---|
| SP-200001 | S3 Bucket Made Public | CRITICAL | T1530 |
| SP-200002 | IAM Role Trust Policy Modified | HIGH | T1098.001 |
| SP-200003 | EC2 Security Group Opened to 0.0.0.0/0 | HIGH | T1562.007 |
| SP-200004 | Lambda Function Created with Admin Role | HIGH | T1098 |
| SP-200005 | CloudTrail Stopped or Deleted | CRITICAL | T1562.008 |
| SP-200006 | KMS Key Deleted | CRITICAL | T1485 |
| SP-200007 | S3 Object Lock Disabled | CRITICAL | T1490 |
| SP-200008 | GuardDuty Detector Deleted | CRITICAL | T1562 |

### Azure / Entra ID

| Rule ID | Name | Severity | Technique |
|---|---|---|---|
| SP-210001 | Azure Global Admin Role Added | CRITICAL | T1098 |
| SP-210002 | Azure Defender Alerts Suppressed | CRITICAL | T1562 |
| SP-210003 | Key Vault Secret Read by Unknown Principal | HIGH | T1552 |
| SP-210004 | Runbook Executed from Azure Automation | HIGH | T1059 |
| SP-210005 | Azure AD Conditional Access Disabled | CRITICAL | T1556 |

### Google Cloud (GCP)

| Rule ID | Name | Severity | Technique |
|---|---|---|---|
| SP-220001 | GCP Service Account Key Created | HIGH | T1098.001 |
| SP-220002 | GCP IAM Policy Set to AllUsers | CRITICAL | T1530 |
| SP-220003 | Cloud Logging Sink Deleted | CRITICAL | T1562.008 |
| SP-220004 | GCP Instance Serial Console Enabled | HIGH | T1059 |

### Microsoft 365

| Rule ID | Name | Severity | Technique |
|---|---|---|---|
| SP-230001 | M365 Mailbox Forwarding Enabled | HIGH | T1114.003 |
| SP-230002 | Unified Audit Log Disabled | CRITICAL | T1562.008 |
| SP-230003 | Teams External Access Opened | HIGH | T1137 |
| SP-230004 | SharePoint Site Shared Externally | MEDIUM | T1048 |

---

## Example: AWS S3 Public Bucket (Splunk)

```splunk-spl
`comment("
SP-200001 | S3 Bucket Made Public
tactic=Collection | technique=T1530
severity=CRITICAL | confidence=92
platform=splunk | status=stable | version=1.0
")`
index=aws sourcetype=aws:cloudtrail eventName IN ("PutBucketAcl","PutBucketPolicy")
| spath requestParameters.AccessControlPolicy.AccessControlList.Grant{}.Grantee.URI
| where 'requestParameters.AccessControlPolicy.AccessControlList.Grant{}.Grantee.URI'
    = "http://acs.amazonaws.com/groups/global/AllUsers"
| eval rule_id="SP-200001"
| eval tactic="Collection", technique="T1530"
| eval severity="CRITICAL", confidence=92
| table _time awsRegion requestParameters.bucketName userIdentity.arn rule_id severity confidence
```
