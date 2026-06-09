# Cloud Security — Extended

Extended cloud threat detection for AWS, Azure, GCP, and Kubernetes beyond UC-036–040.

**Rule packs:** `cloud`, `container_kubernetes`

---

## UC-110 — AWS IAM User Created Outside Terraform/IaC {#uc-110}

**Threat:** New IAM user created via console or CLI instead of through the approved
Infrastructure-as-Code pipeline (Terraform, CDK, CloudFormation). Indicates unauthorized
access or shadow IT that bypasses security controls.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 82 |
| **MITRE** | T1136.003 — Create Account: Cloud Account |
| **Data Sources** | AWS CloudTrail |
| **Rule IDs** | SP-cloud-001 |

### Splunk SPL

```spl
index=aws sourcetype="aws:cloudtrail"
| where eventName="CreateUser"
    AND NOT match(userAgent,"(?i)(terraform|cdk|cloudformation|aws-sdk-go|aws-sdk-java)")
    AND NOT match(userIdentity.arn,"(?i)(AWSReservedSSO|pipeline-user|ci-service)")
| table _time, userIdentity.arn, requestParameters.userName, sourceIPAddress, userAgent
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Actor", "requestParameters.userName" AS "New IAM User",
    sourceip AS "Source IP", "userAgent" AS "Client",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Amazon AWS CloudTrail'
    AND "eventName" = 'CreateUser'
    AND "userAgent" NOT LIKE '%terraform%'
    AND "userAgent" NOT LIKE '%cloudformation%'
    AND "userAgent" NOT LIKE '%cdk%'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Verify with the account owner — was this IAM user creation authorized?
2. If unauthorized: disable the new user, revoke all keys, investigate the source principal
3. Enforce SCPs (Service Control Policies) to deny IAM user creation except via CI/CD role
4. Implement AWS Config rule: `iam-user-no-policies-check` and similar controls
5. Review the permissions assigned to the new user

---

## UC-111 — AWS Security Group Opened to 0.0.0.0/0 {#uc-111}

**Threat:** Security group rule allows inbound traffic from any IP (0.0.0.0/0 or ::/0)
on a sensitive port (22, 3389, 3306, 5432, 27017). Classic misconfiguration or
attacker creating a backdoor.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 90 |
| **MITRE** | T1562.004 — Impair Defenses: Disable or Modify System Firewall |
| **Data Sources** | AWS CloudTrail |
| **Rule IDs** | SP-cloud-002 |

### Splunk SPL

```spl
index=aws sourcetype="aws:cloudtrail"
| where eventName IN ("AuthorizeSecurityGroupIngress","AuthorizeSecurityGroupEgress")
| spath path=requestParameters.ipPermissions.items{} output=permissions
| mvexpand permissions
| spath input=permissions path=ipRanges.items{0}.cidrIp output=cidr
| spath input=permissions path=fromPort output=fromPort
| where cidr IN ("0.0.0.0/0","::/0")
    AND (fromPort IN (22, 3389, 3306, 5432, 27017, 6379, 9200, 8080, 8443, 445))
| table _time, userIdentity.arn, requestParameters.groupId, fromPort, cidr
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Actor", "requestParameters.groupId" AS "Security Group",
    "requestParameters.fromPort" AS "Port", "requestParameters.cidrIp" AS "Source CIDR",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Amazon AWS CloudTrail'
    AND "eventName" = 'AuthorizeSecurityGroupIngress'
    AND ("requestParameters.cidrIp" = '0.0.0.0/0' OR "requestParameters.cidrIp" = '::/0')
    AND "requestParameters.fromPort" IN ('22','3389','3306','5432','27017')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Revoke the rule immediately via AWS Console or CLI
2. Check if any unauthorized access occurred via the open port during the exposure window
3. Enable AWS Config rule: `restricted-ssh`, `restricted-common-ports`
4. Enable GuardDuty finding: `UnauthorizedAccess:EC2/MaliciousIPCaller.Custom`
5. Implement a preventive SCP to deny 0.0.0.0/0 rules in production accounts

---

## UC-112 — AWS KMS Key Scheduled for Deletion {#uc-112}

**Threat:** Attacker or insider schedules a KMS customer-managed key for deletion.
This would render all encrypted data (EBS volumes, S3 objects, RDS) permanently inaccessible.
Precursor to ransomware-style attack on cloud data.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 95 |
| **MITRE** | T1485 — Data Destruction |
| **Data Sources** | AWS CloudTrail |
| **Rule IDs** | SP-cloud-003 |

### Splunk SPL

```spl
index=aws sourcetype="aws:cloudtrail"
| where eventName="ScheduleKeyDeletion"
| table _time, userIdentity.arn, requestParameters.keyId, requestParameters.pendingWindowInDays, sourceIPAddress
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Actor", "requestParameters.keyId" AS "KMS Key ID",
    "requestParameters.pendingWindowInDays" AS "Deletion Window (days)",
    sourceip AS "Source IP", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Amazon AWS CloudTrail'
    AND "eventName" = 'ScheduleKeyDeletion'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. **Immediate action** — cancel the deletion: `aws kms cancel-key-deletion --key-id <key-id>`
2. Identify all resources encrypted with this key and assess blast radius
3. Identify the principal that scheduled the deletion — was it authorized?
4. If unauthorized: rotate the compromised credentials, enable CloudTrail alerting
5. Implement an SCP to deny `kms:ScheduleKeyDeletion` for non-break-glass roles

---

## UC-113 — AWS GuardDuty Disabled {#uc-113}

**Threat:** Attacker disables AWS GuardDuty in the target account to prevent ongoing
threat detection while conducting their attack. High-confidence indicator of targeted attack.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 98 |
| **MITRE** | T1562.008 — Impair Defenses: Disable Cloud Logs |
| **Data Sources** | AWS CloudTrail |
| **Rule IDs** | SP-cloud-004 |

### Splunk SPL

```spl
index=aws sourcetype="aws:cloudtrail"
| where eventName IN ("DeleteDetector","DisassociateFromMasterAccount","DeleteMembers","StopMonitoringMembers","DisableOrganizationAdminAccount")
| table _time, userIdentity.arn, eventName, awsRegion, sourceIPAddress
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Actor", "eventName" AS "Action",
    "awsRegion" AS "Region", sourceip AS "Source IP",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Amazon AWS CloudTrail'
    AND "eventName" IN ('DeleteDetector','DisassociateFromMasterAccount',
        'StopMonitoringMembers','DisableOrganizationAdminAccount')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. **Immediate** — re-enable GuardDuty in all regions
2. Identify what activity occurred between GuardDuty disable and re-enable
3. This is a sophisticated attack — the attacker knew about your detection setup
4. Check for other defense evasion: CloudTrail disabled? Config recorder stopped?
5. Activate AWS Incident Response, preserve CloudTrail logs off-account

---

## UC-114 — Lambda Function with Admin IAM Role {#uc-114}

**Threat:** Attacker creates a Lambda function with an execution role granting
administrative privileges. Lambda can then be triggered to perform any AWS action,
including creating IAM users, exfiltrating S3 data, or launching EC2 instances.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 85 |
| **MITRE** | T1578.002 — Modify Cloud Compute Infrastructure: Create Cloud Instance |
| **Data Sources** | AWS CloudTrail |
| **Rule IDs** | SP-cloud-005 |

### Splunk SPL

```spl
index=aws sourcetype="aws:cloudtrail"
| where eventName IN ("CreateFunction20150331","UpdateFunctionConfiguration20150331")
| spath path=requestParameters.role output=lambda_role
| where match(lambda_role,"(?i)(admin|Administrator|FullAccess|PowerUser)")
| table _time, userIdentity.arn, requestParameters.functionName, lambda_role, awsRegion
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Actor", "requestParameters.functionName" AS "Lambda Function",
    "requestParameters.role" AS "Execution Role",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Amazon AWS CloudTrail'
    AND "eventName" IN ('CreateFunction20150331','UpdateFunctionConfiguration20150331')
    AND ("requestParameters.role" LIKE '%AdministratorAccess%'
        OR "requestParameters.role" LIKE '%FullAccess%'
        OR "requestParameters.role" LIKE '%PowerUser%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Identify the Lambda function and its execution role
2. Review the function code for malicious actions
3. Apply least-privilege: the role should only have the permissions the function actually needs
4. Implement IAM permission boundaries on Lambda execution roles
5. Enable Lambda function URL monitoring and invocation logging

---

## UC-115 — EC2 IMDSv1 Access (Credential Theft Vector) {#uc-115}

**Threat:** EC2 Instance Metadata Service v1 (IMDSv1) allows any code running on
an EC2 instance (including SSRF attack code) to retrieve IAM role credentials without
authentication. IMDSv2 requires a token, preventing SSRF-based credential theft.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 78 |
| **MITRE** | T1552.005 — Unsecured Credentials: Cloud Instance Metadata API |
| **Data Sources** | VPC Flow Logs, AWS CloudTrail |
| **Rule IDs** | SP-cloud-006 |

### Splunk SPL

```spl
index=aws sourcetype="aws:cloudtrail"
| where eventName="RunInstances"
| spath path=requestParameters.metadataOptions.httpTokens output=imds_version
| where imds_version="optional" OR isnull(imds_version)
| table _time, userIdentity.arn, requestParameters.instanceType, imds_version, awsRegion
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Actor", "requestParameters.instanceType" AS "Instance Type",
    "requestParameters.metadataOptions.httpTokens" AS "IMDSv2 Status",
    "awsRegion" AS "Region", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Amazon AWS CloudTrail'
    AND "eventName" = 'RunInstances'
    AND ("requestParameters.metadataOptions.httpTokens" = 'optional'
        OR "requestParameters.metadataOptions.httpTokens" IS NULL)
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Enforce IMDSv2 via SCP: `ec2:MetadataHttpTokens` must be `required`
2. For existing instances: `aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required`
3. Enable AWS Config rule: `ec2-imdsv2-check`
4. If SSRF suspected: check application logs for requests to 169.254.169.254
5. Review which IAM roles are attached to the affected instances

---

## UC-116 — Azure Conditional Access Policy Disabled {#uc-116}

**Threat:** Attacker with Global Admin access disables a Conditional Access policy
to remove MFA requirements or location-based restrictions, enabling unfettered access.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 93 |
| **MITRE** | T1562.001 — Impair Defenses: Disable or Modify Tools |
| **Data Sources** | Entra ID Audit Log |
| **Rule IDs** | SP-cloud-007 |

### Splunk SPL

```spl
index=azure sourcetype="azure:aad:audit"
| where OperationName IN ("Update conditional access policy","Delete conditional access policy")
    AND ResultDescription="Success"
| spath path=ModifiedProperties{}.newValue output=new_state
| where match(new_state,"(?i)disabled")
| table _time, InitiatedBy.user.userPrincipalName, OperationName, TargetResources{}.displayName
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Actor", "OperationName" AS "Action",
    "TargetResource" AS "CA Policy", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Microsoft Azure Active Directory'
    AND ("OperationName" LIKE '%conditional access%disable%'
        OR "OperationName" LIKE '%Delete conditional access%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Re-enable the Conditional Access policy immediately
2. Identify which accounts authenticated without MFA during the window it was disabled
3. Who disabled it? Was it an authorized GA or a compromised account?
4. Implement CA policy change notifications via Azure Monitor Alerts
5. Require a second Global Admin to approve CA policy changes (Privileged Identity Management)

---

## UC-117 — Azure PIM Role Activation Outside Business Hours {#uc-117}

**Threat:** Privileged Identity Management role (Global Admin, Exchange Admin, etc.)
activated outside normal working hours — indicates either account compromise or
unauthorized privileged activity.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 80 |
| **MITRE** | T1078.004 — Valid Accounts: Cloud Accounts |
| **Data Sources** | Entra ID Audit Log, PIM audit |
| **Rule IDs** | SP-cloud-008 |

### Splunk SPL

```spl
index=azure sourcetype="azure:aad:audit"
| where OperationName IN ("Add member to role completed (PIM activation)","Activate a role")
| eval hour=strftime(_time,"%H"), dow=strftime(_time,"%w")
| where (hour < 7 OR hour >= 20) OR dow IN ("0","6")
| table _time, InitiatedBy.user.userPrincipalName, OperationName, TargetResources{}.displayName, hour, dow
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "User", "TargetResource" AS "Role Activated",
    EXTRACT(HOUR FROM starttime) AS "Hour", EXTRACT(DOW FROM starttime) AS "Day",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Microsoft Azure Active Directory'
    AND "OperationName" LIKE '%PIM activation%'
    AND (EXTRACT(HOUR FROM starttime) < 7 OR EXTRACT(HOUR FROM starttime) >= 20
        OR EXTRACT(DOW FROM starttime) IN (0,6))
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Contact the user directly to verify the activation was legitimate
2. If unauthorized: immediately deactivate the role assignment in PIM
3. Review actions taken during the elevated session in Azure Activity Log
4. Enable PIM just-in-time access with manager approval for after-hours activations
5. Implement PIM notifications to security team for all privileged role activations

---

## UC-118 — Kubernetes kubectl exec into Production Pod {#uc-118}

**Threat:** Someone executes a shell inside a running production pod — this should
almost never happen in production. Used for debugging but also for attacker
lateral movement or data access.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 85 |
| **MITRE** | T1609 — Container Administration Command |
| **Data Sources** | Kubernetes Audit Log |
| **Rule IDs** | SP-k8s-001 |

### Splunk SPL

```spl
index=kubernetes sourcetype="kube:apiserver:audit"
| where verb="create" AND resource="pods" AND subresource="exec"
    AND NOT match(user.username,"(?i)(system:serviceaccount.*monitoring|prometheus)")
    AND match(requestObject.namespaces,"(?i)(prod|production|live)")
| table _time, user.username, objectRef.namespace, objectRef.name, requestObject.command
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "User", "namespace" AS "Namespace",
    "podName" AS "Pod", "command" AS "Exec Command",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Kubernetes'
    AND "verb" = 'create' AND "resource" = 'pods' AND "subresource" = 'exec'
    AND "namespace" IN ('prod','production','live')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Verify the exec was authorized — was there an open incident requiring it?
2. Review what commands were run in the container
3. Consider: who should be allowed to exec into pods? Enforce via RBAC
4. Check if the pod's service account has privileged permissions
5. Implement OPA/Gatekeeper policy to alert/deny pod exec in production namespaces

---

## UC-119 — Kubernetes Secret Enumeration {#uc-119}

**Threat:** An account or service account lists or reads Kubernetes secrets across
namespaces — potential credential theft from environment variables or service account tokens.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 82 |
| **MITRE** | T1552.007 — Unsecured Credentials: Container API |
| **Data Sources** | Kubernetes Audit Log |
| **Rule IDs** | SP-k8s-002 |

### Splunk SPL

```spl
index=kubernetes sourcetype="kube:apiserver:audit"
| where resource="secrets" AND verb IN ("list","get","watch")
    AND NOT match(user.username,"(?i)(system:serviceaccount:kube-system|flux|argocd|vault)")
| bucket _time span=5m
| stats count, dc(objectRef.namespace) as Namespaces by user.username, _time
| where count >= 10 OR Namespaces >= 3
| sort -count
```

### QRadar AQL

```sql
SELECT username AS "User", COUNT(*) AS "Secret Reads",
    COUNT(DISTINCT "namespace") AS "Namespaces",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time Window"
FROM events WHERE "LogSourceType" = 'Kubernetes'
    AND "resource" = 'secrets' AND "verb" IN ('list','get')
    AND username NOT LIKE '%system:serviceaccount:kube-system%'
GROUP BY username, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss')
HAVING COUNT(*) >= 10
LAST 1 HOURS ORDER BY "Secret Reads" DESC
```

### Response Actions
1. Identify the service account or user that performed the enumeration
2. Review what secrets exist in the accessed namespaces — contain API keys, passwords?
3. Rotate all secrets that may have been read
4. Apply RBAC least-privilege: service accounts should only access secrets in their namespace
5. Consider Sealed Secrets or External Secrets Operator to avoid storing plain secrets in etcd

---

## UC-120 — Kubernetes DaemonSet with hostPID/hostNetwork {#uc-120}

**Threat:** DaemonSet (or Pod) created with `hostPID: true` or `hostNetwork: true`
gives container-level access to the host's process namespace or network stack —
a common container escape technique.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 90 |
| **MITRE** | T1611 — Escape to Host |
| **Data Sources** | Kubernetes Audit Log |
| **Rule IDs** | SP-k8s-003 |

### Splunk SPL

```spl
index=kubernetes sourcetype="kube:apiserver:audit"
| where verb IN ("create","update") AND resource IN ("daemonsets","pods","deployments")
| spath path=requestObject.spec.hostPID output=hostPID
| spath path=requestObject.spec.hostNetwork output=hostNetwork
| spath path=requestObject.spec.hostIPC output=hostIPC
| where hostPID="true" OR hostNetwork="true" OR hostIPC="true"
    AND NOT match(objectRef.namespace,"(?i)(kube-system|monitoring|calico|cilium)")
| table _time, user.username, resource, objectRef.namespace, hostPID, hostNetwork
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "User", "resource" AS "Resource Type",
    "namespace" AS "Namespace", "hostPID" AS "Host PID",
    "hostNetwork" AS "Host Network", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Kubernetes'
    AND "verb" IN ('create','apply')
    AND ("hostPID" = 'true' OR "hostNetwork" = 'true' OR "hostIPC" = 'true')
    AND "namespace" NOT IN ('kube-system','monitoring','calico-system')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Delete the DaemonSet immediately: `kubectl delete daemonset <name> -n <namespace>`
2. Identify who submitted the manifest — CI/CD pipeline or manual kubectl?
3. Check if the container was used to escape to the host (process inspection)
4. Implement OPA/Gatekeeper PodSecurityPolicy to deny hostPID/hostNetwork
5. Enable Pod Security Standards (restricted profile) cluster-wide
