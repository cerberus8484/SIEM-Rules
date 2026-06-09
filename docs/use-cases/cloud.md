# Cloud & Container

Use cases for AWS, Azure, GCP, and Kubernetes environments.

**Rule packs:** `cloud`, `container_kubernetes`

---

## UC-036 — AWS CloudTrail Disabled {#uc-036}

**Threat:** Attacker disables CloudTrail logging to cover their tracks before
performing destructive or data theft operations in the AWS account.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 98 |
| **MITRE** | T1562.008 — Impair Defenses: Disable Cloud Logs |
| **Data Sources** | AWS CloudTrail |
| **Rule IDs** | SP-600001 |

### Splunk SPL

```spl
index=aws sourcetype="aws:cloudtrail"
| where eventName IN ("StopLogging", "DeleteTrail", "UpdateTrail")
    AND errorCode="Success"
| eval actor=userIdentity.arn
| table _time, actor, eventName, requestParameters.name, sourceIPAddress
| sort -_time
```

### QRadar AQL

```sql
SELECT
    username AS "Actor",
    "EventName" AS "Action",
    "TrailName" AS "Trail",
    sourceip AS "Source IP",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    "LogSourceType" = 'Amazon AWS CloudTrail'
    AND "EventName" IN ('StopLogging', 'DeleteTrail', 'UpdateTrail')
    AND "ErrorCode" = 'Success'
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Re-enable CloudTrail immediately: `aws cloudtrail start-logging --name <trail>`
2. Review what happened in the gap — check VPC Flow Logs (separate log source)
3. Identify the IAM principal that disabled logging — was it compromised?
4. Check for other disruptive actions: S3 public access, IAM changes
5. Enable CloudTrail log file integrity validation to detect future tampering

---

## UC-037 — S3 Bucket Public Access Granted {#uc-037}

**Threat:** Attacker or misconfiguration makes an S3 bucket publicly readable,
potentially exposing sensitive data. Common in data breach scenarios.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 88 |
| **MITRE** | T1530 — Data from Cloud Storage |
| **Data Sources** | AWS CloudTrail |
| **Rule IDs** | SP-600002 |

### Splunk SPL

```spl
index=aws sourcetype="aws:cloudtrail"
| where eventName IN ("PutBucketAcl", "PutBucketPolicy", "DeletePublicAccessBlock")
| spath input=requestParameters.accessControlPolicy.accessControlList.grant{}.grantee.uri output=grantee
| where match(grantee, "AllUsers|AuthenticatedUsers") OR eventName="DeletePublicAccessBlock"
| eval actor=userIdentity.arn, bucket=requestParameters.bucketName
| table _time, actor, eventName, bucket, grantee, sourceIPAddress
| sort -_time
```

### QRadar AQL

```sql
SELECT
    username AS "Actor",
    "BucketName" AS "Bucket",
    "EventName" AS "Action",
    "Grantee" AS "Access Granted To",
    sourceip AS "Source IP",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    "LogSourceType" = 'Amazon AWS CloudTrail'
    AND "EventName" IN ('PutBucketAcl', 'PutBucketPolicy', 'DeletePublicAccessBlock')
    AND (
        "Grantee" LIKE '%AllUsers%'
        OR "Grantee" LIKE '%AuthenticatedUsers%'
        OR "EventName" = 'DeletePublicAccessBlock'
    )
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Immediately re-enable Block Public Access on the affected bucket
2. Check S3 server access logs for data exfiltration (unexpected GetObject calls)
3. Identify what data is in the bucket — classify sensitivity
4. Notify DPO if PII was potentially exposed (→ DSGVO Art. 33: 72h notification window)
5. Review if this was intentional (CDN static assets) or misconfiguration

---

## UC-038 — Azure — New Owner Role Assignment {#uc-038}

**Threat:** Attacker assigns the Owner role on an Azure subscription or resource group,
giving full control including the ability to assign further permissions.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 85 |
| **MITRE** | T1098.003 — Account Manipulation: Additional Cloud Roles |
| **Data Sources** | Azure Activity Log |
| **Rule IDs** | SP-600003 |

### Splunk SPL

```spl
index=azure sourcetype="azure:audit"
| where operationName="Create role assignment" AND activityStatusValue="success"
| spath input=properties output=role_def path=roleDefinitionId
| eval role_name=properties.roleDefinitionName
| where match(role_name, "(?i)(Owner|Contributor|User Access Administrator)")
| eval actor=initiatedBy.user.userPrincipalName, target=properties.principalName
| table _time, actor, target, role_name, properties.scope
| sort -_time
```

### QRadar AQL

```sql
SELECT
    username AS "Assigned By",
    "PrincipalName" AS "Assigned To",
    "RoleName" AS "Role",
    "Scope" AS "Scope",
    sourceip AS "Source IP",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    "LogSourceType" = 'Microsoft Azure Activity'
    AND "OperationName" = 'Create role assignment'
    AND "ActivityStatus" = 'success'
    AND LOWER("RoleName") IN ('owner', 'contributor', 'user access administrator')
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Verify with the account team if this role assignment was planned
2. Remove the role if unauthorized: `az role assignment delete --assignee <principal> --role Owner`
3. Check what the newly-assigned principal did after receiving the role
4. Review Entra ID Privileged Identity Management (PIM) for standing vs. just-in-time access
5. Enable Azure Policy to require approval for Owner role assignments

---

## UC-039 — GCP — Service Account Key Created {#uc-039}

**Threat:** Long-lived service account keys are a significant security risk.
An attacker creating a key has persistent access even after password rotation.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 80 |
| **MITRE** | T1552.001 — Unsecured Credentials: Credentials in Files |
| **Data Sources** | GCP Cloud Audit Logs |
| **Rule IDs** | SP-600004 |

### Splunk SPL

```spl
index=gcp sourcetype="google:gcp:pubsub:message"
| where protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"
    AND protoPayload.status.code=0
| eval actor=protoPayload.authenticationInfo.principalEmail
| eval sa=protoPayload.resourceName
| table _time, actor, sa, protoPayload.requestMetadata.callerIp
| sort -_time
```

### QRadar AQL

```sql
SELECT
    username AS "Actor",
    "ServiceAccount" AS "Service Account",
    "KeyId" AS "Key ID",
    sourceip AS "Source IP",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    "LogSourceType" = 'Google Cloud Platform Audit'
    AND "MethodName" = 'google.iam.admin.v1.CreateServiceAccountKey'
    AND "Status" = 'success'
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Verify if the key creation was expected (deployment pipeline, new service)
2. Disable the key immediately if unauthorized: `gcloud iam service-accounts keys disable`
3. Rotate the service account to invalidate all keys
4. Enforce Workload Identity Federation instead of long-lived keys
5. Review IAM Recommender for excessive permissions on the service account

---

## UC-040 — Kubernetes — Privileged Pod Launched {#uc-040}

**Threat:** A privileged pod (securityContext.privileged=true) has full access to the
host kernel. An attacker launching one can escape to the underlying node and
compromise the entire cluster.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 90 |
| **MITRE** | T1610 — Deploy Container |
| **Data Sources** | Kubernetes Audit Log |
| **Rule IDs** | SP-700001, SP-700002 |

### Splunk SPL

```spl
index=kubernetes sourcetype="kube:audit"
| where verb IN ("create","update") AND objectRef.resource="pods"
| spath input=requestObject.spec.containers{} output=containers
| eval privileged=mvmap(containers, spath(containers, "securityContext.privileged"))
| where privileged="true"
| eval actor=user.username, namespace=objectRef.namespace, pod=objectRef.name
| table _time, actor, namespace, pod, sourceIPs{}
| sort -_time
```

### QRadar AQL

```sql
SELECT
    username AS "Created By",
    "Namespace" AS "Namespace",
    "PodName" AS "Pod Name",
    "Image" AS "Container Image",
    sourceip AS "Source IP",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    "LogSourceType" = 'Kubernetes Audit'
    AND "Verb" IN ('create', 'update')
    AND "Resource" = 'pods'
    AND "Privileged" = 'true'
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Delete the privileged pod: `kubectl delete pod <name> -n <namespace>`
2. Inspect the pod spec — what image is it running? What mounts does it have?
3. Check if the container escaped to the host (node process list, new files in /var)
4. Enforce PodSecurity admission policy — block privileged pods at cluster level
5. Review who has permission to create pods in that namespace (RBAC audit)
