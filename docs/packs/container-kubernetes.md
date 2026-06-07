# Container / Kubernetes Pack

**20 rules — Splunk — Kubernetes audit log**

The Container pack detects privilege escalation, container escape, RBAC abuse,
and API server attacks using Kubernetes audit logs and container runtime events.

---

## Pack Summary

| Property | Value |
|---|---|
| Pack Directory | `container/` |
| ID Range | SP-710001 – SP-710020 |
| Platforms | Splunk |
| Rules | 20 |
| Key Sources | kubernetes:apiserver (audit log) |
| MITRE Tactics | Privilege Escalation, Lateral Movement, Persistence |

---

## Rule Inventory

| Rule ID | Name | Severity | Confidence | Technique |
|---|---|---|---|---|
| SP-710001 | Privileged Pod Created | CRITICAL | 90 | T1611 |
| SP-710002 | RBAC ClusterRoleBinding with Wildcard | CRITICAL | 92 | T1078.001 |
| SP-710003 | Container Exec Shell (kubectl exec) | HIGH | 82 | T1059 |
| SP-710004 | K8s Secrets Listed by Unknown Service Account | HIGH | 85 | T1552.007 |
| SP-710005 | Pod with hostPID or hostNetwork | CRITICAL | 90 | T1611 |
| SP-710006 | API Server Anonymous Auth Enabled | CRITICAL | 95 | T1190 |
| SP-710007 | Kubernetes Dashboard Exposed | HIGH | 82 | T1190 |
| SP-710008 | Node Port in Dangerous Range | MEDIUM | 65 | T1021 |
| SP-710009 | Service Account Token Mounted in Unusual Namespace | HIGH | 78 | T1552.007 |
| SP-710010 | CronJob Created by Non-Admin | HIGH | 80 | T1053.007 |
| SP-710011 | Namespace Created with Privileged Admission | HIGH | 82 | T1078 |
| SP-710012 | Helm Tiller Exposed (Legacy) | HIGH | 88 | T1190 |
| SP-710013 | Container Image from Untrusted Registry | HIGH | 75 | T1195.002 |
| SP-710014 | Kubernetes etcd Accessed Directly | CRITICAL | 95 | T1552 |
| SP-710015 | Pod Security Policy Bypassed | CRITICAL | 88 | T1611 |
| SP-710016 | DaemonSet Modified by Non-Admin | HIGH | 82 | T1543 |
| SP-710017 | K8s Admission Webhook Modified | CRITICAL | 90 | T1562 |
| SP-710018 | Container with SYS_ADMIN Capability | CRITICAL | 92 | T1611 |
| SP-710019 | K8s Audit Log Forwarding Disabled | CRITICAL | 90 | T1562.008 |
| SP-710020 | Lateral Movement via K8s Service Account | HIGH | 82 | T1078.001 |

---

## Kubernetes Audit Log Setup

Enable Kubernetes audit logging with a policy that captures the fields used by these rules:

```yaml
# audit-policy.yaml (minimal required fields)
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["pods", "secrets", "serviceaccounts"]
  - level: Metadata
    resources:
    - group: "rbac.authorization.k8s.io"
      resources: ["clusterrolebindings", "clusterroles"]
  - level: Request
    verbs: ["exec"]
    resources:
    - group: ""
      resources: ["pods/exec"]
```

Forward audit logs to Splunk using the [Splunk Connect for Kubernetes](https://github.com/splunk/splunk-connect-for-kubernetes) Helm chart.

---

## Example: Privileged Pod (Splunk)

```splunk-spl
`comment("
SP-710001 | Privileged Pod Created
tactic=Privilege Escalation | technique=T1611
severity=CRITICAL | confidence=90
platform=splunk | status=stable | version=1.0
")`
index=kubernetes sourcetype=kubernetes:apiserver
    verb=create resource=pods
| spath spec.containers{}.securityContext.privileged
| where 'spec.containers{}.securityContext.privileged'="true"
| eval rule_id="SP-710001"
| eval tactic="Privilege Escalation", technique="T1611"
| eval severity="CRITICAL", confidence=90
| table _time user namespace name spec.containers{}.image rule_id severity confidence
```

---

## Test Fixtures

| Fixture | Type | Scenario |
|---|---|---|
| `tp_privileged_pod.json` | TRUE POSITIVE | Pod with `privileged: true` created by non-cluster-admin |
| `fp_operator_pod.json` | FALSE POSITIVE | Operator pod with `privileged: true` in kube-system namespace |
