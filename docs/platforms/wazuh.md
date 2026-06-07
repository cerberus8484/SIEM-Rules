# Wazuh Integration Guide

The Enterprise Hunt Pack provides ~200 Wazuh rules for Identity/IAM and core Windows/Linux
packs. Wazuh rules use a KQL-style syntax with comment-block metadata headers.

---

## Prerequisites

- Wazuh 4.4+ (Manager + Agents)
- Wazuh Indexer (OpenSearch-based)
- Appropriate decoders configured for log sources
- Wazuh Dashboard for visualization

---

## Rule File Format

Wazuh rules in this pack use KQL filter syntax compatible with the Wazuh Indexer:

```
/* WZ-700006 | AWS IAM Root Login
   tactic=Initial Access | technique=T1078.004
   severity=CRITICAL | confidence=95
   platform=wazuh | status=stable | version=1.0 */
rule.groups: aws
AND data.aws.userIdentity.type: Root
AND data.aws.eventName: ConsoleLogin
AND rule.level >= 12
```

For Wazuh XML rule files (deployed to Manager), the equivalent format:

```xml
<rule id="100700006" level="15">
  <decoded_as>json</decoded_as>
  <field name="data.aws.userIdentity.type">Root</field>
  <field name="data.aws.eventName">ConsoleLogin</field>
  <description>HT-WZ-700006: AWS root account console login detected</description>
  <mitre>
    <id>T1078.004</id>
  </mitre>
  <group>aws,identity,iam</group>
</rule>
```

---

## Deploying to Wazuh Manager

1. Copy custom rule files to `/var/ossec/etc/rules/`:

    ```bash
    cp wazuh/identity/*.kql /var/ossec/etc/rules/huntingthreats/
    ```

2. Convert KQL rules to XML format (script coming in v0.3.0)

3. Validate and restart the manager:

    ```bash
    /var/ossec/bin/ossec-logtest -t
    systemctl restart wazuh-manager
    ```

---

## Wazuh Dashboard Queries

Use the KQL filter files directly in the Wazuh Dashboard **Discover** view:

1. Open **Wazuh Dashboard → Discover**
2. Select the `wazuh-alerts-*` index pattern
3. Paste the KQL query from the `.kql` file (excluding the comment header)

Example for `WZ-700012` (Okta Admin Role Granted):

```kql
rule.groups: okta
AND data.okta.event_type: user.account.privilege.grant
AND data.okta.target.type: AppUser
AND rule.level >= 10
```

---

## Coverage

| Sub-Pack | Rules | Key Log Sources |
|---|---|---|
| AWS IAM | 20 | CloudTrail via Wazuh AWS module |
| Okta | 20 | Okta System Log via Wazuh wodle |
| Entra ID | 15 | Azure AD via Wazuh Azure module |
| Windows | 50+ | WinEventLog via Wazuh agent |
| Linux | 50+ | auditd via Wazuh agent |
| Generic IdP | 15 | Normalized fields |

---

## Required Wazuh Modules

Enable these modules in `ossec.conf` on the Manager:

```xml
<!-- AWS CloudTrail integration -->
<wodle name="aws-s3">
  <disabled>no</disabled>
  <bucket type="cloudtrail">
    <name>your-cloudtrail-bucket</name>
    <aws_profile>default</aws_profile>
  </bucket>
</wodle>

<!-- Azure AD integration -->
<wodle name="azure-logs">
  <disabled>no</disabled>
  <tenant_domain>yourtenant.onmicrosoft.com</tenant_domain>
  <environment>GLOBAL</environment>
  <log_analytics>
    <application_id>YOUR_APP_ID</application_id>
    <application_key>YOUR_APP_KEY</application_key>
    <workspace>YOUR_WORKSPACE_ID</workspace>
    <query>AuditLogs | where TimeGenerated > ago(15m)</query>
    <timeout>30</timeout>
  </log_analytics>
</wodle>
```

!!! warning "Store credentials in Wazuh Keystore, not ossec.conf"
    Use `wazuh-keystore -f integrations -k azure_app_key -v YOUR_KEY` and reference
    it as `$_azure_app_key` in `ossec.conf`.

---

## Tuning

Override rule severity by adding child rules in your custom rules file:

```xml
<!-- Reduce SP-WZ-700043 (Okta failed logins) to INFO for service accounts -->
<rule id="100700043_exclude_svc" level="3">
  <if_sid>100700043</if_sid>
  <field name="data.okta.actor.alternateId">svc_.*@corp.local</field>
  <description>Exclude: Service account Okta login failures are expected</description>
</rule>
```
