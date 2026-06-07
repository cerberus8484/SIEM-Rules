# Detection Examples — Identity & IAM

Four fixtures covering AWS IAM and Okta — two True Positives and two False Positives.

---

## TP: AWS Root Account Console Login

**Rule:** SP-700021 / WZ-700006  
**Expected:** ALERT  
**Severity:** CRITICAL | Confidence: 95  
**MITRE:** T1078.004

```json
{
  "_comment": "TRUE POSITIVE — SP-700021: AWS root account console login",
  "rule_id": "SP-700021",
  "expected_result": "ALERT",
  "severity": "CRITICAL",
  "confidence": 95,
  "scenario": "AWS root account used for console login from unrecognized IP — no legitimate use case in production",
  "mitre": "T1078.004",
  "event": {
    "sourcetype": "aws:cloudtrail",
    "eventName": "ConsoleLogin",
    "userIdentity.type": "Root",
    "userIdentity.arn": "arn:aws:iam::123456789012:root",
    "sourceIPAddress": "198.51.100.42",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "awsRegion": "eu-central-1",
    "responseElements.ConsoleLogin": "Success",
    "time": "2024-01-15T02:33:00Z"
  },
  "why_tp": [
    "Root account has no MFA enabled (responseElements lacks MFA indicator)",
    "Login at 02:33 UTC — outside business hours for EU-based organization",
    "Source IP 198.51.100.42 not in approved admin IP range",
    "Root account should never be used for routine operations (AWS best practice)"
  ],
  "analyst_action": [
    "IMMEDIATELY: Rotate root account credentials and enable MFA",
    "Check: What actions were performed during this session (CloudTrail next 30 min)",
    "Check: Were any IAM users, roles, or policies created/modified?",
    "Check: Were CloudTrail logging settings changed?",
    "Escalate: If any resource modifications found, treat as compromise"
  ]
}
```

---

## FP: Scheduled Admin Provisioning (Not Root Login)

**Rule:** SP-700021  
**Expected:** NO_ALERT

```json
{
  "_comment": "FALSE POSITIVE — SP-700021: Monitoring service triggering non-root login",
  "rule_id": "SP-700021",
  "expected_result": "NO_ALERT",
  "scenario": "CloudWatch monitoring service using assumed role — not root, but role name contains 'root' substring",
  "event": {
    "sourcetype": "aws:cloudtrail",
    "eventName": "ConsoleLogin",
    "userIdentity.type": "AssumedRole",
    "userIdentity.sessionContext.sessionIssuer.userName": "monitoring-root-access-role",
    "sourceIPAddress": "52.94.76.1",
    "userAgent": "AWS Internal",
    "time": "2024-01-15T06:00:00Z"
  },
  "why_fp": [
    "userIdentity.type is 'AssumedRole', not 'Root' — different IAM principal type",
    "userAgent 'AWS Internal' indicates an AWS service, not a human login",
    "Source IP 52.94.76.1 is in the AWS service IP range"
  ],
  "tuning_recommendation": [
    "Add filter: userIdentity.type must equal 'Root' exactly (not substring match)",
    "Exclude userAgent = 'AWS Internal' — no human login uses this agent"
  ]
}
```

---

## TP: Okta Admin Role Granted to Non-Admin

**Rule:** SP-700041 / WZ-700012  
**Expected:** ALERT  
**Severity:** CRITICAL | Confidence: 90  
**MITRE:** T1098

```json
{
  "_comment": "TRUE POSITIVE — SP-700041: Okta admin role granted outside provisioning workflow",
  "rule_id": "SP-700041",
  "expected_result": "ALERT",
  "severity": "CRITICAL",
  "confidence": 90,
  "scenario": "Okta Super Administrator role granted to regular user without change ticket — possible privilege escalation",
  "mitre": "T1098",
  "event": {
    "sourcetype": "okta:system:log",
    "eventType": "user.account.privilege.grant",
    "actor.displayName": "John Smith",
    "actor.type": "User",
    "actor.id": "00u1abc2def3ghi4jkl5",
    "target[0].displayName": "Jane Doe",
    "target[0].type": "User",
    "target[1].displayName": "Super Administrator",
    "target[1].type": "AppUser",
    "client.ipAddress": "203.0.113.99",
    "client.userAgent.os": "Windows",
    "outcome.result": "SUCCESS",
    "time": "2024-01-15T14:22:00Z"
  },
  "why_tp": [
    "Super Administrator role granted — highest privilege in Okta",
    "Actor John Smith is a regular user, not an IT admin (no admin role in actor profile)",
    "No change ticket correlation found in ITSM (checked separately)",
    "Source IP 203.0.113.99 is not in the known IT admin IP range"
  ],
  "analyst_action": [
    "IMMEDIATELY: Revoke the Super Administrator role from Jane Doe",
    "Check: What actions did Jane Doe perform after the role grant?",
    "Check: How did John Smith get access to grant admin roles?",
    "Investigate: Was John Smith's account compromised?"
  ]
}
```

---

## FP: Legitimate Admin Provisioning via ITSM

**Rule:** SP-700041  
**Expected:** NO_ALERT

```json
{
  "_comment": "FALSE POSITIVE — SP-700041: Scheduled admin onboarding via approved workflow",
  "rule_id": "SP-700041",
  "expected_result": "NO_ALERT",
  "scenario": "IT admin grants Okta Help Desk role to new IT team member — correlated with open ITSM ticket",
  "event": {
    "sourcetype": "okta:system:log",
    "eventType": "user.account.privilege.grant",
    "actor.displayName": "IT Admin Service Account",
    "actor.type": "SystemPrincipal",
    "target[1].displayName": "Help Desk Administrator",
    "client.ipAddress": "10.0.1.50",
    "outcome.result": "SUCCESS",
    "time": "2024-01-15T09:00:00Z"
  },
  "why_fp": [
    "Actor is a SystemPrincipal (automated provisioning system), not a human",
    "Source IP 10.0.1.50 is the known ITSM integration server",
    "Role granted is 'Help Desk Administrator' — lowest admin tier, not Super Admin",
    "Timing aligns with scheduled Monday morning onboarding run"
  ],
  "tuning_recommendation": [
    "Suppress for actor.type = 'SystemPrincipal' from approved ITSM IP",
    "Add threshold: alert only on Super Administrator, Organization Administrator, or Application Administrator roles — not Help Desk"
  ]
}
```
