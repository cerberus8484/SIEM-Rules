# Playbook: Account Takeover Investigation

**ID:** PB-002 | **Schweregrad:** HIGH | **Version:** 1.0 | **Datum:** 2026-06-07

---

## Übersicht

Dieses Playbook führt durch die Untersuchung eines verdächtigen oder kompromittierten Benutzerkontos — von der ersten Auffälligkeit bis zur Schadensanalyse und Eindämmung.

**Trigger:**
- Alert auf Passwort-Spray oder Brute-Force
- Login von unbekannter IP / Geographie
- MFA-Bypass-Indikator
- User meldet "Konto wurde gehackt"
- Ungewöhnliche Aktivität nach erfolgreichem Login

---

## Phase 1 — Erstbewertung (5 Minuten)

### Schritt 1.1 — Login-Fehlschläge analysieren

**Splunk:**
```spl
index=windows (EventCode=4625 OR EventCode=4771) TargetUserName="<USER>"
| table _time, EventCode, TargetUserName, IpAddress, LogonType, SubStatus, WorkstationName
| sort -_time
| head 50
```

**QRadar:**
```sql
SELECT DATEFORMAT(devicetime,'yyyy-MM-dd HH:mm:ss') AS Zeit,
  username, sourceip, UTF8(payload) AS Payload
FROM events
WHERE (category = 5002 OR UTF8(payload) ILIKE '%4625%')
  AND username = '<USER>'
ORDER BY devicetime DESC
LAST 1440 MINUTES
```

**Google SecOps:**
```
principal.user.userid = "<USER>" AND metadata.event_type = "USER_LOGIN_FAIL"
```

**Wazuh:**
```kql
data.win.eventdata.targetUserName: "<USER>"
AND data.win.system.eventID: ("4625" OR "4771")
```

---

### Schritt 1.2 — Ersten erfolgreichen Login nach Fehlschlägen finden

**Splunk:**
```spl
index=windows TargetUserName="<USER>" EventCode IN (4624,4625)
| eval status=if(EventCode=4624,"SUCCESS","FAIL")
| table _time, EventCode, status, IpAddress, LogonType, WorkstationName
| sort _time
```

**QRadar:**
```sql
SELECT DATEFORMAT(devicetime,'yyyy-MM-dd HH:mm:ss') AS Zeit,
  username, sourceip, category
FROM events
WHERE username = '<USER>'
  AND category IN (5001, 5002)
ORDER BY devicetime ASC
LAST 1440 MINUTES
```

---

### Schritt 1.3 — Von welchen IPs hat sich der User eingeloggt?

**Splunk:**
```spl
index=windows EventCode=4624 TargetUserName="<USER>"
| stats count latest(_time) as last_seen earliest(_time) as first_seen by IpAddress, LogonType
| sort -count
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M"), first_seen=strftime(first_seen,"%Y-%m-%d %H:%M")
```

**Wazuh:**
```kql
data.win.eventdata.targetUserName: "<USER>"
AND data.win.system.eventID: "4624"
```

---

## Phase 2 — Post-Compromise-Aktivität (15 Minuten)

### Schritt 2.1 — Was hat der Account nach dem Login getan?

**Splunk:**
```spl
index=windows EventCode=1 User="<USER>"
| table _time, host, Image, CommandLine, ParentImage
| sort _time
```

**Splunk — Netzwerkaktivität:**
```spl
index=windows EventCode=3 User="<USER>"
| where NOT match(DestinationIp, "^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)") AND NOT match(DestinationIp, "^127\.")
| table _time, host, Image, DestinationIp, DestinationPort
| sort -_time
```

---

### Schritt 2.2 — Wurden Gruppen oder Berechtigungen geändert?

**Splunk:**
```spl
index=windows EventCode IN (4728,4732,4756,4720,4722,4724,4738) SubjectUserName="<USER>" OR TargetUserName="<USER>"
| eval action=case(EventCode=4728,"AddToGlobalGroup", EventCode=4732,"AddToLocalGroup", EventCode=4756,"AddToUniversalGroup", EventCode=4720,"NewAccount", EventCode=4722,"EnableAccount", EventCode=4724,"PasswordReset", EventCode=4738,"AccountModified")
| table _time, EventCode, action, SubjectUserName, TargetUserName, MemberName
```

**Wazuh:**
```kql
(data.win.eventdata.subjectUserName: "<USER>" OR data.win.eventdata.targetUserName: "<USER>")
AND data.win.system.eventID: ("4728" OR "4732" OR "4756" OR "4720" OR "4724" OR "4738")
```

---

### Schritt 2.3 — Passwort-Änderungen durch oder für diesen Account

**Splunk:**
```spl
index=windows EventCode IN (4723,4724) (SubjectUserName="<USER>" OR TargetUserName="<USER>")
| table _time, EventCode, SubjectUserName, TargetUserName, SubjectDomainName
| sort _time
```

---

### Schritt 2.4 — Neue Accounts nach Compromise erstellt?

**Splunk:**
```spl
index=windows EventCode=4720
| table _time, SubjectUserName, TargetUserName, SamAccountName
| sort -_time
| head 20
```

---

### Schritt 2.5 — Privilegierte Befehle ausgeführt?

**Splunk:**
```spl
index=windows EventCode=4672 SubjectUserName="<USER>"
| table _time, SubjectUserName, PrivilegeList, SubjectLogonId
| sort _time
```

**Google SecOps:**
```
principal.user.userid = "<USER>" AND metadata.event_type = "USER_CHANGE_PERMISSIONS"
```

---

## Phase 3 — Lateral Movement prüfen

### Schritt 3.1 — Hat der Account sich auf andere Systeme verbunden?

**Splunk:**
```spl
index=windows EventCode IN (4624,4648) TargetUserName="<USER>"
| where LogonType IN (3,9,10)
| stats count values(IpAddress) as src_ips by ComputerName
| where mvcount(split(ComputerName," ")) > 1 OR count > 5
| sort -count
```

**QRadar:**
```sql
SELECT destinationip AS Ziel, sourceip AS Quelle, COUNT(*) AS Verbindungen
FROM events
WHERE username = '<USER>'
  AND (category = 5001)
  AND (UTF8(payload) ILIKE '%LogonType%3%' OR UTF8(payload) ILIKE '%LogonType%10%')
GROUP BY destinationip, sourceip
LAST 1440 MINUTES
```

---

### Schritt 3.2 — Admin-Shares zugegriffen?

**Splunk:**
```spl
index=windows EventCode=5140 SubjectUserName="<USER>"
| where match(ShareName, "(?i)(ADMIN\$|C\$|D\$|IPC\$)")
| table _time, SubjectUserName, ComputerName, ShareName, IpAddress
```

---

### Schritt 3.3 — Remote-Execution auf anderen Systemen?

**Splunk — WMI:**
```spl
index=windows EventCode=1 User="<USER>"
| where match(Image, "(?i)wmiprvse") AND match(CommandLine, "(?i)cmd|powershell|net")
| table _time, host, Image, CommandLine, ParentImage
```

**Splunk — PsExec-Pattern:**
```spl
index=windows EventCode=5145 SubjectUserName="<USER>"
| where match(RelativeTargetName, "PSEXESVC")
| table _time, SubjectUserName, ComputerName, RelativeTargetName, IpAddress
```

---

## Phase 4 — Cloud Account prüfen (Azure AD / M365)

### Schritt 4.1 — Azure AD Sign-in des Users

**Splunk:**
```spl
index=azure sourcetype="azure:aad:signin" "properties.userPrincipalName"="<USER>"
| table _time, "properties.userPrincipalName", callerIpAddress, "properties.location.city", "properties.location.countryOrRegion", "properties.clientAppUsed", "properties.status.errorCode"
| sort -_time
| head 30
```

### Schritt 4.2 — M365 Aktivitäten des Users

**Splunk:**
```spl
index=o365 sourcetype="ms:o365:management" UserId="<USER>"
| stats count by Operation, Workload
| sort -count
```

### Schritt 4.3 — Mailbox-Forwarding-Regeln des Users

**Splunk:**
```spl
index=o365 sourcetype="ms:o365:management" UserId="<USER>"
  (Operation="New-InboxRule" OR Operation="Set-InboxRule" OR Operation="New-TransportRule")
| table _time, UserId, Operation, ClientIP, Parameters
```

---

## Phase 5 — Eindämmung & Recovery

### Entscheidungsmatrix

| Szenario | Sofortmaßnahme |
|---|---|
| Login von externer IP, kein Lateral Movement | Passwort-Reset + MFA erzwingen |
| Lateral Movement auf 1-3 Systeme | Account sperren + betroffene Systeme prüfen |
| Gruppenänderungen / neue Accounts | Alle Änderungen rückgängig + vollständige IR |
| M365 Forwarding-Regel | Regel löschen + alle aktiven Sessions beenden |
| Cloud Admin-Privilege erworben | Account-Sperrung + alle Tokens widerrufen |

### Eindämmungs-Queries

**Splunk — Alle aktiven Sessions des Users finden:**
```spl
index=windows EventCode=4624 TargetUserName="<USER>"
| where NOT match(TargetUserName, "\\$")
| stats latest(_time) as letzte_session by LogonId, ComputerName, IpAddress, LogonType
| eval letzte_session=strftime(letzte_session,"%Y-%m-%d %H:%M")
```

---

## Checkliste

```
□ Login-Fehlschläge analysiert und Zeitraum eingegrenzt
□ Erste erfolgreiche Auth nach Fehlschlägen identifiziert
□ Quell-IPs kartiert und bewertet (intern / extern / VPN)
□ Post-Compromise-Aktivität vollständig erfasst
□ Gruppen-/Berechtigungsänderungen geprüft
□ Lateral Movement auf andere Systeme geprüft
□ Cloud-Aktivität (Azure AD / M365) geprüft
□ Mailbox-Forwarding-Regeln geprüft
□ Neue Accounts/Backdoors identifiziert und entfernt
□ Passwort-Reset durchgeführt
□ MFA erzwungen / wiederhergestellt
□ Alle aktiven Sessions beendet
□ Incident-Ticket vollständig dokumentiert
```

---

*HuntingThreats Enterprise Hunt Pack · Playbook PB-002 · v1.0*
