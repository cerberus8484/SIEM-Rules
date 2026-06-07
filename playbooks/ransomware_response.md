# Playbook: Ransomware Response

**ID:** PB-001 | **Schweregrad:** CRITICAL | **Version:** 1.0 | **Datum:** 2026-06-07

---

## Übersicht

Dieses Playbook führt Analysten Schritt für Schritt durch eine Ransomware-Investigation — vom ersten Alert bis zur Bestätigung oder Entwarnung. Alle Queries sind für alle 4 Plattformen angegeben.

**Erkennungsmerkmale (Trigger):**
- Alert auf `vssadmin delete shadows` / `bcdedit /set recoveryenabled no`
- Massenhafte Datei-Umbenennungen mit unbekannter Erweiterung
- AV/Backup-Dienste gestoppt
- Ransom-Note-Dateien (README_DECRYPT, HOW_TO_RECOVER)

---

## Phase 1 — Bestätigung (5 Minuten)

### Schritt 1.1 — Schatten-Kopien-Löschung bestätigen

**Splunk:**
```spl
index=windows host="<HOST>" EventCode=1
| where match(CommandLine, "(?i)(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|wbadmin.*delete.*catalog|bcdedit.*recoveryenabled.*no|diskshadow.*delete)")
| table _time, host, ParentImage, CommandLine
```

**QRadar:**
```sql
SELECT devicetime, hostname, UTF8(payload) FROM events
WHERE hostname = '<HOST>'
AND (UTF8(payload) ILIKE '%vssadmin%delete%shadows%'
  OR UTF8(payload) ILIKE '%bcdedit%recoveryenabled%no%'
  OR UTF8(payload) ILIKE '%wbadmin%delete%catalog%')
LAST 60 MINUTES
```

**Google SecOps:**
```
principal.hostname = "<HOST>" AND metadata.event_type = "PROCESS_LAUNCH"
AND (target.process.command_line ~ "vssadmin.*delete"
  OR target.process.command_line ~ "bcdedit.*recoveryenabled.*no"
  OR target.process.command_line ~ "wbadmin.*delete")
```

**Wazuh:**
```kql
agent.name: "<HOST>" AND data.win.system.eventID: "1"
AND (data.win.eventdata.commandLine: *vssadmin*delete*shadows*
  OR data.win.eventdata.commandLine: *bcdedit*recoveryenabled*no*
  OR data.win.eventdata.commandLine: *wbadmin*delete*catalog*)
```

**Ergebnis:** Wenn Treffer → Ransomware hochwahrscheinlich. Weiter mit 1.2.

---

### Schritt 1.2 — Backup/AV-Dienste gestoppt

**Splunk:**
```spl
index=windows host="<HOST>" EventCode IN (7036,7045)
| where match(Message, "(?i)(vss|backup|MsMpEng|MSSQL|SentinelOne|CrowdStrike|Sophos|Symantec|McAfee)")
| where match(Message, "(?i)(stopped|disabled)")
| table _time, host, Message
```

**Wazuh:**
```kql
agent.name: "<HOST>" AND data.win.system.eventID: ("7036" OR "7045")
AND (full_log: *VSS* OR full_log: *backup* OR full_log: *MsMpEng* OR full_log: *MSSQL*)
AND (full_log: *stopped* OR full_log: *disabled*)
```

---

### Schritt 1.3 — Ransom-Note-Dateien gefunden

**Splunk:**
```spl
index=windows host="<HOST>" EventCode=11
| where match(TargetFilename, "(?i)(README|DECRYPT|RECOVER|HOW_TO|HELP_RESTORE|LOCKED|RANSOM)")
| table _time, host, Image, TargetFilename
```

**Wazuh:**
```kql
agent.name: "<HOST>" AND syscheck.event: "added"
AND (syscheck.path: *README* OR syscheck.path: *DECRYPT* OR syscheck.path: *RECOVER* OR syscheck.path: *LOCKED*)
```

---

## Phase 2 — Ausbreitung prüfen (10 Minuten)

### Schritt 2.1 — Welche Hosts sind betroffen?

**Splunk:**
```spl
index=windows earliest="-2h" latest=now EventCode=1
| where match(CommandLine, "(?i)(vssadmin.*delete|bcdedit.*no|wbadmin.*delete|cipher /w|Stop-Service)")
| stats count values(CommandLine) as commands by host
| sort -count
```

**QRadar:**
```sql
SELECT hostname, COUNT(*) AS Anzahl
FROM events
WHERE (UTF8(payload) ILIKE '%vssadmin%delete%shadows%'
  OR UTF8(payload) ILIKE '%bcdedit%recoveryenabled%no%')
GROUP BY hostname
LAST 120 MINUTES
```

---

### Schritt 2.2 — Massendatei-Aktivität auf betroffenen Hosts

**Splunk:**
```spl
index=windows host="<HOST>" EventCode=2
| bin _time span=1m
| stats count dc(TargetFilename) as files by _time, host
| where count > 50
| eval rate_per_min=count
| table _time, host, files, rate_per_min
```

**Google SecOps:**
```
principal.hostname = "<HOST>" AND metadata.event_type = "FILE_CREATION"
```

---

### Schritt 2.3 — Initial Access identifizieren (Wie kam die Ransomware rein?)

**Splunk — Office spawnt Shell (Phishing):**
```spl
index=windows host="<HOST>" EventCode=1
| where match(ParentImage, "(?i)(winword|excel|powerpnt|outlook|onenote)")
AND match(Image, "(?i)(cmd\.exe|powershell|wscript|mshta|cscript)")
| table _time, host, ParentImage, Image, CommandLine
```

**Splunk — RDP-Login vor Ransomware-Aktivität:**
```spl
index=windows host="<HOST>" EventCode=4624
| where LogonType=10
| table _time, host, TargetUserName, IpAddress
| sort -_time
| head 10
```

---

### Schritt 2.4 — Seitwärtsbewegung des Angreifers

**Splunk:**
```spl
index=windows EventCode IN (4624,4648) TargetUserName=<USER>
| where LogonType IN (3,9,10)
| stats values(ComputerName) as targets count by TargetUserName
| where mvcount(targets) > 2
```

**Wazuh:**
```kql
data.win.eventdata.targetUserName: "<USER>"
AND data.win.system.eventID: ("4624" OR "4648")
AND (data.win.eventdata.logonType: "3" OR data.win.eventdata.logonType: "10")
```

---

## Phase 3 — Eindämmung (Containment)

### Entscheidungsmatrix

| Befund | Sofortmaßnahme |
|---|---|
| Einzelner Host betroffen | Host isolieren (Netzwerk), Ticket an IR |
| Mehrere Hosts betroffen | Netzwerk-Segment isolieren, IR-Team informieren |
| Domain Controller betroffen | Vollständige Netzwerk-Isolation, Notfall-IR |
| Backup-Systeme betroffen | Externe Backups prüfen, Air-Gap aktivieren |

### Schritt 3.1 — Laufende Verschlüsselungs-Prozesse identifizieren

**Splunk:**
```spl
index=windows host="<HOST>" EventCode=1
| where match(CommandLine, "(?i)(\.encrypted|\.locked|\.crypt|\.enc|\.ryuk|\.conti|\.lockbit)")
OR match(Image, "(?i)(/tmp/|/AppData/Local/Temp/).*\.exe")
| table _time, host, Image, CommandLine, ParentImage
```

### Schritt 3.2 — C2-Kommunikation blockieren

**Splunk — C2-Verbindungen des betroffenen Hosts:**
```spl
index=windows host="<HOST>" EventCode=3
| where NOT match(DestinationIp, "^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)") AND NOT match(DestinationIp, "^127\.")
| stats count values(DestinationPort) as ports by DestinationIp
| sort -count
```

---

## Phase 4 — Attribution (Welche Ransomware-Familie?)

### Bekannte Signaturen

| Familie | Datei-Extension | Ransom-Note | Vssadmin | Service-Stop |
|---|---|---|---|---|
| **LockBit 3.0** | `.lockbit` | `LockBit-README.txt` | ✅ | ✅ |
| **BlackCat/ALPHV** | `.sykffle`, `.zoldon` | `RECOVER-*-FILES.txt` | ✅ | ✅ |
| **Ryuk** | `.RYK` | `RyukReadMe.txt` | ✅ | ✅ |
| **Conti** | `.CONTI` | `CONTI_README.txt` | ✅ | ✅ |
| **BlackBasta** | `.basta` | `readme.txt` | ✅ | ✅ |
| **Royal** | `.royal` | `README.TXT` | ✅ | ✅ |
| **Hive** | `.hive`, `.key.hive` | `HOW_TO_DECRYPT.txt` | ✅ | ✅ |

**Splunk — Extension-Erkennung:**
```spl
index=windows host="<HOST>" EventCode=2
| rex field=TargetFilename "\.(?P<ext>[^.]+)$"
| where match(ext, "(?i)(lockbit|ryuk|conti|hive|basta|royal|blackcat|sykffle|zoldon|wncry|crypt)")
| stats count by ext, host
```

---

## Phase 5 — Dokumentation

### Pflichtfelder im Incident-Ticket

```
Datum/Uhrzeit Erstentdeckung: ________________
Betroffene Hosts: ________________
Betroffene Daten/Shares: ________________
Ransomware-Familie (wenn bekannt): ________________
Initialer Angriffsvektor: ________________
Maximale Ausbreitung bis Containment: ________________
Backup-Status: ________________  (intakt / betroffen / unbekannt)
IOCs (Hash, IP, Domain): ________________
MITRE-Techniken identifiziert: ________________
Benachrichtigte Stellen: ________________  (BSI / Strafverfolgung?)
```

---

## Checkliste

```
□ Phase 1: Ransomware-Aktivität bestätigt (VSS, Note, Dienste)
□ Phase 2: Ausbreitung kartiert (alle betroffenen Hosts)
□ Phase 2: Initial Access identifiziert
□ Phase 3: Betroffene Hosts/Segmente isoliert
□ Phase 3: C2 geblockt (Firewall-Regel)
□ Phase 4: Ransomware-Familie attributiert (wenn möglich)
□ Phase 5: Incident-Ticket vollständig dokumentiert
□ Backup-Status geprüft
□ Strafverfolgung / BSI informiert (falls erforderlich)
□ Lessons Learned eingeplant
```

---

*HuntingThreats Enterprise Hunt Pack · Playbook PB-001 · v1.0*
