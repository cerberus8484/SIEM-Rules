# Playbook: Insider Threat Investigation

**ID:** PB-004 | **Schweregrad:** HIGH | **Version:** 1.0 | **Datum:** 2026-06-07

---

## Übersicht

Dieses Playbook unterstützt die Untersuchung eines Insider-Threat-Verdachts — ob ein aktueller oder ausscheidender Mitarbeiter Daten entwendet, Systeme sabotiert oder Zugriffsrechte missbraucht.

**Wichtiger Hinweis:** Insider-Threat-Untersuchungen erfordern **Abstimmung mit HR, Legal und Datenschutz**, bevor umfangreiche personenbezogene Daten gesammelt werden.

**Trigger:**
- HR meldet geplante Kündigung/Entlassung
- Auffällig hohe Datei-Download-Aktivität
- Zugriff außerhalb der normalen Arbeitszeiten
- USB-Device-Verbindung mit großer Datenmenge
- Alert auf Massendownload aus SharePoint/OneDrive
- Kollege meldet verdächtiges Verhalten

---

## Phase 1 — Basis-Aktivitätsprofil erstellen (10 Minuten)

### Schritt 1.1 — Login-Zeiten des Users analysieren

**Splunk:**
```spl
index=windows EventCode=4624 TargetUserName="<USER>"
| eval hour=tonumber(strftime(_time,"%H")), weekday=strftime(_time,"%A")
| stats count by hour, weekday
| sort weekday, hour
```

**Splunk — After-Hours-Logins:**
```spl
index=windows EventCode=4624 TargetUserName="<USER>"
| eval hour=tonumber(strftime(_time,"%H"))
| where hour < 7 OR hour > 20
| table _time, hour, TargetUserName, IpAddress, LogonType, WorkstationName
| sort _time
```

**QRadar:**
```sql
SELECT DATEFORMAT(devicetime,'yyyy-MM-dd HH:mm:ss') AS Zeit,
  username, sourceip,
  EXTRACT(HOUR FROM devicetime) AS Stunde
FROM events
WHERE username = '<USER>' AND category = 5001
  AND (EXTRACT(HOUR FROM devicetime) < 7 OR EXTRACT(HOUR FROM devicetime) > 20)
LAST 30 DAYS
```

---

### Schritt 1.2 — Datei-Zugriffe im Vergleich zum Baseline

**Splunk — Datei-Leserate in letzten 7 Tagen:**
```spl
index=windows EventCode IN (4663,11) SubjectUserName="<USER>" OR User="<USER>"
| bin _time span=1d
| stats count by _time, User
| sort _time
```

**Splunk — Zugriff auf sensitive Verzeichnisse:**
```spl
index=windows EventCode=4663 SubjectUserName="<USER>"
| where match(ObjectName, "(?i)(HR|Personal|Payroll|Vertraulich|Confidential|Customer|Finance|Strategy|M&A|Acquisition)")
| table _time, SubjectUserName, ObjectName, AccessMask, ProcessName
| sort _time
```

---

### Schritt 1.3 — USB / Removable Media Aktivität

**Splunk:**
```spl
index=windows (EventCode=20001 OR EventCode=4663)
| where match(_raw, "(?i)(removable|USB|HID|USBSTOR)")
| table _time, host, user, _raw
| sort -_time
```

**Wazuh:**
```kql
agent.name: "<HOST>" AND (full_log: *USBSTOR* OR full_log: *removable* OR full_log: *USB*)
AND rule.level >= 5
```

---

## Phase 2 — Daten-Staging und Exfiltration

### Schritt 2.1 — Massenhafte Datei-Kopien in persönliche Ordner

**Splunk:**
```spl
index=windows EventCode IN (11,2) User="<USER>"
| where match(TargetFilename, "(?i)(desktop|downloads|OneDrive.*Personal|C:\\Users\\<USER>)") AND NOT match(TargetFilename, "\.tmp$|\.log$")
| bin _time span=1h
| stats count dc(TargetFilename) as unique_files by _time, host
| where count > 100 OR unique_files > 50
```

**Splunk — Archive-Dateien erstellt (ZIP, RAR, 7z):**
```spl
index=windows EventCode=11 User="<USER>"
| where match(TargetFilename, "(?i)(\.zip$|\.rar$|\.7z$|\.tar\.gz$|\.tar$)")
| table _time, host, User, TargetFilename, Image
| sort -_time
```

---

### Schritt 2.2 — Cloud-Sync ungewöhnlich aktiv

**Splunk:**
```spl
index=windows EventCode=3 User="<USER>"
| where match(DestinationHostname, "(?i)(dropbox|drive\.google|onedrive|wetransfer|mega\.nz|box\.com|icloud|sync\.com|pcloud)")
| bin _time span=1h
| stats sum(bytes_out) as uploaded count by _time, DestinationHostname
| eval uploaded_mb=round(uploaded/1048576,1)
| where uploaded_mb > 100
```

**M365 Splunk:**
```spl
index=o365 sourcetype="ms:o365:management" UserId="<USER>" Operation="FileDownloaded"
| bin _time span=1h
| stats count dc(ObjectId) as files sum(bytes) as bytes by _time
| eval mb=round(bytes/1048576,1)
| where count > 50 OR mb > 500
```

---

### Schritt 2.3 — E-Mail-Exfiltration

**Splunk — Emails an externe Adresse:**
```spl
index=o365 sourcetype="ms:o365:management" UserId="<USER>" (Operation="Send" OR Operation="SendAs")
| where match(RecipientAddress, "(?i)(@gmail|@yahoo|@proton|@tutanota|@outlook\.com)") AND NOT match(RecipientAddress, "@<COMPANY_DOMAIN>")
| table _time, UserId, RecipientAddress, Subject, ClientIP
| sort -_time
```

**Splunk — Mailbox-Forwarding-Regeln des Users:**
```spl
index=o365 sourcetype="ms:o365:management" UserId="<USER>"
  (Operation="New-InboxRule" OR Operation="Set-InboxRule")
| table _time, UserId, Operation, ClientIP, Parameters
```

---

### Schritt 2.4 — Browser-Downloads

**Splunk:**
```spl
index=windows EventCode=11 User="<USER>"
| where match(Image, "(?i)(chrome|firefox|edge|msedge|iexplore)") AND match(TargetFilename, "(?i)(\.pdf$|\.docx$|\.xlsx$|\.csv$|\.zip$|\.rar$)")
| bin _time span=1h
| stats count dc(TargetFilename) as files by _time, host
| where count > 20
```

---

## Phase 3 — Sabotage-Muster erkennen

### Schritt 3.1 — Massenhafte Löschungen

**Splunk:**
```spl
index=windows EventCode=4660 SubjectUserName="<USER>"
| bin _time span=1h
| stats count by _time, host, SubjectUserName
| where count > 50
```

**Splunk — Recycle Bin Aktivität:**
```spl
index=windows EventCode=11 User="<USER>"
| where match(TargetFilename, "(?i)(Recycle\.Bin|\\$Recycle)")
| bin _time span=1h
| stats count by _time, host
| where count > 20
```

---

### Schritt 3.2 — Account- oder Berechtigungsänderungen

**Splunk:**
```spl
index=windows EventCode IN (4728,4729,4732,4733,4756,4757,4720,4726) SubjectUserName="<USER>"
| eval action=case(EventCode=4720,"Create Account", EventCode=4726,"Delete Account", EventCode=4728,"Add to Group", EventCode=4729,"Remove from Group", EventCode=4732,"Add Local Group", EventCode=4733,"Remove Local Group", true(),"Other")
| table _time, EventCode, action, SubjectUserName, TargetUserName, MemberName
```

---

### Schritt 3.3 — Backup-Systeme oder Logs gelöscht/manipuliert

**Splunk:**
```spl
index=windows EventCode IN (1,4688) User="<USER>"
| where match(CommandLine, "(?i)(vssadmin|wbadmin|bcdedit|wevtutil|clear-eventlog|delete.*backup)")
| table _time, host, User, Image, CommandLine
```

---

## Phase 4 — Zeitachse rekonstruieren

### Schritt 4.1 — Vollständige Aktivitäts-Timeline für Zeitraum

**Splunk:**
```spl
index=windows (User="<USER>" OR SubjectUserName="<USER>" OR TargetUserName="<USER>") earliest="<START>" latest="<END>"
| eval category=case(EventCode=4624,"Login", EventCode=4625,"FailedLogin", EventCode=4663,"FileAccess", EventCode=4660,"FileDelete", EventCode=1,"ProcessStart", EventCode=3,"NetworkConn", EventCode=11,"FileCreate", EventCode=13,"RegistryWrite", true(),"Other")
| table _time, category, EventCode, host, Image, CommandLine, TargetFilename, DestinationIp, ObjectName
| sort _time
```

---

### Schritt 4.2 — Letzter Arbeitstag Aktivität (Off-Boarding-Risiko)

**Splunk:**
```spl
index=windows (User="<USER>" OR SubjectUserName="<USER>") earliest="<LAST_WORKDAY_START>" latest="<LAST_WORKDAY_END>"
| eval category=case(EventCode=11 AND match(TargetFilename,"(?i)\.zip|\.rar|\.7z"),"ARCHIV", EventCode=3 AND NOT match(DestinationIp,"^(10\.|192\.168\.|172\.)"), "EXT_NETZWERK", EventCode=4663 AND match(ObjectName,"(?i)(confidential|HR|Finance|Strategy)"), "SENSITIVE_FILE", true(),"ANDERE")
| stats count by category
| sort -count
```

---

## Phase 5 — Dokumentation und Übergabe

### Untersuchungsergebnis-Formular

```
Untersuchte Person: ________________  (Initialen oder HR-ID)
Untersuchungszeitraum: ________________
Anlass: ________________  (Kündigung / Entlassung / Incident-Report / Verdacht)

Befund: □ Kein Verdacht erhärtet  □ Verdacht teilweise bestätigt  □ Eindeutige Exfiltration

Datei-Exfiltration:
  Volumen: ________________ MB/GB
  Ziel: ________________  (USB / Cloud / Email / Extern)
  Dateitypen: ________________

After-Hours-Zugriffe:
  Anzahl: ________________
  Zeitraum: ________________
  Systeme: ________________

Mailbox-Forwarding: □ Ja  □ Nein
USB-Aktivität:      □ Ja  □ Nein
Massendownload:     □ Ja  □ Nein
Löschaktivität:     □ Ja  □ Nein

Weiterleitung an: □ HR  □ Legal  □ Management  □ Strafverfolgung
```

---

## Checkliste

```
□ Genehmigung durch HR / Legal eingeholt
□ Datenschutzbeauftragten informiert (bei umfangreicher Überwachung)
□ Login-Zeiten analysiert (After-Hours-Logins)
□ Datei-Zugriffsrate mit Baseline verglichen
□ USB-Aktivität geprüft
□ Cloud-Sync-Aktivität geprüft
□ E-Mail-Forwarding-Regeln geprüft
□ Massendownload aus SharePoint/OneDrive geprüft
□ Archive-Erstellung geprüft (ZIP/RAR)
□ Löschaktivitäten geprüft
□ Vollständige Timeline erstellt
□ Letzter Arbeitstag gesondert analysiert
□ Ergebnis dokumentiert und an zuständige Stelle übergeben
□ Account nach HR-Freigabe deaktiviert
```

---

*HuntingThreats Enterprise Hunt Pack · Playbook PB-004 · v1.0*
