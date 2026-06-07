# Analyst Query Library — Benutzerhandbuch

**HuntingThreats Enterprise Hunt Pack · Analyst Edition**  
Version 1.0.0 · 2026-06-07 · 200 Queries · 4 Plattformen

---

## Inhaltsverzeichnis

1. [Was sind Analyst Queries?](#1-was-sind-analyst-queries)
2. [Unterschied: Hunt Rules vs. Analyst Queries](#2-unterschied-hunt-rules-vs-analyst-queries)
3. [Query-Struktur und Aufbau](#3-query-struktur-und-aufbau)
4. [Parameter-Referenz](#4-parameter-referenz)
5. [Kategorien-Übersicht](#5-kategorien-übersicht)
6. [Verwendung — Splunk](#6-verwendung--splunk)
7. [Verwendung — QRadar](#7-verwendung--qradar)
8. [Verwendung — Google SecOps](#8-verwendung--google-secops)
9. [Verwendung — Wazuh](#9-verwendung--wazuh)
10. [Typische Investigationsworkflows](#10-typische-investigationsworkflows)
11. [Tipps für den Analyst-Alltag](#11-tipps-für-den-analyst-alltag)
12. [Cheat Sheet](#12-cheat-sheet)

---

## 1. Was sind Analyst Queries?

Analyst Queries sind **fertige, sofort nutzbare Suchabfragen** für Security-Analysten im Triage- und Investigation-Alltag. Sie unterscheiden sich von Hunt Rules dadurch, dass sie:

- **interaktiv** ausgeführt werden — manuell, gezielt, anlassbezogen
- **parameterisiert** sind — du tauschst `<HOST>` gegen den echten Hostnamen aus
- **keine Alerting-Logik** enthalten — sie antworten auf eine Frage, die du gerade hast
- **schnell** sind — optimiert auf einfaches Copy-Paste in die SIEM-Oberfläche

**Typische Anwendungsfälle:**
- Alert wurde getriggert → du willst mehr Kontext
- Ticket kommt rein: "User xyz hat seltsames Verhalten gezeigt"
- Incident läuft: schnelle Timeline-Rekonstruktion
- Threat Intelligence: neue IOC → sofortiger Environment-Scan

---

## 2. Unterschied: Hunt Rules vs. Analyst Queries

| Eigenschaft | Hunt Rules | Analyst Queries |
|---|---|---|
| **Ausführung** | Automatisch / Scheduled | Manuell, on-demand |
| **Zweck** | Alerting, kontinuierliche Überwachung | Triage, Investigation |
| **Parameter** | Statisch, in der Regel eingebaut | Dynamisch, `<PLATZHALTER>` ersetzen |
| **Ergebnis** | Alert / Finding | Suchergebnisse, Tabellen |
| **Zeitfenster** | Festes Lookback-Window | Frei wählbar über UI |
| **Komplexität** | Hohe Logik (Threshold, Correlation) | Einfach, direkt, lesbar |
| **Dateien** | `hunts/<plattform>/` | `analyst_queries/<plattform>/` |

---

## 3. Query-Struktur und Aufbau

Jede Query ist nach folgendem Schema aufgebaut:

```
/* AQ-<PLATTFORM>-<NUMMER> | <KATEGORIE> | <TITEL>
   USE CASE: Was beantwortet diese Query?
   PARAMETER: Welche <PLATZHALTER> müssen ersetzt werden? */
<eigentliche Query>
```

### Query-ID Schema

```
AQ  - Analyst Query (Präfix, immer gleich)
SPL - Plattform: SPL=Splunk, QR=QRadar, GS=Google SecOps, WZ=Wazuh
001 - Laufende Nummer innerhalb der Plattform (001–050)
```

**Beispiele:**
- `AQ-SPL-001` → Splunk, Query #1
- `AQ-QR-009` → QRadar, Query #9
- `AQ-GS-025` → Google SecOps, Query #25
- `AQ-WZ-041` → Wazuh, Query #41

### Annotiertes Beispiel (Splunk)

```spl
/* AQ-SPL-001 | Triage | Alle Events eines Hosts — letzten 24h
   ↑               ↑       ↑
   Query-ID     Kategorie  Titel

   USE CASE: Erster Überblick nach Alert auf Endpunkt
   ↑ Wofür wird diese Query eingesetzt?

   PARAMETER: <HOST>
   ↑ Was muss ich ersetzen? */

index=windows host="<HOST>"      ← <HOST> = echter Hostname
| eval EventCodeStr=tostring(EventCode)
| stats count by EventCodeStr, Source
| sort -count
| rename EventCodeStr as "Event Code", Source as Quelle, count as Anzahl
```

---

## 4. Parameter-Referenz

Alle Platzhalter sind mit `<` und `>` markiert. Vor der Ausführung **alle** Platzhalter ersetzen.

| Parameter | Beschreibung | Beispiel |
|---|---|---|
| `<HOST>` | Hostname des Systems | `WIN10-CLIENT01`, `srv-dc01` |
| `<USER>` | Benutzername | `jsmith`, `DOMAIN\jsmith`, `jsmith@corp.local` |
| `<IP>` | IP-Adresse | `192.168.1.55`, `185.220.101.1` |
| `<DOMAIN>` | Domain-Name | `evil-c2.example.com`, `*.onion` |
| `<PROCESS>` | Prozessname (mit oder ohne .exe) | `powershell.exe`, `cmd.exe` |
| `<STRING>` | Beliebiger Suchstring / Keyword | `-EncodedCommand`, `mimikatz` |
| `<HASH>` | Datei-Hash (SHA256 oder MD5) | `d41d8cd98f00b204e9800998ecf8427e` |
| `<PATH>` | Dateipfad oder Pfad-Muster | `\\Temp\\`, `C:\Windows\System32` |
| `<START>` | Startzeitpunkt | `2026-06-07T08:00:00` |
| `<END>` | Endzeitpunkt | `2026-06-07T18:00:00` |
| `<PORT>` | TCP/UDP-Port-Nummer | `4444`, `443`, `9001` |
| `<N>` | Numerischer Schwellenwert | `10`, `50`, `100` |

### Plattform-Besonderheiten beim Ersetzen

**Splunk:** Wildcards mit `*` — z.B. `Image="*\\powershell.exe"`  
**QRadar:** Wildcards mit `%` in ILIKE — z.B. `ILIKE '%powershell%'`  
**Google SecOps:** Regex mit `~` — z.B. `~ "powershell"`  
**Wazuh/KQL:** Wildcards mit `*` — z.B. `data.win.eventdata.image: *powershell.exe*`

---

## 5. Kategorien-Übersicht

Die 50 Queries jeder Plattform sind in 9 Kategorien eingeteilt:

| Kategorie | Query-Nummern | Beschreibung |
|---|---|---|
| **Triage & Timeline** | 001–008 | Erster Überblick, Zeitlinien, Host-Übersicht |
| **Authentication & Accounts** | 009–016 | Logins, Fehlschläge, neue Accounts, Gruppen |
| **Prozess & Ausführung** | 017–024 | Prozessbäume, Commandlines, Hashes |
| **Netzwerk & C2** | 025–031 | Verbindungen, DNS, Beaconing, Ports |
| **Dateisystem** | 032–036 | Dateierstellungen, Drops, Staging-Pfade |
| **Persistenz** | 037–040 | Registry, Tasks, Dienste, Startup |
| **Credential Access** | 041–045 | LSASS, Dumps, Kerberos, Brute Force |
| **Lateral Movement** | 046–049 | RDP, SMB, WMI, PsExec |
| **Discovery & Recon** | 050 | Recon-Tool-Burst, Enumeration |

---

## 6. Verwendung — Splunk

### Datei
`analyst_queries/splunk/analyst_queries.spl`

### Wo eingeben?
`Splunk Web UI → Search & Reporting → Search-Bar`

### Schritt-für-Schritt
1. `analyst_queries.spl` in Editor öffnen
2. Gewünschte Query anhand der Kommentar-ID (`/* AQ-SPL-XXX */`) finden
3. `<PARAMETER>` durch echten Wert ersetzen
4. Query in die Splunk-Suchleiste kopieren (nur den Query-Block, nicht den Kommentar)
5. Zeitfenster über den Time-Picker oben rechts setzen (oder `earliest=` / `latest=` inline)
6. Suche starten

### Zeitfenster-Optionen in Splunk

| Ziel | Methode |
|---|---|
| Letzte 24h | Time-Picker: "Last 24 hours" |
| Letzter Monat | Time-Picker: "Last 30 days" |
| Individueller Zeitraum | Time-Picker: "Custom time" |
| Inline im Query | `earliest="-24h" latest=now` |
| Absoluter Zeitraum | `earliest="2026-06-07T08:00:00" latest="2026-06-07T18:00:00"` |

### Query-Ausgabe anpassen

```spl
-- Mehr Felder anzeigen:
| table _time, host, user, Image, CommandLine, <WEITERES_FELD>

-- Alle Felder anzeigen:
| table *

-- Ergebnisse exportieren:
-- Job → Export → CSV

-- Als Dashboard-Panel speichern:
-- Suche ausführen → "Save As" → Dashboard Panel
```

### Splunk-Tipps

```spl
-- Fuzzy-Suche (case-insensitive):
CommandLine="*powershell*"   -- Wildcards sind case-insensitive

-- Mehrere Werte (OR):
EventCode IN (4624, 4625, 4648)

-- Negation:
NOT Image="*\\svchost.exe"

-- Zeitstempel formatieren:
| eval ts=strftime(_time, "%Y-%m-%d %H:%M:%S")

-- Ergebnisse begrenzen:
| head 100
```

---

## 7. Verwendung — QRadar

### Datei
`analyst_queries/qradar/analyst_queries.aql`

### Wo eingeben?
`QRadar Console → Log Activity → Add Filter → Advanced Search`  
oder: `QRadar Console → Offenses → Event Search`

### Schritt-für-Schritt
1. `analyst_queries.aql` in Editor öffnen
2. Gewünschte Query anhand des Kommentars (`-- AQ-QR-XXX`) finden
3. `<PARAMETER>` durch echten Wert ersetzen
4. Query in das AQL-Suchfeld kopieren (nur SELECT-Block, ohne Kommentare)
5. "Search" oder "Execute Query" klicken

### AQL-Zeitfenster-Optionen

```sql
-- Relative Zeitfenster:
LAST 60 MINUTES          -- letzte Stunde
LAST 1440 MINUTES        -- letzte 24h
LAST 10080 MINUTES       -- letzte 7 Tage

-- Absoluter Zeitraum:
START '2026-06-07 08:00' STOP '2026-06-07 18:00'

-- Tipp: LAST N MINUTES ans Ende der Query, NICHT in die WHERE-Klausel
```

### AQL-Syntax-Referenz

```sql
-- Enthält (case-insensitive):
UTF8(payload) ILIKE '%powershell%'

-- Exakter Wert:
sourceip = '192.168.1.55'

-- Liste:
category IN (5001, 5002)

-- NICHT:
NOT (sourceip ILIKE '10.%')

-- Aggregation:
GROUP BY hostname HAVING COUNT(*) > 10

-- Ergebnis begrenzen:
(ans Ende der Query, vor LAST N MINUTES)
-- In QRadar gibt es kein LIMIT — nutze Top N im UI
```

### QRadar-Tipps

- **Payload-Suche:** `UTF8(payload) ILIKE '%string%'` — sucht im Rohlog
- **Custom Properties:** Wenn Felder wie `hostname` leer sind → `UTF8(payload) ILIKE '%hostname%'` verwenden
- **Ergebnis speichern:** Query → Save → "Saved Search" — später über Log Activity → Saved Searches abrufbar
- **Performance:** `LAST N MINUTES` statt absolutem Zeitraum — schneller
- **Payload-Debug:** Spalte `UTF8(payload)` immer mitanzeigen — sieht man was wirklich im Log steht

---

## 8. Verwendung — Google SecOps

### Datei
`analyst_queries/secops/analyst_queries.udm`

### Wo eingeben?
`Google SecOps (Chronicle) → Search → UDM Search`

### Schritt-für-Schritt
1. `analyst_queries.udm` in Editor öffnen
2. Gewünschte Query anhand des Kommentars (`// AQ-GS-XXX`) finden
3. `<PARAMETER>` durch echten Wert ersetzen
4. Query in die UDM Search Bar kopieren (nur den Query-Ausdruck, ohne Kommentare)
5. Zeitfenster über den Time-Picker setzen
6. "Search" klicken

### UDM Search Syntax

```
-- Gleichheit:
principal.hostname = "WIN10-CLIENT01"

-- Enthält (Regex):
target.process.command_line ~ "powershell"

-- Case-insensitiv:
principal.hostname nocase "WIN10-CLIENT01"

-- UND:
principal.hostname = "HOST" AND metadata.event_type = "PROCESS_LAUNCH"

-- ODER:
target.port = 443 OR target.port = 8443

-- NICHT:
NOT target.ip ~ "^(10\.|192\.168\.)"

-- Array-Felder:
network.dns.questions.name ~ "evil.com"
```

### UDM Event Types — Wichtigste

| Event Type | Bedeutung | Sysmon Event |
|---|---|---|
| `PROCESS_LAUNCH` | Prozessstart | EventCode 1 |
| `NETWORK_CONNECTION` | Netzwerkverbindung | EventCode 3 |
| `DNS_RESOLUTION` | DNS-Anfrage | EventCode 22 |
| `FILE_CREATION` | Datei erstellt | EventCode 11 |
| `REGISTRY_MODIFICATION` | Registry geändert | EventCode 13 |
| `USER_LOGIN` | Erfolgreicher Login | EventCode 4624 |
| `USER_LOGIN_FAIL` | Fehlgeschlagener Login | EventCode 4625 |
| `USER_CREATION` | Neuer Account | EventCode 4720 |
| `SERVICE_INSTALLATION` | Dienst installiert | EventCode 7045 |
| `SCHEDULED_TASK_CREATION` | Task erstellt | EventCode 4698 |

### UDM Feldpfade — Wichtigste

```
principal.hostname          → Quell-Host
principal.ip                → Quell-IP
principal.user.userid       → Quell-Nutzer
principal.process.file.full_path   → Elternprozess-Pfad
principal.process.command_line     → Elternprozess-Commandline

target.hostname             → Ziel-Host
target.ip                   → Ziel-IP
target.port                 → Ziel-Port
target.process.file.full_path      → Prozess-Pfad
target.process.command_line        → Prozess-Commandline
target.process.file.sha256         → SHA256-Hash
target.file.full_path              → Dateipfad
target.registry.registry_key       → Registry-Schlüssel

metadata.event_type         → Event-Typ (PROCESS_LAUNCH etc.)
metadata.vendor_name        → Log-Quelle (microsoft, google, etc.)
network.dns.questions.name  → DNS-Anfrage-Domain
```

### Google SecOps Tipps

- **Zeitfenster:** Über den Time-Picker — "Last 24h", "Last 7d", "Custom Range"
- **Ergebnis-Ansicht:** UDM-Felder werden strukturiert angezeigt — einzelne Events aufklappen für Details
- **Regex-Tipp:** `~` erwartet valides Regex — spezielle Zeichen escapen: `\\.`, `\\\\`
- **Entity Graph:** IOC (IP, Domain, Hash) in die Suche eingeben → Chronicle zeigt Graph-Visualisierung
- **Saved Searches:** Suche → Disketten-Icon → für wiederkehrende Investigations speichern

---

## 9. Verwendung — Wazuh

### Datei
`analyst_queries/wazuh/analyst_queries.kql`

### Wo eingeben?
`Wazuh Dashboard → Security Events → KQL-Suchleiste (oben)`  
oder: `Wazuh Dashboard → Discover → Index wazuh-alerts-* → KQL-Suchleiste`

### Schritt-für-Schritt
1. `analyst_queries.kql` in Editor öffnen
2. Gewünschte Query anhand des Kommentars (`/* AQ-WZ-XXX */`) finden
3. `<PARAMETER>` durch echten Wert ersetzen
4. Query in die KQL-Suchleiste kopieren (nur den KQL-Ausdruck, nicht den Kommentar)
5. Zeitfenster über den Zeit-Selector oben rechts setzen
6. Enter drücken

### KQL-Syntax-Referenz

```kql
-- Gleichheit:
agent.name: "WIN10-CLIENT01"

-- Enthält (Wildcard):
data.win.eventdata.commandLine: *powershell*

-- Mehrere Werte (OR):
data.win.system.eventID: ("4624" OR "4625" OR "4648")

-- Bereich (numerisch):
rule.level >= 10

-- UND:
agent.name: "HOST" AND rule.level >= 10

-- NICHT:
NOT data.srcip: 10.*

-- Existiert:
data.win.eventdata.commandLine: *

-- Exakter Match:
rule.id: "92650"
```

### Wichtige Wazuh-Felder

```
agent.name                          → Hostname des Agents
agent.ip                            → Agent-IP
rule.id                             → Wazuh-Rule-ID
rule.level                          → Schweregrad (1–15)
rule.description                    → Regel-Beschreibung
rule.groups                         → Gruppen (authentication_failed, attack, etc.)
rule.mitre.id                       → ATT&CK-Technik (T1059.001)
rule.mitre.tactic                   → ATT&CK-Taktik

data.win.system.eventID             → Windows Event ID
data.win.eventdata.commandLine      → Commandline
data.win.eventdata.image            → Prozess-Pfad
data.win.eventdata.parentImage      → Elternprozess-Pfad
data.win.eventdata.targetUserName   → Ziel-Nutzername
data.win.eventdata.subjectUserName  → Quell-Nutzername
data.win.eventdata.destinationIp    → Ziel-IP (Sysmon 3)
data.win.eventdata.destinationPort  → Ziel-Port
data.win.eventdata.queryName        → DNS-Query (Sysmon 22)
data.win.eventdata.targetObject     → Registry-Pfad (Sysmon 13)
data.win.eventdata.targetFileName   → Datei-Pfad (Sysmon 11)
data.win.eventdata.hashes           → Hashes (Sysmon 1)

syscheck.path                       → FIM: überwachter Pfad
syscheck.event                      → FIM: added / modified / deleted
full_log                            → Vollständiger Roh-Log
```

### Wazuh-Tipps

- **FIM-Alerts:** Syscheck muss konfiguriert sein (`/var/ossec/etc/ossec.conf`)
- **Sysmon-Daten:** Nur verfügbar wenn Sysmon auf dem Windows-Agent läuft
- **Level-Guide:** Level 1–4 = Info, 5–7 = Low, 8–11 = Medium, 12–14 = High, 15 = Critical
- **Gruppen-Filter:** `rule.groups: "syscheck"` für FIM, `rule.groups: "web"` für Webserver-Logs
- **Agent-Filter:** Immer zuerst `agent.name: "<HOST>"` setzen — sonst sucht man über alle Agents
- **Saved Searches:** Discover → Disketten-Icon → "Save search" — in Dashboards einbettbar

---

## 10. Typische Investigationsworkflows

### Workflow A: Alert-Triage (15 Minuten)

```
1. HOST identifizieren (aus Alert)
   → AQ-XXX-001: Alle Events des Hosts — letzten 24h

2. Zeitfenster einschränken (Alert-Timestamp ± 30 Min)
   → AQ-XXX-003: Timeline für definierten Zeitraum

3. Prozesse analysieren
   → AQ-XXX-018: PowerShell-Ausführungen
   → AQ-XXX-020: Commandline-Keyword-Suche

4. Netzwerk-Check
   → AQ-XXX-025: Ausgehende Verbindungen
   → AQ-XXX-027: DNS-Anfragen

5. Persistenz prüfen
   → AQ-XXX-040: Alle Persistenz-Events

6. Ergebnis: Eskalieren oder Schließen
```

### Workflow B: Kompromittierter Account (30 Minuten)

```
1. Account-Aktivität prüfen
   → AQ-XXX-009: Fehlgeschlagene Logins des Users
   → AQ-XXX-015: Alle Quell-IPs des Users

2. Gelingende Logins nach Fehlschlägen?
   → AQ-XXX-011: Erfolgreicher Login nach Fehlschlägen

3. Was hat der Account nach Login getan?
   → AQ-XXX-002: Alle Events des Users
   → AQ-XXX-013: Gruppenänderungen
   → AQ-XXX-014: Passwortänderungen

4. Lateral Movement?
   → AQ-XXX-046: RDP von diesem Account
   → AQ-XXX-047: Admin-Share-Zugriffe

5. Backdoor-Account?
   → AQ-XXX-012: Neue Accounts nach Compromittierung

6. Ergebnis: Account sperren, IR einleiten
```

### Workflow C: IOC-Sweep (10 Minuten)

```
Neuer IOC aus Threat Intelligence (z.B. C2-IP: 185.220.101.1)

1. IP im Netzwerk suchen
   → AQ-XXX-006: Events für diese IP-Adresse
   → AQ-XXX-026: Verbindungen zu dieser IP

2. Betroffene Hosts identifizieren
   → AQ-XXX-025: Ausgehende Verbindungen, filtern auf IOC-IP

3. Zeitfenster der Kommunikation bestimmen
   → AQ-XXX-007: Erstes und letztes Auftreten

4. Prozesse hinter der Verbindung
   → AQ-XXX-024: Netzwerkverbindungen des verdächtigen Prozesses

5. Persistenz auf betroffenen Hosts
   → AQ-XXX-040: Persistenz-Events nach IOC-Zeitfenster

6. Ergebnis: Isolation, IR, Threat-Hunt ausweiten
```

### Workflow D: Ransomware-Verdacht (20 Minuten)

```
1. Schatten-Kopien-Manipulation?
   → AQ-XXX-020: Suche nach "vssadmin" "delete" "shadows"
   → AQ-XXX-020: Suche nach "bcdedit" "recoveryenabled"

2. Massendatei-Aktivität?
   → AQ-XXX-032: Dateierstellungen auf Host (Zeitfenster!)
   → AQ-XXX-033: EXE/DLL in Staging-Pfaden

3. Dienste gestoppt?
   → AQ-XXX-039: Dienst-Events ("stop", "SQL", "backup")

4. Ransom-Note?
   → AQ-XXX-034: Dateisuche nach "README", "DECRYPT", "RECOVER"

5. Ursprung (Initial Access)?
   → AQ-XXX-022: Office-Prozesse spawnen Shell (Phishing?)
   → AQ-XXX-016: Logins nach Fehlschlägen

6. Ergebnis: Netz-Isolation, IR, Backup-Status prüfen
```

---

## 11. Tipps für den Analyst-Alltag

### Zeitfenster richtig wählen

| Situation | Empfohlenes Fenster |
|---|---|
| Aktiver Incident (gerade laufend) | Letzte 30–60 Minuten |
| Alert-Triage | Alert-Timestamp ± 2h |
| Forensische Analyse | Bekannter Incident-Zeitraum |
| IOC-Sweep | Letzte 30 Tage |
| Baseline-Analyse | Letzte 7 Tage |

### Die 5 häufigsten Analyst-Fehler

1. **Zu breites Zeitfenster** → Performance-Probleme, zu viele Ergebnisse
2. **Vergessener Host-Filter** → sucht über alle Systeme → zu viel Rauschen
3. **Wildcard zu früh** → `*powershell*` matcht auch `C:\tools\anti-powershell\`
4. **Nur auf Alerts schauen** → manchmal steckt das Wichtige in unbewerteten Events
5. **Zeitzone ignorieren** → Alert-Timestamp in UTC, SIEM in lokaler Zeit? → Verechnung!

### Performance-Tipps

```
Splunk:  Immer mit "index=..." beginnen, dann host=, dann Keywords
QRadar:  LAST N MINUTES statt absoluem Datum — schneller
SecOps:  Spezifischer Event-Type zuerst setzen
Wazuh:   agent.name zuerst, dann weitere Filter
```

### Ergebnis-Dokumentation (IR-Best-Practice)

Nach jeder Analyse kurz festhalten:
```
Timestamp: 2026-06-07 14:32 UTC
Analyst: [Name]
Query: AQ-SPL-001, Host: WIN10-CLIENT01, Zeitraum: 06:00–14:00
Ergebnis: 3 PowerShell-Executions mit -enc Flag, 1 Netzwerkverbindung nach 185.220.101.1
Nächste Schritte: AQ-SPL-024 für Prozess-Details, AQ-SPL-026 für alle Hosts die diese IP kontaktierten
```

---

## 12. Cheat Sheet

### Query-IDs nach Kategorie

```
001–008  → Triage & Timeline
009–016  → Authentication & Accounts
017–024  → Prozess & Ausführung
025–031  → Netzwerk & C2
032–036  → Dateisystem
037–040  → Persistenz
041–045  → Credential Access
046–049  → Lateral Movement
050      → Discovery & Recon
```

### Schnell-Navigation: "Ich sehe X, was nehme ich?"

| Situation | Query |
|---|---|
| Alert auf Host → Überblick | AQ-XXX-001 |
| Account verdächtig | AQ-XXX-002, AQ-XXX-009 |
| IP als IOC bekannt | AQ-XXX-006, AQ-XXX-026 |
| Powershell-Alert | AQ-XXX-018, AQ-XXX-019 |
| Viele Fehllogins | AQ-XXX-010, AQ-XXX-042 |
| Neuer Account | AQ-XXX-012 |
| Dienst-Install | AQ-XXX-039 |
| Geplanter Task | AQ-XXX-038 |
| Registry-Änderung | AQ-XXX-037 |
| RDP-Bewegung | AQ-XXX-046 |
| Lateral Movement | AQ-XXX-047, AQ-XXX-048 |
| Credential Dump | AQ-XXX-041, AQ-XXX-043 |
| Recon-Aktivität | AQ-XXX-050 |
| Ransomware-Verdacht | AQ-XXX-001, AQ-XXX-032, AQ-XXX-039 |

### Plattform-Wildcard-Syntax

| Plattform | Wildcard | Beispiel |
|---|---|---|
| Splunk | `*` | `CommandLine="*-enc*"` |
| QRadar | `%` in ILIKE | `ILIKE '%powershell%'` |
| Google SecOps | Regex mit `~` | `~ "powershell"` |
| Wazuh/KQL | `*` | `commandLine: *-enc*` |

---

*HuntingThreats Enterprise Hunt Pack — Version 1.0.0 — 2026-06-07*  
*Analyst Query Library: 200 Queries · 4 Plattformen · 9 Kategorien*
