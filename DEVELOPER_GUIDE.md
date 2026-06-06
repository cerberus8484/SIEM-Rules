# Developer Guide — HuntingThreats Enterprise Hunt Pack

> Schritt-für-Schritt-Anleitung zum Entwickeln, Testen und Deployen
> neuer Hunt-Regeln für Wazuh, QRadar AQL und Google SecOps YARA-L 2.0 (Splunk folgt).
>
> **Grundregel:** Immer nur **eine neue Regel** pro Commit. Tests schreiben.
> Dann deployen und FP-Rate beobachten.

---

## Inhaltsverzeichnis

**Wazuh (XML/PCRE2)**
1. [Voraussetzungen](#1-voraussetzungen)
2. [Verzeichnisstruktur](#2-verzeichnisstruktur)
3. [Neue Wazuh-Regel schreiben](#3-neue-wazuh-regel-schreiben)
4. [Rule-ID vergeben](#4-rule-id-vergeben)
5. [Severity wählen](#5-severity-wählen)
6. [MITRE-Technik referenzieren](#6-mitre-technik-referenzieren)
7. [Feldnamen-Referenz Wazuh/Sysmon](#7-feldnamen-referenz)
8. [PCRE2-Muster schreiben](#8-pcre2-muster-schreiben)
9. [Threshold-Regeln (Wazuh)](#9-threshold-regeln)
10. [Tags (group-Element)](#10-tags-group-element)
11. [Qualitätscheckliste](#11-qualitätscheckliste)
12. [Testing & Validation](#12-testing--validation)
13. [Deployment auf Wazuh](#13-deployment-auf-wazuh)
14. [FP-Rate messen](#14-fp-rate-messen)
15. [Cheat Sheet Wazuh](#15-cheat-sheet)

**QRadar AQL**
16. [Neue QRadar-Regel schreiben](#16-neue-qradar-regel-schreiben)
17. [AQL Feldnamen-Referenz](#17-aql-feldnamen-referenz)
18. [AQL Muster-Bibliothek](#18-aql-muster-bibliothek)
19. [Threshold-Regeln (AQL)](#19-threshold-regeln-aql)
20. [Qualitätscheckliste QRadar](#20-qualitätscheckliste-qradar)
21. [Deployment in QRadar](#21-deployment-in-qradar)
22. [Cheat Sheet QRadar](#22-cheat-sheet-qradar)

**Google SecOps — YARA-L 2.0**
23. [Neue YARA-L-Regel schreiben](#23-neue-yara-l-regel-schreiben)
24. [UDM-Feldnamen-Referenz](#24-udm-feldnamen-referenz)
25. [YARA-L Muster-Bibliothek](#25-yara-l-muster-bibliothek)
26. [Threshold-Regeln (YARA-L)](#26-threshold-regeln-yara-l)
27. [Multi-Event-Korrelation (YARA-L)](#27-multi-event-korrelation-yara-l)
28. [Qualitätscheckliste Google SecOps](#28-qualitätscheckliste-google-secops)
29. [Deployment in Google SecOps](#29-deployment-in-google-secops)
30. [Cheat Sheet Google SecOps](#30-cheat-sheet-google-secops)

---

## 1. Voraussetzungen

**Entwicklungsumgebung:**
```
- Texteditor mit XML-Syntax-Highlighting (VS Code + XML Extension)
- xmllint für lokale Validierung (optional aber empfohlen)
- Zugriff auf Wazuh Manager (SSH) für Deployment
- Sysmon-Testumgebung oder Log-Replay-Tool (z.B. evtx_dump)
```

**Wissen:**
- MITRE ATT&CK Framework (Taktiken → Techniken → Sub-Techniken)
- Sysmon Event-IDs und Feldnamen
- Grundlagen PCRE2-Regex

**Notwendige Berechtigungen:**
```bash
# Wazuh Manager — Regel-Deployment
sudo -u ossec /var/ossec/bin/ossec-control reload
```

---

## 2. Verzeichnisstruktur

```
hunts/
├── ARCHITECTURE.md         ← Sprachen & Architektur-Doku
├── DEVELOPER_GUIDE.md      ← Diese Datei
├── ARCHITECTURE.html       ← HTML-Version (Dark Theme)
├── DEVELOPER_GUIDE.html    ← HTML-Version (Dark Theme)
│
├── wazuh/                  ← Wazuh 4.x XML-Regeln (500 Regeln ✅)
│   ├── initial_access/001_phishing.xml
│   ├── execution/
│   │   ├── 001_powershell.xml
│   │   ├── 002_lolbins.xml
│   │   └── 003_wmi_office.xml
│   ├── persistence/
│   │   ├── 001_registry.xml
│   │   ├── 002_scheduled_tasks.xml
│   │   └── 003_services.xml
│   ├── privilege_escalation/001_privesc.xml
│   ├── defense_evasion/001_process_injection.xml
│   ├── credential_access/001_lsass.xml
│   ├── discovery/001_enumeration.xml
│   ├── lateral_movement/001_lateral_movement.xml
│   ├── c2/001_c2_ports.xml
│   ├── exfiltration/001_exfiltration.xml
│   └── impact/001_ransomware.xml
│
├── qradar/                 ← QRadar AQL-Regeln (500 Regeln ✅)
│   ├── initial_access/001_phishing.aql
│   ├── execution/
│   │   ├── 001_powershell.aql
│   │   ├── 002_lolbins.aql
│   │   └── 003_wmi_office.aql
│   ├── persistence/
│   │   ├── 001_registry.aql
│   │   ├── 002_scheduled_tasks.aql
│   │   └── 003_services.aql
│   ├── privilege_escalation/001_privesc.aql
│   ├── defense_evasion/001_process_injection.aql
│   ├── credential_access/001_lsass.aql
│   ├── discovery/001_enumeration.aql
│   ├── lateral_movement/001_lateral_movement.aql
│   ├── c2/001_c2_ports.aql
│   ├── exfiltration/001_exfiltration.aql
│   └── impact/001_ransomware.aql
│
└── secops/                 ← Google SecOps YARA-L 2.0 (500 Regeln ✅)
    ├── initial_access/001_phishing.yaral
    ├── execution/
    │   ├── 001_powershell.yaral
    │   ├── 002_lolbins.yaral
    │   └── 003_wmi_office.yaral
    ├── persistence/
    │   ├── 001_registry.yaral
    │   ├── 002_scheduled_tasks.yaral
    │   └── 003_services.yaral
    ├── privilege_escalation/001_privesc.yaral
    ├── defense_evasion/001_process_injection.yaral
    ├── credential_access/001_lsass.yaral
    ├── discovery/001_enumeration.yaral
    ├── lateral_movement/001_lateral_movement.yaral
    ├── c2/001_c2_ports.yaral
    ├── exfiltration/001_exfiltration.yaral
    └── impact/001_ransomware.yaral
```

**Dateinamen-Konvention:**
```
NNN_thema.xml      → Wazuh
NNN_thema.aql      → QRadar
NNN_thema.yaral    → Google SecOps

Beispiele:
  001_powershell.xml/.aql/.yaral  ← erste Datei der Kategorie
  002_lolbins.xml/.aql/.yaral     ← zweite Datei der Kategorie
```

---

## 3. Neue Wazuh-Regel schreiben

### 3.1 Template — Einfache Regel

```xml
<!--
  Kurze Beschreibung was diese Regel erkennt.
  Technik: T1XXX
  Quelle: Sysmon 1 / Windows Event 4688
-->
<group name="hunt_[taktik],[kategorie],windows,">

  <rule id="XXXXXX" level="12">
    <if_group>windows</if_group>
    <field name="win.system.eventID" type="pcre2">^1$|^4688$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)\\tool\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)verdächtiges-muster</field>
    <description>tool.exe: kurze Erklärung — Angriffskontext (T1XXX)</description>
    <mitre><id>T1XXX</id></mitre>
    <group>taktik,technik,konfidenz,</group>
  </rule>

</group>
```

### 3.2 Template — Neue Datei anlegen

Wenn du eine neue Datei in einer Kategorie erstellst, beginne immer mit dem
Kommentar-Header:

```xml
<!--
  HuntingThreats — Wazuh Hunt Rules
  Category:  [Taktik] — [Unterkategorie] (T1XXX, T1XXX)
  Batch:     N / [Taktik]
  Rules:     [ID-Von] – [ID-Bis]
  Platform:  Wazuh 4.x
  Sources:   Sysmon Event X (Beschreibung)
             Windows Event YYYY (Beschreibung)

  TXXXX — Technik-Name
  TXXXX — Technik-Name
-->

<group name="hunt_[taktik],[subtag],windows,">
  <!-- Regeln hier -->
</group>
```

### 3.3 Multi-Field-Matching

**Mehrere Felder werden mit AND verknüpft:**
```xml
<rule id="100001" level="12">
  <if_group>windows</if_group>
  <!-- Event-ID UND Prozessname UND Commandline müssen matchen -->
  <field name="win.system.eventID" type="pcre2">^1$|^4688$</field>
  <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)-encodedcommand</field>
  ...
</rule>
```

**Alternativ-Match auf mehrere Felder (OR über Feldnamen mit |):**
```xml
<!-- commandLine ODER scriptBlockText muss matchen -->
<field name="win.eventdata.commandLine|win.eventdata.scriptBlockText" type="pcre2">(?i)invoke-expression</field>
```

### 3.4 Negative Lookahead (Ausschlüsse)

Legitime Prozesse ausschließen um FP-Rate zu senken:
```xml
<!-- Alles AUSSER svchost, lsass, taskmgr -->
<field name="win.eventdata.image" type="pcre2">(?i)(?!.*\\(svchost|lsass|taskmgr)\.exe)</field>
```

---

## 4. Rule-ID vergeben

### ID-Ranges (Wazuh)

```
Taktik                        Bereich        Nächste freie ID
──────────────────────────────────────────────────────────────
Initial Access                110000–110999  110041
Execution                     100000–100999  100101
Persistence                   101000–101999  101081
Privilege Escalation          109000–109999  109041
Defense Evasion               102000–102999  102036
Credential Access             103000–103999  103036
Discovery                     106000–106999  106036
Lateral Movement              105000–105999  105041
C2 & Network                  104000–104999  104036
Exfiltration                  107000–107999  107031
Impact                        108000–108999  108031
```

**Regel:** Immer die nächste freie ID in deiner Kategorie nehmen.
Keine Lücken lassen. Keine IDs wiederverwenden.

**Duplikate prüfen:**
```bash
# Lokal prüfen ob ID schon existiert:
grep -r 'id="XXXXXX"' hunts/wazuh/
# → kein Output = ID ist frei
```

---

## 5. Severity wählen

```
Level  Bedeutung               Wann verwenden
──────────────────────────────────────────────────────────────────
6      Informational           Enumeration, Discovery — kaum False Negatives nötig
8      Low / Suspicious        Häufig legitim (whoami, systeminfo), Kontext nötig
10     Medium                  Selten legitim im Unternehmenskontext
12     High                    Fast immer bösartig, legitime Ausnahmen existieren
14     Critical                Nahezu ausschließlich bösartig (Shadow-Delete, Mimikatz)
```

**Faustregel:**
- Signed Microsoft Tool missbraucht → Level 10
- Signed Tool + riskanter Pfad/Flag → Level 12
- Eindeutiger Angriff (Shadow Delete, LSASS-Dump) → Level 14
- Discovery aus Script-Kontext → Level 6–8

---

## 6. MITRE-Technik referenzieren

Jede Regel braucht mindestens ein `<mitre><id>` Element.

**Sub-Techniken bevorzugen wenn möglich:**
```xml
<!-- Schlecht: zu generisch -->
<mitre><id>T1059</id></mitre>

<!-- Besser: spezifisch -->
<mitre><id>T1059.001</id></mitre>   <!-- PowerShell -->
<mitre><id>T1059.005</id></mitre>   <!-- VBA -->
<mitre><id>T1059.007</id></mitre>   <!-- JavaScript -->
```

**Mehrere Techniken wenn sinnvoll:**
```xml
<mitre><id>T1053.005</id></mitre>   <!-- Scheduled Task -->
<mitre><id>T1027</id></mitre>       <!-- Obfuscation (falls relevant) -->
```

**Wichtige Techniken-Referenz:**

| Technik-ID | Name | Typische Signale |
|---|---|---|
| T1059.001 | PowerShell | `-enc`, `IEX`, `-w hidden` |
| T1047 | WMI | `wmic process call create` |
| T1055.001–013 | Process Injection | CreateRemoteThread, Sysmon 8 |
| T1003.001 | LSASS Dump | Sysmon 10, procdump, comsvcs |
| T1548.002 | UAC Bypass | fodhelper, eventvwr, sdclt |
| T1543.003 | Windows Service | Event 7045, sc.exe create |
| T1547.001 | Run Keys | HKLM/HKCU CurrentVersion\Run |
| T1053.005 | Scheduled Task | Event 4698, schtasks /create |
| T1486 | Ransomware | .locked Extension, Shadow Delete |
| T1190 | Exploit Public App | w3wp.exe spawning shell |

---

## 7. Feldnamen-Referenz

### Sysmon Event-IDs → Feldnamen

**Event 1 — Process Creation:**
```
win.eventdata.image            → Vollpfad Executable
win.eventdata.commandLine      → Komplette Commandline
win.eventdata.parentImage      → Parent-Prozess Vollpfad
win.eventdata.parentCommandLine → Parent Commandline
win.eventdata.user             → Ausführender User
win.eventdata.hashes           → SHA256/MD5 des Binary
win.eventdata.signed           → true/false
win.eventdata.signatureStatus  → Valid/Invalid/Expired
```

**Event 3 — Network Connection:**
```
win.eventdata.image            → Prozess der Verbindung aufbaut
win.eventdata.destinationIp    → Ziel-IP-Adresse
win.eventdata.destinationPort  → Ziel-Port
win.eventdata.destinationHostname → DNS-Name (wenn verfügbar)
win.eventdata.sourceIp         → Quell-IP
win.eventdata.sourcePort       → Quell-Port
win.eventdata.protocol         → tcp/udp/icmp
win.eventdata.initiated        → true = ausgehend, false = eingehend
```

**Event 7 — Image Loaded (DLL):**
```
win.eventdata.image            → Prozess der DLL lädt
win.eventdata.imageLoaded      → Vollpfad geladene DLL
win.eventdata.signed           → true/false
win.eventdata.signatureStatus  → Gültigkeit
win.eventdata.hashes           → DLL-Hash
```

**Event 8 — CreateRemoteThread:**
```
win.eventdata.sourceImage      → Prozess der Thread erstellt
win.eventdata.targetImage      → Ziel-Prozess
win.eventdata.targetPid        → PID des Ziel-Prozesses
win.eventdata.startAddress     → Thread-Start-Adresse
```

**Event 10 — Process Access:**
```
win.eventdata.sourceImage      → Zugreifender Prozess
win.eventdata.targetImage      → Ziel-Prozess (z.B. lsass)
win.eventdata.grantedAccess    → Zugriffsmaske (Hex)
```

**Event 11 — File Created:**
```
win.eventdata.image            → Prozess der Datei erstellt
win.eventdata.targetFilename   → Vollpfad der neuen Datei
win.eventdata.creationUtcTime  → Erstellungszeitpunkt
```

**Event 13 — Registry Value Set:**
```
win.eventdata.image            → Prozess der Wert setzt
win.eventdata.targetObject     → Vollständiger Registry-Pfad
win.eventdata.details          → Neuer Wert (Typ + Inhalt)
```

**Event 22 — DNS Query:**
```
win.eventdata.image            → Anfragender Prozess
win.eventdata.queryName        → Angeforderte Domain
win.eventdata.queryType        → Record-Typ (1=A, 16=TXT, 28=AAAA)
win.eventdata.queryResults     → Antwort-IPs
```

**Windows Security Events:**
```
Event 4624  → win.eventdata.logonType, win.eventdata.ipAddress,
              win.eventdata.authenticationPackageName
Event 4625  → Fehlgeschlagene Anmeldung (gleiche Felder)
Event 4648  → win.eventdata.targetUserName (explizite Credentials)
Event 4672  → win.eventdata.subjectUserName, win.eventdata.privileges
Event 4688  → win.eventdata.newProcessName, win.eventdata.commandLine
Event 4698  → win.eventdata.taskName, win.eventdata.taskContent
Event 7045  → win.eventdata.serviceName, win.eventdata.imagePath, win.eventdata.serviceType
```

**PowerShell (Event 4103/4104):**
```
win.eventdata.scriptBlockText   → Dekomprimierter Script-Block
win.eventdata.scriptBlockId     → Block-ID
win.eventdata.path              → Skript-Pfad (wenn aus Datei)
```

---

## 8. PCRE2-Muster schreiben

### Case-Insensitive (Standard)

```pcre2
(?i)powershell    → matcht: PowerShell, POWERSHELL, powershell
```

**Immer `(?i)` für Dateinamen und Commandlines verwenden** — Windows ist case-insensitiv.

### Pfade

```pcre2
(?i)\\powershell\.exe$           → endet auf \powershell.exe
(?i)\\(cmd|powershell)\.exe$     → cmd.exe ODER powershell.exe
(?i)(\\appdata\\|\\temp\\)       → enthält \appdata\ ODER \temp\
```

### Event-IDs (exakter Match)

```pcre2
^1$              → genau "1"
^1$|^4688$       → "1" ODER "4688"
^(1|4688)$       → äquivalent mit Gruppe
```

### Ports

```pcre2
^4444$                          → genau Port 4444
^(4444|4445|4446|31337)$        → einer dieser Ports
^[4-9][0-9]{4}$                 → alle Ports 40000–99999
```

### Negative Lookahead

```pcre2
(?!.*\\svchost\.exe)            → NICHT wenn svchost im Pfad
(?!^10\.|^192\.168\.)           → NICHT private IPs
(?!.*(SYSTEM|LOCAL SERVICE))    → NICHT System-Accounts
```

### Flags und Parameter

```pcre2
(?i)/create.*\/ru\s+system     → /create ... /ru system (mit Whitespace-Varianten)
(?i)(-enc|-encodedcommand)     → -enc ODER -encodedcommand
(?i)\s+(stop|config)\s+        → Wort mit Whitespace darum
```

### Häufige Muster

```pcre2
# Base64-String (mindestens 80 Zeichen)
[A-Za-z0-9+/]{80,}={0,2}

# IPv4-Adresse
[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}

# UNC-Pfad
\\\\[0-9a-zA-Z].*

# Registry Run-Key
(?i)\\CurrentVersion\\Run(Once)?\\

# Bekannte Staging-Pfade
(?i)(\\appdata\\|\\temp\\|\\downloads\\|\\public\\|\\desktop\\)
```

---

## 9. Threshold-Regeln

Für Beaconing, Brute-Force und Scanning verwende Frequency+Timeframe:

```xml
<rule id="XXXXXX" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID" type="pcre2">^4625$</field>
  <field name="win.eventdata.logonType" type="pcre2">^3$</field>

  <!-- Korreliere über gleiches Feld: gleiche Quell-IP -->
  <same_field>win.eventdata.ipAddress</same_field>

  <!-- 5 Events innerhalb von 60 Sekunden -->
  <frequency>5</frequency>
  <timeframe>60</timeframe>

  <description>Windows Security: 5+ Fehlversuche von gleicher IP in 60s — Brute Force (T1110)</description>
  <mitre><id>T1110</id></mitre>
  <group>credential_access,brute_force,threshold,</group>
</rule>
```

**Threshold-Werte als Orientierung:**

| Szenario | frequency | timeframe |
|---|---|---|
| Brute Force Login | 5–10 | 60 |
| Port Scan | 10–20 | 30 |
| Beaconing (Medium) | 5 | 360 |
| Beaconing (High) | 10 | 300 |
| Ransomware Mass-Encrypt | 100 | 30 |
| Multiple Service Stops | 5 | 30 |

---

## 10. Tags (group-Element)

Das `<group>`-Element am Ende jeder Regel steuert Filterung und Korrelation.

**Format:** `taktik,technik,[konfidenz],`

Wichtig: Letztes Komma nicht vergessen (Wazuh-Syntax).

**Standard-Taktik-Tags:**
```
execution, persistence, privilege_escalation, defense_evasion,
credential_access, discovery, lateral_movement, c2, exfiltration, impact
```

**Konfidenz-Tags:**
```
high_confidence  → ~10% FP-Rate oder weniger
critical         → ~1% FP-Rate oder weniger (fast nur böse)
threshold        → Nur mit Frequency+Timeframe sinnvoll
```

**Technische Tags (für Filterung):**
```
powershell, lolbin, wmi, office_macro, dll_hijack, process_injection,
run_key, service, scheduled_task, lsass_access, rdp, smb, dns_tunnel,
ransomware, shadow_delete, mimikatz, lateral_movement, ...
```

**Vollständiges Beispiel:**
```xml
<group>credential_access,lsass_access,vm_read,critical,</group>
```

---

## 11. Qualitätscheckliste

Vor jedem Commit eine neue Regel gegen diese Liste prüfen:

```
□ Rule-ID ist eindeutig (grep -r 'id="XXXXXX"' hunts/wazuh/ → kein Treffer)
□ Level passt zur Schwere (6/8/10/12/14 Schema)
□ MITRE-ID ist korrekt und aktuell (Sub-Technik wenn möglich)
□ (?i) bei allen Pfad/Tool-Matches gesetzt
□ Keine echten IP-Adressen oder Hostnamen im Pattern
□ Beschreibung nennt: Tool, Kontext, MITRE-ID
□ Tags vollständig (Taktik + Technik + Konfidenz)
□ Keine Magic Strings — Kommentar erklärt unklare Regex-Teile
□ Negative Lookaheads für legitime Tools gesetzt wo nötig
□ Bei Threshold-Regeln: same_field, frequency, timeframe korrekt
□ XML syntaktisch valid (xmllint --noout datei.xml)
□ Keine doppelten Regeln — ähnliche Patterns konsolidieren
□ Keine Panik-Formulierungen in Description
□ Beschreibung folgt Format: "tool.exe: Aktion — Kontext (T1XXX)"
```

---

## 12. Testing & Validation

### 12.1 XML-Validierung

```bash
# Syntaxcheck (lokal)
xmllint --noout hunts/wazuh/execution/001_powershell.xml
echo $?  # → 0 = OK

# Alle Dateien prüfen
find hunts/wazuh -name "*.xml" -exec xmllint --noout {} \; && echo "Alle OK"
```

### 12.2 Duplikat-Check

```bash
# Doppelte Rule-IDs finden
grep -h 'rule id=' hunts/wazuh/**/*.xml \
  | grep -o 'id="[0-9]*"' \
  | sort | uniq -d

# → kein Output = keine Duplikate
```

### 12.3 Manuelle Event-Simulation

**Methode 1: Direkt im Wazuh-Test-Modus:**
```bash
# Wazuh Agent simuliert Event und zeigt ausgelöste Regeln:
/var/ossec/bin/ossec-logtest -V

# Dann JSON-Event eingeben:
{
  "win": {
    "system": { "eventID": "1" },
    "eventdata": {
      "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "commandLine": "powershell.exe -EncodedCommand AAAA..."
    }
  }
}
```

**Methode 2: Echtes Sysmon-Event erzeugen (Testumgebung):**
```powershell
# Harmlose Test-Commandline die Regel 100001 auslösen sollte:
powershell.exe -EncodedCommand "ZQBjAGgAbwAgACIAdABlAHMAdAAi"
```

### 12.4 FP-Baseline

Neue Regel zunächst auf **Level 6 (Informational)** deployen,
2–7 Tage beobachten, dann auf Ziellevel anheben wenn FP-Rate < 5%.

---

## 13. Deployment auf Wazuh

### 13.1 Dateien kopieren

```bash
# Einzelne Datei:
scp hunts/wazuh/execution/001_powershell.xml \
  user@wazuh-manager:/var/ossec/rules/ht_execution_001.xml

# Alle Dateien:
rsync -av hunts/wazuh/ user@wazuh-manager:/var/ossec/rules/huntingthreats/
```

### 13.2 Eigentumsrechte setzen

```bash
chown ossec:ossec /var/ossec/rules/huntingthreats/*.xml
chmod 640 /var/ossec/rules/huntingthreats/*.xml
```

### 13.3 ossec.conf eintragen

```xml
<!-- In /var/ossec/etc/ossec.conf, Abschnitt <ruleset>: -->
<ruleset>
  <decoder_dir>ruleset/decoders</decoder_dir>
  <rule_dir>ruleset/rules</rule_dir>

  <!-- Hunt Pack -->
  <rule_dir>rules/huntingthreats</rule_dir>

  <!-- oder einzelne Dateien: -->
  <rule_include>rules/huntingthreats/ht_execution_001.xml</rule_include>
</ruleset>
```

### 13.4 Reload ohne Downtime

```bash
# Regeln neu laden ohne Agent-Neustart:
/var/ossec/bin/ossec-control reload

# Alternativ:
systemctl restart wazuh-manager
```

### 13.5 Deployment-Verifizierung

```bash
# Prüfen ob Regeln geladen:
grep -c 'rule id="1000' /var/ossec/etc/shared/merged.mg

# Spezifische Regel-ID prüfen:
grep 'rule id="100001"' /var/ossec/var/run/agent.state
```

---

## 14. FP-Rate messen

### 14.1 Query in Wazuh Dashboard (OpenSearch/Kibana)

```json
{
  "query": {
    "bool": {
      "must": [
        { "range": { "rule.id": { "gte": 100001, "lte": 100999 } } },
        { "range": { "@timestamp": { "gte": "now-7d" } } }
      ]
    }
  },
  "aggs": {
    "by_rule": {
      "terms": { "field": "rule.id", "size": 50 }
    }
  }
}
```

### 14.2 FP-Entscheidungsmatrix

```
Alert → Analyse → Ergebnis
                  ├── Echter Angriff         → True Positive  ✅
                  ├── Legitimes Tool/Verhalten → False Positive ⚠️
                  │   └── Aktion:
                  │       ├── Pattern verfeinern (negativer Lookahead)
                  │       ├── Parent-Prozess-Filter hinzufügen
                  │       └── Level absenken
                  └── Unbekannt              → Weiteres Hunting
```

### 14.3 FP-Reduktion — Techniken

```xml
<!-- 1. Parent-Prozess einschränken -->
<field name="win.eventdata.parentImage" type="pcre2">
  (?i)(?!.*\\(explorer|services|svchost)\.exe)
</field>

<!-- 2. Pfad einschränken -->
<field name="win.eventdata.image" type="pcre2">
  (?i)(\\appdata\\|\\temp\\)
</field>

<!-- 3. Spezifischeres Commandline-Pattern -->
<field name="win.eventdata.commandLine" type="pcre2">
  (?i)\/create\s+.*\/ru\s+system.*\/sc\s+onlogon
</field>

<!-- 4. Level absenken bis FP-Rate sinkt -->
<!-- Temporär Level 6 statt Level 12 -->
```

---

## 15. Cheat Sheet

### Regel-Skelett (Copy-Paste)

```xml
<rule id="XXXXXX" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID" type="pcre2">^1$|^4688$</field>
  <field name="win.eventdata.image" type="pcre2">(?i)\\BINARY\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)PATTERN</field>
  <description>BINARY: AKTION — KONTEXT (T1XXX)</description>
  <mitre><id>T1XXX</id></mitre>
  <group>TAKTIK,TECHNIK,KONFIDENZ,</group>
</rule>
```

### Wichtigste Event-IDs

```
Sysmon 1  → Process Create     (image, commandLine, parentImage)
Sysmon 3  → Network Connect    (destinationIp, destinationPort, initiated)
Sysmon 7  → Image Load         (imageLoaded, signed)
Sysmon 8  → RemoteThread       (sourceImage, targetImage)
Sysmon 10 → Process Access     (sourceImage, targetImage, grantedAccess)
Sysmon 11 → File Create        (targetFilename)
Sysmon 13 → Registry Set       (targetObject, details)
Sysmon 22 → DNS Query          (queryName, queryType)
Sysmon 25 → Process Tamper     (image)
Win 4624  → Logon Success      (logonType, ipAddress)
Win 4625  → Logon Failure      (logonType, ipAddress)
Win 4688  → Process Create     (newProcessName, commandLine)
Win 4698  → Task Created       (taskName, taskContent)
Win 4724  → Password Reset
Win 4732  → Group Member Added
Win 7045  → Service Installed  (serviceName, imagePath)
PS  4104  → Script Block       (scriptBlockText)
```

### Level-Kurzreferenz

```
6  = Info      (Enum, Discovery)
8  = Low       (Selten aber legitim möglich)
10 = Medium    (Ungewöhnlich, Kontext nötig)
12 = High      (Fast immer bösartig)
14 = Critical  (Sofortiger Alert)
```

### Häufig gebrauchte Staging-Pfade

```pcre2
(?i)(\\appdata\\|\\temp\\|\\downloads\\|\\public\\|\\desktop\\|\\programdata\\[^W])
```

### Privat-IP-Ausschluss

```pcre2
(?!^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^127\.)
```

---

## 16. Neue QRadar-Regel schreiben

### 16.1 Template — Einfache AQL-Regel

```sql
-- ==================================================
-- QR-XXXXXX | T1XXX.XXX | Kurzbeschreibung
-- Severity: High | Confidence: High
-- ==================================================
SELECT
  DATEFORMAT(startTime, 'yyyy-MM-dd HH:mm:ss') AS EventTime,
  LOGSOURCENAME(logsourceid) AS LogSource,
  username,
  UTF8(payload) AS EventPayload
FROM events
WHERE (LOGSOURCETYPENAME(logsourceid) ILIKE '%Windows%'
    OR LOGSOURCETYPENAME(logsourceid) ILIKE '%Sysmon%')
  AND UTF8(payload) ILIKE '%verdächtiges-muster%'
LAST 1440 MINUTES;
```

### 16.2 Template — Neue AQL-Datei anlegen

Jede neue Datei beginnt mit dem Datei-Header:

```sql
-- ============================================================
-- HuntingThreats — QRadar AQL Hunt Rules
-- Category : [Taktik] ([T1XXX, T1XXX])
-- Batch    : NN / [Kategoriename]
-- Rules    : QR-XXXXXX – QR-XXXXXX
-- Platform : QRadar 7.4+ / AQL
-- Sources  : Windows Security (Event-IDs), Sysmon (Event-IDs)
-- ============================================================
```

### 16.3 Log-Source-Filter-Muster

Für Windows/Sysmon-Events:
```sql
WHERE (LOGSOURCETYPENAME(logsourceid) ILIKE '%Windows%'
    OR LOGSOURCETYPENAME(logsourceid) ILIKE '%Sysmon%')
```

Für PowerShell Script Block Logging:
```sql
WHERE LOGSOURCETYPENAME(logsourceid) ILIKE '%PowerShell%'
```

Für Netzwerk-Events (C2/Exfiltration):
```sql
WHERE (LOGSOURCETYPENAME(logsourceid) ILIKE '%Firewall%'
    OR LOGSOURCETYPENAME(logsourceid) ILIKE '%Netflow%')
```

Für alle Windows-Quellen kombiniert:
```sql
WHERE (LOGSOURCETYPENAME(logsourceid) ILIKE '%Windows%'
    OR LOGSOURCETYPENAME(logsourceid) ILIKE '%Sysmon%'
    OR LOGSOURCETYPENAME(logsourceid) ILIKE '%PowerShell%'
    OR LOGSOURCETYPENAME(logsourceid) ILIKE '%WinCollect%')
```

### 16.4 Mehrere Muster kombinieren (AND / OR)

```sql
-- AND: beide Bedingungen müssen erfüllt sein
AND UTF8(payload) ILIKE '%powershell%'
AND UTF8(payload) ILIKE '%-enc%'

-- OR: eines der Muster muss matchen
AND (UTF8(payload) ILIKE '%-EncodedCommand%'
  OR UTF8(payload) ILIKE '%-enc %'
  OR UTF8(payload) ILIKE '%-e %')

-- Ausschluss (NOT)
AND NOT (destinationip ILIKE '10.%'
  OR destinationip ILIKE '192.168.%')
```

### 16.5 Nächste freie QRadar-Rule-IDs

```
Taktik                    Letzter QR-Prefix   Nächste freie ID
────────────────────────────────────────────────────────────────
Initial Access            QR-110040           QR-110041
Execution (3 Dateien)     QR-100100           QR-100101
Persistence (3 Dateien)   QR-101080           QR-101081
Privilege Escalation      QR-109040           QR-109041
Defense Evasion           QR-102035           QR-102036
Credential Access         QR-103035           QR-103036
Discovery                 QR-106035           QR-106036
Lateral Movement          QR-105040           QR-105041
C2 & Network              QR-104035           QR-104036
Exfiltration              QR-107030           QR-107031
Impact                    QR-108030           QR-108031
```

---

## 17. AQL Feldnamen-Referenz

### 17.1 Normalisierte QRadar-Felder

Diese Felder werden von QRadar aus den rohen Events normalisiert:

```
sourceip           → Quell-IP (aus Event oder DSM-Mapping)
destinationip      → Ziel-IP
destinationport    → Ziel-Port (Integer)
sourceport         → Quell-Port
username           → Benutzername (normalisiert)
logsourceid        → Interne Log-Source-ID
startTime          → Event-Zeitstempel (Unix-ms)
eventcount         → Aggregierte Event-Anzahl (Netflow: Bytes)
```

### 17.2 AQL-Funktionen

```sql
LOGSOURCETYPENAME(logsourceid)          → Typ-Name der Log-Source
LOGSOURCENAME(logsourceid)              → Hostname / Asset-Name
DATEFORMAT(startTime, 'yyyy-MM-dd HH:mm:ss')  → Formatierter Timestamp
UTF8(payload)                           → Roher Event-Payload als UTF-8 String
QIDNAME(qid)                            → QRadar-interner Event-Name
```

### 17.3 Wichtige Payload-Pattern für Event-IDs

Da QRadar das komplette Event als `payload` speichert, werden Event-IDs über
Textsuche gefunden:

```sql
-- Windows Security / Sysmon Event-IDs im Payload
UTF8(payload) ILIKE '%EventID>4624<%'    → EventID in XML-Format (WinCollect)
UTF8(payload) ILIKE '%EventID">"4624"%'  → EventID in JSON-Format
UTF8(payload) ILIKE '%EventCode=4624%'   → EventCode-Format (alternative DSM)

-- Sysmon Event-Typen im Payload
UTF8(payload) ILIKE '%ProcessCreate%'    → Sysmon Event 1
UTF8(payload) ILIKE '%NetworkConnect%'   → Sysmon Event 3
UTF8(payload) ILIKE '%FileCreate%'       → Sysmon Event 11
UTF8(payload) ILIKE '%RegistryEvent%'    → Sysmon Event 12/13
UTF8(payload) ILIKE '%ImageLoad%'        → Sysmon Event 7
UTF8(payload) ILIKE '%DnsQuery%'         → Sysmon Event 22
UTF8(payload) ILIKE '%ProcessTamper%'    → Sysmon Event 25
UTF8(payload) ILIKE '%PipeEvent%'        → Sysmon Event 17/18
```

### 17.4 Standard Private-IP-Ausschluss

```sql
NOT (destinationip ILIKE '10.%'
  OR destinationip ILIKE '192.168.%'
  OR destinationip ILIKE '172.1%.%'
  OR destinationip ILIKE '127.%'
  OR destinationip ILIKE '::1')
```

---

## 18. AQL Muster-Bibliothek

### 18.1 Prozess-Erkennung (Sysmon 1 / Event 4688)

```sql
-- Prozess-Name
AND UTF8(payload) ILIKE '%powershell.exe%'
AND UTF8(payload) ILIKE '%cmd.exe%'

-- Commandline-Flags
AND UTF8(payload) ILIKE '%-EncodedCommand%'
AND UTF8(payload) ILIKE '%-WindowStyle Hidden%'
AND UTF8(payload) ILIKE '%-ExecutionPolicy Bypass%'

-- Parent-Prozess aus Office
AND (UTF8(payload) ILIKE '%winword%'
  OR UTF8(payload) ILIKE '%excel%'
  OR UTF8(payload) ILIKE '%powerpnt%')
```

### 18.2 Netzwerkverbindungen (Sysmon 3)

```sql
-- Bestimmter Port
AND destinationport = 4444

-- Port-Bereich
AND destinationport BETWEEN 50050 AND 50053

-- Port-Liste
AND destinationport IN (1234, 1337, 4444, 31337)

-- Bekannte C2-Domains im Payload
AND UTF8(payload) ILIKE '%ngrok%'
AND UTF8(payload) ILIKE '%serveo.net%'
```

### 18.3 Registry-Persistenz (Sysmon 13)

```sql
AND UTF8(payload) ILIKE '%RegistryEvent%'
AND UTF8(payload) ILIKE '%CurrentVersion\\Run%'
AND UTF8(payload) ILIKE '%IFEO%'          -- Image File Execution Options
AND UTF8(payload) ILIKE '%AppInit_DLLs%'
```

### 18.4 Datei-Operationen (Sysmon 11)

```sql
AND UTF8(payload) ILIKE '%FileCreate%'
-- Staging-Pfade
AND (UTF8(payload) ILIKE '%\Temp\%'
  OR UTF8(payload) ILIKE '%\AppData\Local\%'
  OR UTF8(payload) ILIKE '%\ProgramData\%')
-- Bekannte Ransomware-Extensions
AND (UTF8(payload) ILIKE '%.locked%'
  OR UTF8(payload) ILIKE '%.encrypted%'
  OR UTF8(payload) ILIKE '%.wncry%')
```

### 18.5 DNS-Abfragen (Sysmon 22)

```sql
AND UTF8(payload) ILIKE '%DnsQuery%'
-- Long Subdomain (DNS Tunneling)
AND (UTF8(payload) ILIKE '%================%'
  OR UTF8(payload) ILIKE '%AAAAAAAAAAAAAAAA%')
-- TXT-Record-Abfragen
AND UTF8(payload) ILIKE '%QueryType>16%'
```

---

## 19. Threshold-Regeln (AQL)

QRadar-Threshold-Detektion über `GROUP BY` + `HAVING`:

### 19.1 Brute Force

```sql
SELECT
  sourceip,
  COUNT(*) AS FailCount
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) ILIKE '%Windows%'
  AND UTF8(payload) ILIKE '%EventID>4625<%'
GROUP BY sourceip
HAVING COUNT(*) >= 10
LAST 15 MINUTES;
```

### 19.2 Beaconing (Schwellenwert-Verbindungen)

```sql
SELECT
  sourceip,
  destinationip,
  COUNT(*) AS Connections
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) ILIKE '%Sysmon%'
  AND UTF8(payload) ILIKE '%NetworkConnect%'
  AND NOT (destinationip ILIKE '10.%' OR destinationip ILIKE '192.168.%')
GROUP BY sourceip, destinationip
HAVING COUNT(*) >= 5
LAST 360 MINUTES;
```

### 19.3 Lateral Movement (viele Ziele)

```sql
SELECT
  sourceip,
  COUNT(DISTINCT LOGSOURCENAME(logsourceid)) AS UniqueTargets
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) ILIKE '%Windows%'
  AND UTF8(payload) ILIKE '%EventID>4624<%'
GROUP BY sourceip
HAVING COUNT(DISTINCT LOGSOURCENAME(logsourceid)) >= 3
LAST 60 MINUTES;
```

### 19.4 Threshold-Referenzwerte

| Szenario | HAVING COUNT | LAST |
|---|---|---|
| Brute Force Login | >= 10 | 15 MINUTES |
| Password Spray (viele User) | >= 5 DISTINCT usernames | 5 MINUTES |
| Port Scan | >= 20 DISTINCT destinationport | 5 MINUTES |
| Ping Sweep | >= 10 DISTINCT destinationip | 2 MINUTES |
| Beaconing Medium | >= 5 | 360 MINUTES |
| Beaconing High | >= 10 | 300 MINUTES |
| Ransomware Mass-Encrypt | >= 100 | 5 MINUTES |
| Service Mass-Stop | >= 5 | 1 MINUTES |
| Lateral Movement | >= 3 DISTINCT targets | 60 MINUTES |

---

## 20. Qualitätscheckliste QRadar

Vor jedem Commit eine neue AQL-Regel gegen diese Liste prüfen:

```
□ QR-ID ist eindeutig (grep -r 'QR-XXXXXX' hunts/qradar/ → kein Treffer)
□ Header-Kommentar vollständig (QR-ID, Technik, Severity, Confidence)
□ LOGSOURCETYPENAME-Filter passt zur Event-Quelle
□ UTF8(payload) ILIKE verwendet (nicht LIKE — ILIKE ist case-insensitiv)
□ LAST X MINUTES gesetzt (1440 = 24h für Standard-Hunts)
□ Für Netzwerk-Regeln: Private-IP-Ausschluss vorhanden
□ Threshold-Regeln: GROUP BY + HAVING + sinnvolles Zeitfenster
□ Keine echten IP-Adressen oder Hostnamen im Pattern
□ Beschreibung (Kommentar) erklärt was erkannt wird und warum
□ MITRE-Technik im Header korrekt referenziert
□ SQL-Syntax: SELECT vor WHERE, LAST am Ende mit Semikolon
□ Keine Panik-Formulierungen in Kommentaren
□ Sensitivity testen: Wird bei einer Testabfrage etwas zurückgegeben?
□ Specificity prüfen: Gibt es offensichtliche legitime FP-Quellen?
```

---

## 21. Deployment in QRadar

### 21.1 Manuelles Testing (Quick Check)

```
QRadar UI → Log Activity → Advanced Search → AQL einfügen → Search
```

Zeitfenster für Tests initial eng setzen (z.B. `LAST 60 MINUTES`) um
Ladezeiten zu minimieren. Dann auf `LAST 1440 MINUTES` erweitern.

### 21.2 Saved Search anlegen

```
Log Activity → Advanced Search → Save Criteria
  Name:     HT-QR-XXXXXX-[Kurzname]
  Category: HuntingThreats
  Shared:   Yes (für SOC-Team)
```

### 21.3 Custom Rule Engine (CRE) — Persistentes Monitoring

```
Offenses → Rules → Add Rule → Event
  Condition: "when the event payload contains X"
  Basis: Saved Search oder Custom Property
  Action: Create Offense → Severity Level zuweisen
```

**Empfohlene QRadar Offense-Severity-Mapping:**

| AQL Severity | QRadar Offense Severity |
|---|---|
| Critical | 9–10 |
| High | 7–8 |
| Medium | 5–6 |
| Low | 3–4 |

### 21.4 Bulk-Import via REST API

```bash
# Alle AQL-Dateien einer Kategorie als Batch testen
for f in hunts/qradar/execution/*.aql; do
  echo "=== $f ==="
  cat "$f" | grep -A20 "QR-"
done

# REST API — Suche starten
curl -k -X POST \
  "https://<qradar-host>/api/ariel/searches" \
  -H "SEC: <api_token>" \
  -H "Content-Type: application/json" \
  -d "{\"query_expression\": \"$(cat hunts/qradar/execution/001_powershell.aql | head -20 | tail -15)\"}"
```

### 21.5 FP-Rate in QRadar messen

```aql
-- Wie oft feuert eine Regel pro Tag?
SELECT
  DATEFORMAT(startTime, 'yyyy-MM-dd') AS Day,
  COUNT(*) AS HitCount
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) ILIKE '%Windows%'
  AND UTF8(payload) ILIKE '%<dein-muster>%'
GROUP BY Day
LAST 10080 MINUTES;  -- 7 Tage
```

Ziel: **< 5% False-Positive-Rate** in Produktion.
Bei > 5% FP: Pattern verfeinern oder zusätzlichen Filter ergänzen.

---

## 22. Cheat Sheet QRadar

### AQL-Skelett (Copy-Paste)

```sql
-- QR-XXXXXX | T1XXX.XXX | Name
-- Severity: High | Confidence: High
SELECT
  DATEFORMAT(startTime, 'yyyy-MM-dd HH:mm:ss') AS EventTime,
  LOGSOURCENAME(logsourceid) AS LogSource,
  username,
  UTF8(payload) AS EventPayload
FROM events
WHERE (LOGSOURCETYPENAME(logsourceid) ILIKE '%Windows%'
    OR LOGSOURCETYPENAME(logsourceid) ILIKE '%Sysmon%')
  AND UTF8(payload) ILIKE '%MUSTER%'
LAST 1440 MINUTES;
```

### Threshold-Skelett (Copy-Paste)

```sql
-- QR-XXXXXX | T1XXX | Threshold-Name
-- Severity: High | Threshold: N in M MINUTES
SELECT
  sourceip,
  COUNT(*) AS HitCount
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) ILIKE '%Windows%'
  AND UTF8(payload) ILIKE '%MUSTER%'
GROUP BY sourceip
HAVING COUNT(*) >= N
LAST M MINUTES;
```

### Log-Source-Filter Kurzreferenz

```
'%Windows%'    → Windows Security + System + Application
'%Sysmon%'     → Microsoft Windows Sysmon
'%PowerShell%' → PowerShell Script Block Logging
'%WinCollect%' → IBM WinCollect Agent
'%Firewall%'   → Netzwerk-Firewall
'%Netflow%'    → Netflow / IPFIX
```

### Event-Typ-Pattern Kurzreferenz

```sql
-- Sysmon Events via payload
'%ProcessCreate%'    → Event 1  (Prozess gestartet)
'%NetworkConnect%'   → Event 3  (Netzwerkverbindung)
'%DriverLoad%'       → Event 6  (Treiber geladen)
'%ImageLoad%'        → Event 7  (DLL geladen)
'%CreateRemoteThread%' → Event 8 (Remote Thread)
'%ProcessAccess%'    → Event 10 (Prozess-Zugriff)
'%FileCreate%'       → Event 11 (Datei erstellt)
'%RegistryEvent%'    → Event 12/13 (Registry-Änderung)
'%DnsQuery%'         → Event 22 (DNS-Abfrage)
'%ProcessTamper%'    → Event 25 (Prozess manipuliert)

-- Windows Security Events
'%EventID>4624<%'    → Logon Success
'%EventID>4625<%'    → Logon Failure
'%EventID>4688<%'    → Process Created
'%EventID>4698<%'    → Scheduled Task Created
'%EventID>7045<%'    → Service Installed
'%EventID>1102<%'    → Audit Log Cleared
```

### Severity-Mapping (QRadar Offense)

```
Critical  → Offense Severity 9–10 (sofortiger Alert)
High      → Offense Severity 7–8  (Alert innerhalb 1h)
Medium    → Offense Severity 5–6  (Triage im SOC)
Low       → Offense Severity 3–4  (Hunt Log / Beobachtung)
```

---

## 23. Neue YARA-L-Regel schreiben

### 23.1 Template — Einfache YARA-L 2.0 Regel

```yaral
rule ht_gs_XXXXXX_kurzname {
  meta:
    rule_id         = "GS-XXXXXX"
    author          = "HuntingThreats"
    description     = "Kurzbeschreibung was erkannt wird — Angriffskontext"
    mitre_tactic    = "Execution"
    mitre_technique = "T1XXX.XXX"
    severity        = "HIGH"
    confidence      = "HIGH"
    platform        = "Google SecOps / Chronicle SIEM"
    created         = "2026-06-07"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e.target.process.command_line, `(?i)verdächtiges-muster`) nocase

  condition:
    $e
}
```

### 23.2 Template — Neue YARA-L-Datei anlegen

```yaral
// ============================================================
// HuntingThreats — Google SecOps YARA-L 2.0 Hunt Rules
// Category : [Taktik] ([T1XXX, T1XXX])
// Batch    : NN / [Kategoriename]
// Rules    : GS-XXXXXX – GS-XXXXXX
// Platform : Google SecOps / Chronicle SIEM — YARA-L 2.0
// Sources  : Sysmon (UDM: PROCESS_LAUNCH, NETWORK_CONNECTION, ...)
//            Windows Security Events (UDM: USER_LOGIN, ...)
// ============================================================
```

### 23.3 Rule-Naming-Konvention

```
Dateiname:    001_powershell.yaral
Rule-Name:    ht_gs_XXXXXX_kurzname
              │   │        └── Sprechender Kurzname (lowercase, underscores)
              │   └── GS-Namespace + 6-stellige ID
              └── Pflicht-Prefix für alle Hunt-Pack-Regeln

meta.rule_id: "GS-XXXXXX"   (GS = Google SecOps)
```

### 23.4 Nächste freie GS-Rule-IDs

```
Taktik                    Letzter GS-Prefix   Nächste freie ID
────────────────────────────────────────────────────────────────
Initial Access            GS-110040           GS-110041
Execution (3 Dateien)     GS-100100           GS-100101
Persistence (3 Dateien)   GS-101080           GS-101081
Privilege Escalation      GS-109040           GS-109041
Defense Evasion           GS-102035           GS-102036
Credential Access         GS-103035           GS-103036
Discovery                 GS-106035           GS-106036
Lateral Movement          GS-105040           GS-105041
C2 & Network              GS-104035           GS-104036
Exfiltration              GS-107030           GS-107031
Impact                    GS-108030           GS-108031
```

---

## 24. UDM-Feldnamen-Referenz

### 24.1 UDM Event-Typen (metadata.event_type)

```
PROCESS_LAUNCH          → Sysmon Event 1 / Windows Event 4688
PROCESS_TERMINATION     → Prozess beendet
NETWORK_CONNECTION      → Sysmon Event 3 (Netzwerkverbindung)
FILE_CREATION           → Sysmon Event 11 (Datei erstellt)
FILE_MODIFICATION       → Datei geändert
REGISTRY_MODIFICATION   → Sysmon Event 13 (Registry Set)
USER_LOGIN              → Windows Event 4624 / 4625
SERVICE_CREATION        → Windows Event 7045
NETWORK_DNS             → Sysmon Event 22 (DNS-Abfrage)
PROCESS_OPEN            → Sysmon Event 10 (Process Access)
DRIVER_LOAD             → Sysmon Event 6 (Treiber geladen)
IMAGE_LOAD              → Sysmon Event 7 (DLL geladen)
```

### 24.2 Prozess-Felder (PROCESS_LAUNCH)

```
$e.target.process.command_line           → Komplette Commandline
$e.target.process.file.full_path         → Vollpfad Executable (Ziel-Prozess)
$e.principal.process.file.full_path      → Vollpfad Parent-Prozess
$e.target.process.file.md5               → MD5-Hash
$e.target.process.file.sha256            → SHA256-Hash
$e.principal.user.userid                 → Ausführender User
$e.target.process.pid                    → PID
$e.principal.process.pid                 → Parent-PID
```

### 24.3 Netzwerk-Felder (NETWORK_CONNECTION)

```
$e.target.ip                             → Ziel-IP-Adresse
$e.target.port                           → Ziel-Port
$e.principal.ip                          → Quell-IP
$e.principal.port                        → Quell-Port
$e.network.ip_protocol                   → Protokoll (TCP/UDP/ICMP)
$e.network.direction                     → OUTBOUND/INBOUND
$e.network.sent_bytes                    → Gesendete Bytes
$e.network.received_bytes                → Empfangene Bytes
$e.principal.process.file.full_path      → Prozess der Verbindung aufbaut
```

### 24.4 DNS-Felder (NETWORK_DNS)

```
$e.network.dns.questions.name            → Angefragte Domain
$e.network.dns.questions.type            → Record-Typ (1=A, 16=TXT, 28=AAAA)
$e.network.dns.answers.name              → DNS-Antwort-Name
$e.principal.process.file.full_path      → Anfragender Prozess
```

### 24.5 Registry-Felder (REGISTRY_MODIFICATION)

```
$e.target.registry.registry_key          → Vollständiger Registry-Pfad
$e.target.registry.registry_value_name   → Wert-Name
$e.target.registry.registry_value_data   → Wert-Inhalt
$e.principal.process.file.full_path      → Prozess der Änderung vornimmt
```

### 24.6 Datei-Felder (FILE_CREATION)

```
$e.target.file.full_path                 → Vollständiger Datei-Pfad
$e.target.file.file_extension            → Dateiendung
$e.target.file.md5                       → MD5-Hash
$e.principal.process.file.full_path      → Prozess der Datei erstellt
```

### 24.7 Logon-Felder (USER_LOGIN)

```
$e.principal.user.userid                 → Benutzername
$e.principal.ip                          → Quell-IP der Anmeldung
$e.target.hostname                       → Ziel-Hostname
$e.extensions.auth.auth_details          → "Success" / "Failure"
$e.extensions.auth.auth_type             → NTLM / Kerberos / SAML
$e.extensions.auth.mechanism             → Authentifizierungsmechanismus
```

### 24.8 Service-Felder (SERVICE_CREATION)

```
$e.target.application                    → Service-Name
$e.target.file.full_path                 → Service-Binär-Pfad (ImagePath)
$e.target.process.command_line           → Service-Commandline
```

---

## 25. YARA-L Muster-Bibliothek

### 25.1 Regex-Matching

```yaral
// Case-insensitive Regex (Standard für alle Pfade/Tools)
re.regex($e.target.process.command_line, `(?i)-encodedcommand`) nocase

// Pfad-Match (endet auf Executable)
re.regex($e.target.process.file.full_path, `(?i)\\powershell\.exe$`) nocase

// OR-Gruppe (mehrere Binaries)
re.regex($e.target.process.file.full_path, `(?i)\\(cmd|powershell|wscript)\.exe$`) nocase

// Staging-Pfade
re.regex($e.target.process.file.full_path, `(?i)(\\appdata\\|\\temp\\|\\downloads\\|\\public\\)`) nocase

// Base64-String (mindestens 80 Zeichen)
re.regex($e.target.process.command_line, `[A-Za-z0-9+/]{80,}={0,2}`) nocase
```

### 25.2 Exakter Feld-Match

```yaral
// Exakter Event-Typ
$e.metadata.event_type = "PROCESS_LAUNCH"

// Exakter Port-Match
$e.target.port = 4444

// Boolean-Feld
$e.network.direction = "OUTBOUND"

// Auth-Ergebnis
$e.extensions.auth.auth_details = "Success"
```

### 25.3 CIDR-Ausschlüsse (Netzwerk-Regeln)

```yaral
// Privat-IPs ausschließen (Standard für C2/Exfil-Regeln)
NOT $e.target.ip in cidr "10.0.0.0/8"
NOT $e.target.ip in cidr "192.168.0.0/16"
NOT $e.target.ip in cidr "172.16.0.0/12"
NOT $e.target.ip in cidr "127.0.0.0/8"
NOT $e.target.ip in cidr "169.254.0.0/16"
```

### 25.4 Mehrere Bedingungen kombinieren (AND)

Alle `events:`-Bedingungen werden automatisch mit AND verknüpft:

```yaral
events:
  $e.metadata.event_type = "PROCESS_LAUNCH"
  // Beide müssen gleichzeitig zutreffen:
  re.regex($e.principal.process.file.full_path, `(?i)\\WINWORD\.EXE$`) nocase
  re.regex($e.target.process.command_line, `(?i)(powershell|cmd|wscript)`) nocase
```

### 25.5 Feldgleichheit über Events (Multi-Event)

```yaral
// Zwei Events müssen vom gleichen Host kommen:
$e1.principal.hostname = $e2.principal.hostname

// Gleicher User in beiden Events:
$e1.principal.user.userid = $e2.principal.user.userid

// Gleiche Quell-IP:
$e1.principal.ip = $e2.principal.ip
```

---

## 26. Threshold-Regeln (YARA-L)

Beaconing, Brute Force, Scanning: `match:` Block + `#variable > N`:

### 26.1 Beaconing-Pattern

```yaral
rule ht_gs_104004_beaconing_threshold {
  meta:
    rule_id         = "GS-104004"
    mitre_technique = "T1071.001"
    severity        = "HIGH"

  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    NOT $e.target.ip in cidr "10.0.0.0/8"
    NOT $e.target.ip in cidr "192.168.0.0/16"
    NOT $e.target.ip in cidr "172.16.0.0/12"

  match:
    $e.target.ip over 60m   // Gruppiere nach Ziel-IP im 60-Minuten-Fenster

  condition:
    #e > 20                  // Mehr als 20 Verbindungen = Beaconing
}
```

### 26.2 Brute-Force-Pattern

```yaral
rule ht_gs_110032_password_spray_threshold {
  meta:
    rule_id         = "GS-110032"
    mitre_technique = "T1110.003"
    severity        = "HIGH"

  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.extensions.auth.auth_details = "Failure"
    NOT $e.principal.ip in cidr "10.0.0.0/8"
    NOT $e.principal.ip in cidr "192.168.0.0/16"

  match:
    $e.principal.ip over 5m   // Gruppiere nach Quell-IP in 5 Minuten

  condition:
    #e > 5                     // Mehr als 5 Fehlversuche
}
```

### 26.3 Threshold-Referenzwerte

| Szenario | match: over | condition: #e > |
|---|---|---|
| Brute Force Login | 5m | 10 |
| Password Spray | 5m | 5 |
| Port Scan | 5m | 20 |
| Beaconing (Medium) | 60m | 10 |
| Beaconing (High) | 60m | 20 |
| DNS Tunneling | 10m | 100 |
| Ransomware Mass-Encrypt | 5m | 100 |
| Mass Service Stop | 2m | 5 |
| Discovery Burst | 2m | 10 |
| Lateral Movement (Hosts) | 10m | 5 |

---

## 27. Multi-Event-Korrelation (YARA-L)

Angriffsketten über mehrere Events mit Zeitfenster:

### 27.1 Template — Zwei-Event-Korrelation

```yaral
rule ht_gs_XXXXXX_chain_name {
  meta:
    rule_id         = "GS-XXXXXX"
    mitre_technique = "T1XXX"
    severity        = "CRITICAL"

  events:
    // Event 1: Erstes Angriffs-Signal
    $e1.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e1.target.process.command_line, `(?i)mimikatz`) nocase

    // Event 2: Folge-Aktivität auf gleichem Host
    $e2.metadata.event_type = "NETWORK_CONNECTION"
    NOT $e2.target.ip in cidr "10.0.0.0/8"
    $e2.principal.hostname = $e1.principal.hostname   // Gleicher Host!

  match:
    $e1.principal.hostname over 30m   // 30-Minuten-Korrelationsfenster

  condition:
    $e1 and $e2   // Beide Events müssen auftreten
}
```

### 27.2 Template — Drei-Event-Angriffskette

```yaral
rule ht_gs_110040_initial_access_chain {
  meta:
    rule_id         = "GS-110040"
    mitre_technique = "T1566.001"
    severity        = "CRITICAL"

  events:
    // Event 1: Externer Login
    $e1.metadata.event_type = "USER_LOGIN"
    NOT $e1.principal.ip in cidr "10.0.0.0/8"
    NOT $e1.principal.ip in cidr "192.168.0.0/16"
    $e1.extensions.auth.auth_details = "Success"

    // Event 2: Recon-Prozess (gleicher Host)
    $e2.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e2.target.process.file.full_path, `(?i)(whoami|net\.exe|ipconfig)$`) nocase
    $e2.principal.hostname = $e1.target.hostname

    // Event 3: Persistenz-Schreiben (gleicher Host)
    $e3.metadata.event_type = "REGISTRY_MODIFICATION"
    re.regex($e3.target.registry.registry_key, `(?i)\\Run$`) nocase
    $e3.principal.hostname = $e1.target.hostname

  match:
    $e1.target.hostname over 30m

  condition:
    $e1 and $e2 and $e3
}
```

### 27.3 Korrelationsfenster-Richtwerte

| Angriffskette | match: over |
|---|---|
| Recon nach Login | 5m |
| Persistenz nach Staging | 10m |
| Lateral Move nach Credential Theft | 30m–60m |
| C2 nach Initial Access | 60m |
| Exfil nach Discovery | 120m |
| Ransomware-Vorstufen (Shadow + Disable + Encrypt) | 30m |

---

## 28. Qualitätscheckliste Google SecOps

Vor jedem Commit eine neue YARA-L-Regel gegen diese Liste prüfen:

```
□ GS-ID ist eindeutig (grep -r 'rule_id.*GS-XXXXXX' hunts/secops/ → kein Treffer)
□ Rule-Name folgt Konvention: ht_gs_XXXXXX_kurzname
□ meta-Block vollständig: rule_id, author, description, mitre_tactic, mitre_technique, severity, confidence
□ metadata.event_type korrekt gesetzt (PROCESS_LAUNCH / NETWORK_CONNECTION / ...)
□ re.regex() mit nocase am Ende (nicht nur (?i) im Pattern)
□ UDM-Feldnamen korrekt (nicht Sysmon-Rohfelder!)
□ Für Netzwerk-Regeln: CIDR-Ausschlüsse für private IPs vorhanden
□ Threshold-Regeln: match:-Block + #e > N Condition
□ Multi-Event: Hostname-/IP-Gleichheit zwischen Events gesetzt
□ Keine echten IP-Adressen oder Hostnamen im Pattern
□ MITRE-Technik-ID aktuell und korrekt (Sub-Technik bevorzugen)
□ Beschreibung erklärt was erkannt wird ohne Panik-Formulierungen
□ condition: $e (oder $e1 and $e2 ...) — nicht vergessen
□ YARA-L Syntax valid (Google SecOps Rule Editor → Validate)
□ FP-Check: Gibt es legitime Enterprise-Tools die das Pattern auslösen könnten?
```

---

## 29. Deployment in Google SecOps

### 29.1 Chronicle UI — Manuelle Validierung

```
Security Operations → Detection Engine → Rules → New Rule
  → YARA-L 2.0 auswählen
  → Regelinhalt einfügen
  → "Validate" klicken (Syntaxcheck)
  → "Run Test" auf historischen Daten
  → "Create" wenn Test sauber
```

**Zeitfenster für Tests:** Initial 1h wählen, dann auf 24h / 7 Tage ausweiten.

### 29.2 Alerting-Modus einstellen

```
LIVE: Regel läuft auf eingehenden Events — erzeugt Alerts in Echtzeit
      → Nur für high_confidence-Regeln (FP-Rate < 5%)

ALERTING DISABLED: Regel läuft, erzeugt aber keine Alerts
                   → Für neue Regeln im Einlaufbetrieb

RETROSPECTIVE: Regelauswertung auf historischen Daten (kein Echtzeit-Alert)
               → FP-Baseline messen vor Live-Schaltung
```

### 29.3 Bulk-Import via gcloud / API

```bash
# Alle YARA-L-Dateien einer Kategorie validieren
for f in hunts/secops/execution/*.yaral; do
  echo "=== $f ==="
  grep -E "rule_id|description|mitre_technique|severity" "$f"
done

# Chronicle Detection API (REST)
# POST /v2/projects/{project}/locations/{location}/instances/{instance}/rules
# Body: { "ruleText": "<yaral-inhalt>" }
# Auth: OAuth2 / Service Account mit Chronicle API Scope
```

### 29.4 FP-Rate in Google SecOps messen

```
Security Operations → Search (UDM Search)
  Zeitraum: Letzte 7 Tage
  Filter: metadata.ingested_timestamp > "7d ago"
         AND metadata.event_type = "DETECTION_ALERT"
         AND security_result.rule_name = "ht_gs_XXXXXX_name"
```

Ziel: **< 5% False-Positive-Rate** — gleicher Standard wie Wazuh/QRadar.

### 29.5 Severity-Mapping Google SecOps Alerts

| YARA-L meta.severity | Google SecOps Alert Level | Empfohlene Aktion |
|---|---|---|
| CRITICAL | CRITICAL | Sofort eskalieren |
| HIGH | HIGH | Alert innerhalb 1h |
| MEDIUM | MEDIUM | Triage im SOC |
| LOW | LOW | Hunt Log / Beobachtung |
| INFO | INFORMATIONAL | Nur loggen |

---

## 30. Cheat Sheet Google SecOps

### YARA-L-Skelett (Copy-Paste)

```yaral
rule ht_gs_XXXXXX_kurzname {
  meta:
    rule_id         = "GS-XXXXXX"
    author          = "HuntingThreats"
    description     = "BINARY: AKTION — KONTEXT"
    mitre_tactic    = "TAKTIK"
    mitre_technique = "T1XXX.XXX"
    severity        = "HIGH"
    confidence      = "HIGH"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e.target.process.command_line, `(?i)MUSTER`) nocase

  condition:
    $e
}
```

### Threshold-Skelett (Copy-Paste)

```yaral
rule ht_gs_XXXXXX_threshold_name {
  meta:
    rule_id         = "GS-XXXXXX"
    mitre_technique = "T1XXX"
    severity        = "HIGH"

  events:
    $e.metadata.event_type = "NETZWERK_EVENT_TYP"
    NOT $e.target.ip in cidr "10.0.0.0/8"
    NOT $e.target.ip in cidr "192.168.0.0/16"
    NOT $e.target.ip in cidr "172.16.0.0/12"

  match:
    $e.target.ip over Xm   // Gruppierungsfeld + Zeitfenster

  condition:
    #e > N
}
```

### UDM Event-Typen Kurzreferenz

```
PROCESS_LAUNCH          → Sysmon 1 / Win 4688  (commandLine, file.full_path)
NETWORK_CONNECTION      → Sysmon 3             (target.ip, target.port)
FILE_CREATION           → Sysmon 11            (target.file.full_path)
REGISTRY_MODIFICATION   → Sysmon 13            (registry_key, registry_value_data)
USER_LOGIN              → Win 4624/4625         (auth_details, principal.ip)
SERVICE_CREATION        → Win 7045             (target.application, target.file.full_path)
NETWORK_DNS             → Sysmon 22            (dns.questions.name, dns.questions.type)
PROCESS_OPEN            → Sysmon 10            (target.process, principal.process)
DRIVER_LOAD             → Sysmon 6             (target.file.full_path, target.file.signed)
IMAGE_LOAD              → Sysmon 7             (target.file.full_path, target.file.signed)
```

### CIDR-Ausschluss Kurzreferenz

```yaral
NOT $e.target.ip in cidr "10.0.0.0/8"       // Klasse A privat
NOT $e.target.ip in cidr "192.168.0.0/16"   // Klasse C privat
NOT $e.target.ip in cidr "172.16.0.0/12"    // Klasse B privat
NOT $e.target.ip in cidr "127.0.0.0/8"      // Loopback
NOT $e.target.ip in cidr "169.254.0.0/16"   // Link-Local (APIPA)
```

### Severity-Kurzreferenz

```
CRITICAL  → Sofortiger Alert (nahezu ausschließlich bösartig)
HIGH      → Alert innerhalb 1h (fast immer bösartig)
MEDIUM    → Triage im SOC (selten legitim im Enterprise-Kontext)
LOW       → Hunt Log / Beobachtung (häufig legitim, Kontext nötig)
INFO      → Nur Discovery/Enum (immer legitim möglich)
```

---

*Version 0.3.0 | 2026-06-07 | HuntingThreats Enterprise Hunt Pack*
