# Hunt Pack — Architektur & Regelsprachen

> **HuntingThreats Enterprise Hunt Pack** — Dokumentation der Regelarchitektur,
> Regelsprachen und Design-Entscheidungen.
>
> Gültig für: Wazuh Batch 1 (500 Regeln ✅) · QRadar Batch 1 (500 Regeln ✅) · Google SecOps Batch 1 (500 Regeln ✅) · Splunk (geplant)

---

## 1. Überblick

Das Enterprise Hunt Pack ist eine Sammlung von Threat-Hunting-Regeln für
Security Information and Event Management (SIEM)-Systeme. Jede Regel deckt ein
konkretes Angriffsmuster aus dem **MITRE ATT&CK Framework** ab.

```
Hunt Pack
├── wazuh/      Wazuh 4.x XML-Regelformat   (500 Regeln ✅ — Batch 1 fertig)
├── qradar/     QRadar AQL-Format            (500 Regeln ✅ — Batch 1 fertig)
├── secops/     Google SecOps YARA-L 2.0     (500 Regeln ✅ — Batch 1 fertig)
└── splunk/     Splunk SPL-Format            (500 Regeln — geplant)
```

---

## 2. Regelsprachen

### 2.1 Wazuh — XML Rule Language

**Technologie:** Wazuh 4.x Custom Rule Engine  
**Dateiformat:** XML (`.xml`)  
**Encoding:** UTF-8  
**Regex-Engine:** PCRE2 (Perl Compatible Regular Expressions v2)

Wazuh-Regeln sind deklarative XML-Dokumente. Jede Regel definiert:

| Element | Bedeutung |
|---|---|
| `<rule id="..." level="...">` | Eindeutige Regel-ID + Severity (1–15) |
| `<if_group>` | Vorbedingung: Log-Gruppe (z.B. `windows`) |
| `<field name="..." type="pcre2">` | Feld-Match gegen PCRE2-Pattern |
| `<description>` | Menschenlesbarer Regeltext |
| `<mitre><id>` | MITRE ATT&CK Technik-ID |
| `<group>` | Tags für Kategorisierung / Correlation |
| `<frequency>` + `<timeframe>` | Threshold-Detektion (N Events in X Sekunden) |
| `<same_field>` | Korrelliert Events über dasselbe Feldfeld |

**Feldnamen (Windows / Sysmon):**

```xml
<!-- Process Creation -->
win.system.eventID          → Event-ID (1, 4688, etc.)
win.eventdata.image         → Sysmon: Vollpfad der Executable
win.eventdata.newProcessName → Windows Security 4688: Prozessname
win.eventdata.commandLine   → Komplette Commandline
win.eventdata.parentImage   → Parent-Prozess (Sysmon)

<!-- Network -->
win.eventdata.destinationIp     → Ziel-IP
win.eventdata.destinationPort   → Ziel-Port
win.eventdata.destinationHostname → Ziel-Hostname (DNS)
win.eventdata.initiated         → true = ausgehend

<!-- Registry -->
win.eventdata.targetObject  → Vollständiger Registry-Pfad
win.eventdata.details       → Neuer Wert

<!-- File -->
win.eventdata.targetFilename → Zieldatei-Pfad
win.eventdata.imageLoaded    → Geladene DLL (Sysmon 7)

<!-- PowerShell -->
win.eventdata.scriptBlockText → Entschlüsselter Script-Block (Event 4104)
```

**Minimal-Beispiel einer Wazuh-Regel:**

```xml
<rule id="100001" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID" type="pcre2">^1$|^4688$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)-encodedcommand</field>
  <description>PowerShell: EncodedCommand verwendet — obfuskiertes Skript (T1059.001)</description>
  <mitre><id>T1059.001</id></mitre>
  <group>execution,powershell,encoded,high_confidence,</group>
</rule>
```

---

### 2.2 Splunk — SPL (Search Processing Language) *(geplant)*

**Technologie:** Splunk Enterprise Security / Splunk SIEM  
**Dateiformat:** SPL-Suchanfragen (`.spl` oder als Savedsearch-XML)  
**Pattern:** Index-Suche + `| eval` + `| stats` + `| where`

Splunk-Regeln basieren auf der **Splunk Common Information Model (CIM)** —
normalisierte Feldnamen über alle Log-Quellen hinweg.

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
  EventCode=1
  CommandLine="*-EncodedCommand*"
| eval mitre_technique="T1059.001"
| table _time, host, User, ParentImage, Image, CommandLine
```

---

### 2.3 Google SecOps — YARA-L 2.0

**Technologie:** Google SecOps (Chronicle SIEM)  
**Dateiformat:** YARA-L 2.0 (`.yaral`)  
**Pattern:** `rule { meta: events: [match:] condition: }`

YARA-L 2.0 ist eine deklarative Regelsprache für Google SecOps basierend auf dem
**Unified Data Model (UDM)** — normalisierte Felder über alle Log-Quellen.

| Element | Bedeutung |
|---|---|
| `meta:` | Metadaten: rule_id, author, description, MITRE ATT&CK |
| `events:` | Eventfilter mit UDM-Feldern + YARA-L Regex |
| `match:` | Grouping-Felder + Zeitfenster für Threshold-Regeln |
| `condition:` | Logische Bedingung: `$e`, `$e1 and $e2`, `#e > N` |

**UDM-Feldschema (Wichtigste Felder):**

```yaral
// Prozess
$e.metadata.event_type = "PROCESS_LAUNCH"
$e.target.process.file.full_path           → Vollpfad der Executable
$e.target.process.command_line             → Komplette Commandline
$e.principal.process.file.full_path        → Parent-Prozess-Pfad
$e.principal.user.userid                   → Aufrufender Benutzer

// Netzwerk
$e.metadata.event_type = "NETWORK_CONNECTION"
$e.target.ip                               → Ziel-IP
$e.target.port                             → Ziel-Port
$e.network.http.url                        → HTTP URL
$e.network.dns.questions.name              → DNS Query-Name
$e.network.sent_bytes                      → Bytes gesendet

// Registry
$e.metadata.event_type = "REGISTRY_MODIFICATION"
$e.target.registry.registry_key            → Vollständiger Registry-Pfad
$e.target.registry.registry_value_data     → Neuer Wert

// Datei
$e.metadata.event_type = "FILE_CREATION"
$e.target.file.full_path                   → Zieldatei-Pfad
$e.target.file.size                        → Dateigröße in Bytes

// Login
$e.metadata.event_type = "USER_LOGIN"
$e.extensions.auth.auth_details            → SUCCESS / FAILED
$e.principal.ip                            → Quell-IP des Logins

// Service / DNS
$e.metadata.event_type = "SERVICE_CREATION"
$e.metadata.event_type = "NETWORK_DNS"
```

**Minimal-Beispiel einer YARA-L 2.0 Regel:**

```yaral
rule ht_gs_100001_powershell_encoded_command {
  meta:
    rule_id         = "GS-100001"
    author          = "HuntingThreats"
    description     = "PowerShell: -EncodedCommand flag — obfuscated script execution"
    mitre_tactic    = "Execution"
    mitre_technique = "T1059.001"
    severity        = "HIGH"
    confidence      = "HIGH"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e.target.process.command_line, `(?i)-enc(odedcommand)?\s`) nocase

  condition:
    $e
}
```

**Threshold-Detektion (match + #e > N):**

```yaral
rule ht_gs_103022_password_spray_threshold {
  meta:
    rule_id = "GS-103022"
    ...

  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.extensions.auth.auth_details = "FAILED"

  match:
    $e.principal.ip over 5m   // Grouping-Feld + Zeitfenster

  condition:
    #e > 10                   // Mehr als 10 Events im Fenster
}
```

**Multi-Event-Korrelation (Attack Chain):**

```yaral
rule ht_gs_110040_initial_access_combo {
  events:
    $e1.metadata.event_type = "USER_LOGIN"
    $e1.extensions.auth.auth_details = "SUCCESS"

    $e2.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e2.target.process.file.full_path, `(?i)\\whoami\.exe$`)

    $e3.metadata.event_type = "REGISTRY_MODIFICATION"

    $e1.target.hostname = $e2.principal.hostname
    $e2.principal.hostname = $e3.principal.hostname

  match:
    $e1.target.hostname over 30m

  condition:
    $e1 and $e2 and $e3
}
```

**CIDR-Matching:**

```yaral
// Private IP-Ausschluss
NOT $e.target.ip in cidr "10.0.0.0/8"
NOT $e.target.ip in cidr "192.168.0.0/16"
NOT $e.target.ip in cidr "172.16.0.0/12"
NOT $e.target.ip in cidr "127.0.0.0/8"
```

---

### 2.4 QRadar — AQL (Ariel Query Language)

**Technologie:** IBM QRadar 7.4+ SIEM  
**Dateiformat:** AQL-Abfragen (`.aql`)  
**Pattern:** `SELECT ... FROM events WHERE ... GROUP BY ... LAST X MINUTES`

QRadar-Regeln sind SQL-ähnliche Abfragen gegen die **Ariel-Datenbank**. Jede Abfrage definiert:

| Element | Bedeutung |
|---|---|
| `SELECT ... FROM events` | Felder die ausgegeben werden |
| `LOGSOURCETYPENAME(logsourceid) ILIKE '%Windows%'` | Log-Quell-Typ-Filter |
| `UTF8(payload) ILIKE '%muster%'` | Case-insensitiver Payload-Match |
| `DATEFORMAT(startTime, ...)` | Timestamp-Formatierung |
| `LOGSOURCENAME(logsourceid)` | Hostname / Asset-Name |
| `GROUP BY ... HAVING COUNT(*) >= N` | Threshold-Detektion |
| `LAST N MINUTES` | Zeitfenster |

**Universaler Payload-Ansatz:**

Da QRadar DSM/CEP-Konfigurationen deploymentspezifisch sind, nutzt das Hunt Pack
`UTF8(payload) ILIKE '%keyword%'` — funktioniert in jedem Standard-Deployment
mit WinCollect / Windows Log Sources ohne Custom Event Properties.

**Standard-Log-Source-Typen:**

```
'Microsoft Windows Security Event Log'   → Windows Security (4624, 4688 etc.)
'Microsoft Windows Sysmon'               → Sysmon Events
'Microsoft Windows PowerShell'           → PowerShell Script Block Logging
'WinCollect'                             → WinCollect Agent (alle Windows Events)
'Firewall'                               → Netzwerk-Firewall-Logs
'Netflow'                                → Netflow / IPFIX
```

**Normalisierte QRadar-Felder:**

```
sourceip          → Quell-IP (normalisiert durch QRadar)
destinationip     → Ziel-IP (normalisiert)
destinationport   → Ziel-Port (normalisiert)
username          → Benutzername (normalisiert)
startTime         → Event-Zeitstempel
logsourceid       → Log-Source-ID
eventcount        → Anzahl aggregierter Events (für Netflow/Bytes)
```

**Minimal-Beispiel einer QRadar AQL-Regel:**

```sql
-- QR-100001 | T1059.001 | PowerShell EncodedCommand
SELECT
  DATEFORMAT(startTime, 'yyyy-MM-dd HH:mm:ss') AS EventTime,
  LOGSOURCENAME(logsourceid) AS LogSource,
  username,
  UTF8(payload) AS EventPayload
FROM events
WHERE (LOGSOURCETYPENAME(logsourceid) ILIKE '%Windows%'
    OR LOGSOURCETYPENAME(logsourceid) ILIKE '%Sysmon%'
    OR LOGSOURCETYPENAME(logsourceid) ILIKE '%PowerShell%')
  AND (UTF8(payload) ILIKE '%-EncodedCommand%'
    OR UTF8(payload) ILIKE '%-enc %')
LAST 1440 MINUTES;
```

**Threshold-Detektion (GROUP BY + HAVING):**

```sql
-- Brute Force: 10+ Fehlversuche von gleicher IP in 15 Minuten
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

**Private-IP-Ausschluss (Standardmuster):**

```sql
NOT (destinationip ILIKE '10.%'
  OR destinationip ILIKE '192.168.%'
  OR destinationip ILIKE '172.1%.%'
  OR destinationip ILIKE '127.%')
```

---

## 3. Architektur

### 3.1 MITRE ATT&CK Alignment

Das Hunt Pack folgt der **MITRE ATT&CK Taktik-Struktur**. Jede Kategorie
entspricht einer ATT&CK-Taktik:

```
Taktik                    Verzeichnis                 Wazuh ID-Bereich
────────────────────────────────────────────────────────────────────────
Initial Access            initial_access/             110000–110999
Execution                 execution/                  100000–100999
Persistence               persistence/                101000–101999
Privilege Escalation      privilege_escalation/       109000–109999
Defense Evasion           defense_evasion/            102000–102999
Credential Access         credential_access/          103000–103999
Discovery                 discovery/                  106000–106999
Lateral Movement          lateral_movement/           105000–105999
Command & Control         c2/                         104000–104999
Exfiltration              exfiltration/               107000–107999
Impact                    impact/                     108000–108999
```

### 3.2 Rule-ID-Namespace

```
Taktik                    Bereich        Wazuh ID    QRadar-Prefix
────────────────────────────────────────────────────────────────────
Initial Access            110000–110999  10 Regeln  QR-110001–110040
Execution                 100000–100999  100 Regeln QR-100001–100100
Persistence               101000–101999  80 Regeln  QR-101001–101080
Privilege Escalation      109000–109999  40 Regeln  QR-109001–109040
Defense Evasion           102000–102999  35 Regeln  QR-102001–102035
Credential Access         103000–103999  35 Regeln  QR-103001–103035
Discovery                 106000–106999  35 Regeln  QR-106001–106035
Lateral Movement          105000–105999  40 Regeln  QR-105001–105040
C2 & Network              104000–104999  35 Regeln  QR-104001–104035
Exfiltration              107000–107999  30 Regeln  QR-107001–107030
Impact                    108000–108999  30 Regeln  QR-108001–108030

Kommentar-Format (AQL):      -- QR-XXXXXX | T1XXX.XXX | Rule Name
Kommentar-Format (Wazuh):   <!-- Wazuh ID: XXXXXX | T1XXX.XXX -->
Google SecOps Rule Names:    ht_gs_XXXXXX_[shortname]  (YARA-L rule name)
SecOps meta.rule_id:         GS-XXXXXX
Splunk Correlation Names:    ht_[tactic]_[shortname]
```

### 3.3 Severity-Schema (Wazuh Level)

Wazuh-Level steuert die Alerting-Priorität. Das Hunt Pack verwendet:

| Level | Bedeutung | Beispiele |
|---|---|---|
| **6** | Informational — Discovery, Enumeration | tasklist, nslookup |
| **8** | Low — Suspicious aber häufig legitim | whoami, systeminfo |
| **10** | Medium — Erhöhte Aufmerksamkeit | HKCU Run-Key, schtasks create |
| **12** | High — Wahrscheinlich bösartig | Mimikatz-Keyword, LSASS-Zugriff |
| **14** | Critical — Fast immer bösartig | Ransom-Note, Shadow-Copy-Delete |

### 3.4 Tag-System (group-Element)

Jede Regel hat ein `<group>`-Element mit Tags, das maschinelle Filterung ermöglicht:

```
Aufbau: [taktik],[technik],[konfidenz-tag],
Beispiel: execution,powershell,encoded,high_confidence,

Konfidenz-Tags:
  high_confidence  → Niedrige FP-Rate, kaum legitime Nutzung
  critical         → Regel feuert fast nie legitim
  threshold        → Nur aussagekräftig mit Frequency+Timeframe
  (kein Tag)       → Moderate FP-Rate — Kontext erforderlich
```

### 3.5 Datenquellen

Das Hunt Pack deckt folgende Windows-Ereignisquellen ab:

| Quelle | Kanal | Wichtigste Event-IDs |
|---|---|---|
| **Sysmon** | `Microsoft-Windows-Sysmon/Operational` | 1, 2, 3, 6, 7, 8, 10, 11, 13, 19–22, 25 |
| **Windows Security** | `Security` | 4624/25, 4648, 4672/73, 4688, 4698–4702, 4720, 4728/32, 4769 |
| **Windows System** | `System` | 7036, 7040, 7045 |
| **PowerShell** | `Microsoft-Windows-PowerShell/Operational` | 4103 (Pipeline), 4104 (Script Block) |
| **WMI** | `Microsoft-Windows-WMI-Activity/Operational` | Sysmon 19/20/21 bevorzugt |
| **DNS Client** | Sysmon DNS | 22 (DNSEvent) |
| **Driver Load** | Sysmon | 6 (Kernel Driver) |

### 3.6 Event-ID-Matrix nach Kategorie

```
Sysmon Event-ID → Was wird detektiert
────────────────────────────────────────
1   Process Create       → Execution, Lateral Movement, Persistence
2   File Time Changed    → Defense Evasion (Timestomping)
3   Network Connect      → C2, Exfiltration, Lateral Movement
6   Driver Loaded        → Privilege Escalation (Rootkit)
7   Image Loaded         → DLL Injection, Side-loading
8   CreateRemoteThread   → Process Injection
10  Process Access       → LSASS Dumping, Injection Prep
11  File Created         → Payload Drop, Ransomware, Staging
12  Registry Key Create  → Persistence
13  Registry Value Set   → Persistence, UAC Bypass
19  WMI EventFilter      → WMI Subscription
20  WMI EventConsumer    → WMI Subscription
21  WMI FilterBinding    → WMI Subscription (final)
22  DNS Query            → C2, Exfiltration, Tunneling
25  Process Tampered     → Process Hollowing
```

---

## 4. Designprinzipien

### 4.1 False-Positive-Minimierung

Alle Regeln folgen diesen Grundsätzen:

1. **Kontextbedingungen**: Nicht nur das Binary, sondern auch Parent-Prozess, Commandline-Flags und Pfad prüfen
2. **Negative Lookahead**: Legitime Anwendungen über `(?!...)` ausschließen (z.B. Task Manager bei LSASS-Zugriff)
3. **Konservative Portlisten**: Nur eindeutige C2-Ports, keine Entwickler-Ports (8080, 8888 etc.)
4. **Threshold statt Einzelevent**: Für Beaconing und Scanning Frequency+Timeframe nutzen

### 4.2 IOSP (Integration Operation Separation Principle)

Regeln sind **deklarativ** — sie beschreiben WAS zu erkennen ist, nicht WIE zu reagieren ist. Aktionen (Alerting, Isolation) werden im SIEM konfiguriert.

### 4.3 Keine Panik-Formulierungen

Regelbeschreibungen verwenden nie Begriffe wie *Malware gefunden*, *infiziert*, *kompromittiert*. Stattdessen: *Muster erkannt*, *Technik detektiert*, *Verhaltensauffälligkeit*.

### 4.4 Vollständige MITRE-Referenz

Jede Regel referenziert mindestens eine MITRE ATT&CK Technik. Sub-Techniken (T1xxx.yyy) werden bevorzugt, wenn die Regel spezifisch genug ist.

---

## 5. Abdeckungsmatrix

### Batch 1 — Wazuh (500 Regeln ✅)

```
Taktik                   Regeln   Dateien   Highlights
─────────────────────────────────────────────────────────────────────────
Initial Access             40       1        Phishing, Drive-by, Web Shells
Execution                 100       3        PowerShell, LOLBins, WMI, Office
Persistence                80       3        Registry, Schtasks, Services
Privilege Escalation       40       1        UAC Bypass, Token, AD Delegation
Defense Evasion            35       1        Injection, Hollowing, Log Tampering
Credential Access          35       1        LSASS, Kerberos, Browser Creds
Discovery                  35       1        Enum, AD Recon, AV Discovery
Lateral Movement           40       1        RDP, WMI, SMB, Pass-the-Hash
C2 & Network               35       1        Ports, Tunneling, Beaconing
Exfiltration               30       1        HTTP POST, DNS, Cloud, Archive
Impact                     30       1        Ransomware, Wiper, Backup Delete
─────────────────────────────────────────────────────────────────────────
GESAMT                    500      15        52 MITRE-Techniken abgedeckt
```

### Batch 1 — QRadar AQL (500 Regeln ✅)

```
Taktik                   Regeln   Dateien   Highlights
─────────────────────────────────────────────────────────────────────────
Initial Access             40       1        Phishing, HTML-Smuggling, ClickFix
Execution                 100       3        PowerShell, LOLBins, WMI, Office
Persistence                80       3        Registry, Schtasks, Services
Privilege Escalation       40       1        UAC Bypass, JuicyPotato, Kernel
Defense Evasion            35       1        Injection, AMSI/ETW Bypass, ADS
Credential Access          35       1        LSASS, Kerberoasting, Browser DB
Discovery                  35       1        Enum, BloodHound, AV-Discovery
Lateral Movement           40       1        RDP, WMI, SMB, RBCD, PetitPotam
C2 & Network               35       1        Cobalt Strike, Beaconing, DNS-over-H
Exfiltration               30       1        Rclone, DNS-Tunnel, Cloud APIs
Impact                     30       1        Ransomware, Shadow-Delete, Wiper
─────────────────────────────────────────────────────────────────────────
GESAMT                    500      15        52 MITRE-Techniken abgedeckt
```

### Batch 1 — Google SecOps YARA-L 2.0 (500 Regeln ✅)

```
Taktik                   Regeln   Dateien   Highlights
─────────────────────────────────────────────────────────────────────────
Initial Access             40       1        Phishing, Web Shell, Exploit, Brute Force
Execution                 100       3        PowerShell, LOLBins, WMI, Office Macros
Persistence                80       3        Registry, Schtasks, Services, Active Setup
Privilege Escalation       40       1        UAC Bypass, BYOVD, Token, AD Delegation
Defense Evasion            35       1        Injection, AMSI, ETW Bypass, Log Tampering
Credential Access          35       1        LSASS, Kerberoasting, DCSync, Browser DB
Discovery                  35       1        Enum, LDAP, BloodHound, AV Discovery
Lateral Movement           40       1        RDP, WMI, SMB, RBCD, PetitPotam, Impacket
C2 & Network               35       1        Cobalt Strike, Beaconing, DNS Tunnel, RATs
Exfiltration               30       1        Rclone, DNS Tunnel, Cloud APIs, HTTP POST
Impact                     30       1        Ransomware, Shadow Delete, Wiper, Service Stop
─────────────────────────────────────────────────────────────────────────
GESAMT                    500      15        52 MITRE-Techniken abgedeckt
```

**Google SecOps Deployment:**

```
1. YARA-L .yaral Dateien in SecOps Rule Editor importieren
2. Regeln aktivieren — Test-Modus zuerst empfohlen
3. Alerts konfigurieren: Alert Policies → YARA-L Match → Action
4. Threshold-Regeln: match-Block bestimmt das Aggregations-Fenster
5. API-Import: POST /v1/projects/{project}/locations/{region}/rules
```

### Batch 1 — Splunk SPL *(geplant)*

```
500 Regeln · 15 Dateien · Gleiche Taktik-Abdeckung wie Wazuh/QRadar/SecOps
Format: SPL + Splunk Common Information Model (CIM)
```

---

## 6. Technische Voraussetzungen

### Wazuh-Deployment

| Komponente | Mindestanforderung |
|---|---|
| **Wazuh Version** | 4.3.0+ (PCRE2 + Sysmon native support) |
| **Sysmon Version** | 13.0+ (Event 25 Process Tamper) |
| **Sysmon Config** | SwiftOnSecurity oder äquivalent |
| **PowerShell Logging** | Script Block Logging aktiviert (Event 4104) |
| **Windows Auditing** | Process Creation, Logon, Object Access, Registry |

**Deployment-Pfad:**
```
/var/ossec/rules/local_rules.xml       → Wazuh Standalone
/var/ossec/rules/ht_[tactic]_*.xml    → Empfohlen: separate Dateien pro Taktik
```

```bash
systemctl restart wazuh-manager
/var/ossec/bin/ossec-control reload   # ohne Neustart
```

### QRadar-Deployment

| Komponente | Mindestanforderung |
|---|---|
| **QRadar Version** | 7.4.0+ (AQL + UTF8() Funktion) |
| **Log-Sources** | WinCollect Agent oder Microsoft Windows DSM |
| **Sysmon** | 13.0+ via WinCollect auf Endpoints |
| **PowerShell** | Script Block Logging (Event 4104) → WinCollect weiterleiten |
| **Netflow** | Für Threshold-Exfil-Regeln (Bytes-basiert) |

**Deployment-Methode:**

```
1. AQL-Abfragen in QRadar Log Activity → Advanced Search einfügen
2. Für dauerhaftes Monitoring: Custom Rules Engine (CRE) erstellen
3. Alternativ: QRadar Use Cases als Saved Searches hinterlegen
4. Für SOC-Dashboard: Offense-Regeln auf Basis der AQL-Pattern bauen
```

**AQL-Import per API:**
```bash
curl -X POST "https://qradar/api/searches" \
  -H "SEC: <API_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"query_expression": "SELECT ... FROM events WHERE ... LAST 1440 MINUTES"}'
```

---

## 7. Versionierung

| Version | Datum | Inhalt |
|---|---|---|
| `0.1.0` | 2026-06-06 | Wazuh Batch 1: 500 Regeln, 15 Dateien, 11 Taktiken |
| `0.2.0` | 2026-06-06 | QRadar AQL Batch 1: 500 Regeln, 15 Dateien, 11 Taktiken |
| `0.3.0` | 2026-06-07 | Google SecOps YARA-L 2.0 Batch 1: 500 Regeln, 15 Dateien |
| `0.4.0` | *geplant* | Splunk SPL Batch 1: 500 Regeln |
| `1.0.0` | *geplant* | Alle 4 Plattformen, 2000 Regeln, Tuning-Guide |

---

*Generiert: 2026-06-07 | HuntingThreats Enterprise Hunt Pack v0.3.0*
