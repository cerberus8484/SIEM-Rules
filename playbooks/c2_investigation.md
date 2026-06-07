# Playbook: C2 Investigation

**ID:** PB-003 | **Schweregrad:** CRITICAL | **Version:** 1.0 | **Datum:** 2026-06-07

---

## Übersicht

Dieses Playbook führt durch die Untersuchung eines Command-and-Control-Verdachts — von der Erstidentifikation eines IOC bis zur vollständigen Kompromittierungs-Analyse und Eindämmung.

**Trigger:**
- Beaconing-Alert auf regelmäßige ausgehende Verbindungen
- Neuer Threat-Intel-IOC (IP, Domain, Hash) im Environment gefunden
- DNS-TXT-Query mit ungewöhnlich langen Labels
- Verbindung zu Tor / unbekanntem Proxy
- Alert auf bekannte C2-Ports (4444, 50050, 8443, 443 zu unbekanntem Host)

---

## Phase 1 — IOC im Environment suchen (5 Minuten)

### Schritt 1.1 — IP-IOC sweepen

**Splunk:**
```spl
index=windows EventCode=3 DestinationIp="<IOC_IP>"
| stats count values(Image) as processes values(host) as hosts by DestinationIp, DestinationPort
| sort -count
```

**QRadar:**
```sql
SELECT sourceip AS Intern, destinationip AS Extern, UTF8(payload) AS Details, COUNT(*) AS Verbindungen
FROM events
WHERE destinationip = '<IOC_IP>'
GROUP BY sourceip, destinationip, UTF8(payload)
LAST 10080 MINUTES
```

**Google SecOps:**
```
target.ip = "<IOC_IP>"
```

**Wazuh:**
```kql
data.win.eventdata.destinationIp: "<IOC_IP>"
```

---

### Schritt 1.2 — Domain-IOC sweepen (DNS)

**Splunk:**
```spl
index=windows EventCode=22 QueryName="<IOC_DOMAIN>"
| stats count values(Image) as processes values(host) as hosts by QueryName
| sort -count
```

**QRadar:**
```sql
SELECT sourceip AS Host, UTF8(payload) AS Details
FROM events
WHERE UTF8(payload) ILIKE '%<IOC_DOMAIN>%'
LAST 10080 MINUTES
```

**Google SecOps:**
```
network.dns.questions.name = "<IOC_DOMAIN>"
```

**Wazuh:**
```kql
data.win.eventdata.queryName: "<IOC_DOMAIN>"
```

---

### Schritt 1.3 — Hash-IOC sweepen

**Splunk:**
```spl
index=windows EventCode=1
| where match(Hashes, "(?i)<IOC_HASH>")
| stats count values(host) as hosts by Hashes, Image
```

**Google SecOps:**
```
target.process.file.sha256 = "<IOC_HASH>"
```

**Wazuh:**
```kql
data.win.eventdata.hashes: *<IOC_HASH>*
```

---

## Phase 2 — Beaconing-Analyse (10 Minuten)

### Schritt 2.1 — Verbindungs-Intervalle messen (Cobalt Strike Default: 60s)

**Splunk:**
```spl
index=windows EventCode=3 (DestinationIp="<IOC_IP>" OR DestinationHostname="<IOC_DOMAIN>")
| sort _time
| streamstats window=2 current=true last(_time) as prev_time by host, DestinationIp
| eval interval_sec=_time - prev_time
| stats avg(interval_sec) as avg_interval stdev(interval_sec) as stdev_interval count by host, DestinationIp
| where stdev_interval < 30 AND count > 10
| eval beaconing_score=if(stdev_interval < 10, "KRITISCH", if(stdev_interval < 30, "HOCH", "MEDIUM"))
```

**Splunk — Beaconing-Visualisierung (Zeitreihe):**
```spl
index=windows EventCode=3 host="<HOST>" DestinationIp="<IOC_IP>"
| timechart span=5m count
```

---

### Schritt 2.2 — Welcher Prozess kommuniziert?

**Splunk:**
```spl
index=windows host="<HOST>" EventCode=3 DestinationIp="<IOC_IP>"
| stats count first(_time) as first_seen last(_time) as last_seen by Image, ProcessId, DestinationPort
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M"), last_seen=strftime(last_seen,"%Y-%m-%d %H:%M")
```

**Wazuh:**
```kql
agent.name: "<HOST>" AND data.win.eventdata.destinationIp: "<IOC_IP>" AND data.win.system.eventID: "3"
```

---

### Schritt 2.3 — Prozess-Herkunft (Parent-Child-Chain)

**Splunk:**
```spl
index=windows host="<HOST>" EventCode=1
| where match(Image, "(?i)<SUSPICIOUS_PROCESS>")
| table _time, host, Image, ParentImage, CommandLine, ProcessId, ParentProcessId
| sort _time
```

**Google SecOps:**
```
principal.hostname = "<HOST>" AND target.process.file.full_path ~ "<SUSPICIOUS_PROCESS>" AND metadata.event_type = "PROCESS_LAUNCH"
```

---

### Schritt 2.4 — Payload-Analyse: Welches C2-Framework?

#### Cobalt Strike Indikatoren
```spl
index=windows host="<HOST>"
| where match(CommandLine, "(?i)(\-EncodedCommand|\-nop \-w hidden|IEX|Invoke-Expression|Net\.WebClient|DownloadString)") OR match(Image, "(?i)rundll32|regsvr32|mshta")
| table _time, host, Image, CommandLine, ParentImage
```

#### Metasploit Indikatoren
```spl
index=windows host="<HOST>" EventCode=3
| where DestinationPort IN (4444,5555,8443,1234) AND NOT match(DestinationIp, "^(10\.|192\.168\.|172\.)")
| table _time, host, Image, DestinationIp, DestinationPort
```

#### Sliver/Havoc Indikatoren
```spl
index=windows host="<HOST>" EventCode=3
| where DestinationPort IN (31337,43443,8080,8888) AND NOT match(DestinationIp, "^(10\.|192\.168\.|172\.)")
| table _time, host, Image, DestinationIp, DestinationPort
```

---

## Phase 3 — Scope-Analyse (Wer ist noch betroffen?)

### Schritt 3.1 — Alle internen Hosts die den IOC kontaktierten

**Splunk:**
```spl
index=windows EventCode=3 (DestinationIp="<IOC_IP>" OR DestinationHostname="<IOC_DOMAIN>")
| stats count first(_time) as first_contact last(_time) as last_contact by host, Image
| sort -count
| eval first_contact=strftime(first_contact,"%Y-%m-%d %H:%M"), last_contact=strftime(last_contact,"%Y-%m-%d %H:%M")
```

**QRadar:**
```sql
SELECT sourceip AS Host, COUNT(*) AS Verbindungen,
  MIN(devicetime) AS Erste_Verbindung,
  MAX(devicetime) AS Letzte_Verbindung
FROM events
WHERE destinationip = '<IOC_IP>'
GROUP BY sourceip
LAST 10080 MINUTES
```

---

### Schritt 3.2 — Zeitraum der ersten C2-Kommunikation (Patient Zero)

**Splunk:**
```spl
index=windows EventCode=3 (DestinationIp="<IOC_IP>" OR DestinationHostname="<IOC_DOMAIN>")
| stats min(_time) as first_contact by host
| sort first_contact
| eval first_contact=strftime(first_contact,"%Y-%m-%d %H:%M:%S")
```

---

### Schritt 3.3 — Persistence auf betroffenen Hosts?

**Splunk:**
```spl
index=windows host="<HOST>" EventCode IN (4698,13,7045)
| table _time, EventCode, Image, TargetObject, Details, ImagePath
| sort _time
```

**Wazuh:**
```kql
agent.name: "<HOST>" AND data.win.system.eventID: ("4698" OR "7045") AND rule.level >= 8
```

---

## Phase 4 — DNS-Tunnel-Analyse

### Schritt 4.1 — DNS-TXT-Queries mit langen Subdomains

**Splunk:**
```spl
index=windows EventCode=22
| rex field=QueryName "(?P<subdomain>[^.]{20,})\."
| where isnotnull(subdomain) AND len(subdomain) > 20
| stats count values(host) as hosts by QueryName, subdomain
| sort -count
```

### Schritt 4.2 — Hohe Anzahl an Subdomains einer Domain (DNS-Exfil)

**Splunk:**
```spl
index=windows EventCode=22
| rex field=QueryName "(?:[^.]+\.)*(?P<root>[^.]+\.[^.]+)$"
| bin _time span=5m
| stats dc(QueryName) as subdomains by _time, host, root
| where subdomains > 30
| sort -subdomains
```

---

## Phase 5 — Attributierung

### C2-Framework-Erkennungs-Matrix

| Indikator | Framework | Confidence |
|---|---|---|
| Port 50050 + Zertifikat-Fingerprint | Cobalt Strike Teamserver | HOCH |
| Default Malleable-Profile HTTP-Header | Cobalt Strike | HOCH |
| Port 4444/5555 + Meterpreter | Metasploit | MITTEL |
| Port 31337/43443 + TLS GRPC | Sliver | MITTEL |
| Port 40056 + Havoc-Daemon | Havoc C2 | MITTEL |
| DNS-Subdomain >20 Zeichen + TXT | DNS-Tunnel (dnscat2/iodine) | HOCH |
| Named Pipe `\\.\pipe\MSSE-*` | Cobalt Strike | HOCH |
| Named Pipe `\\.\pipe\postex_*` | Cobalt Strike | HOCH |

**Splunk — Named Pipes prüfen:**
```spl
index=windows EventCode=17 OR EventCode=18
| where match(PipeName, "(?i)(MSSE-|postex_|msagent_|mojo\.|chrome\.|status_|SearchTextHarvester)")
| table _time, host, Image, PipeName, EventCode
```

---

## Phase 6 — Eindämmung

### Schritt 6.1 — Firewall-Regeln für IOC-IPs

```
Maßnahme: Ausgehende Verbindungen zu <IOC_IP> blockieren
Scope: Alle internen Hosts
Priorität: SOFORT
Tool: Firewall-Konsole / EDR-Policy / NDR-Block
```

### Schritt 6.2 — DNS-Sinkholing für C2-Domain

```
Maßnahme: <IOC_DOMAIN> auf internen DNS-Sinkhole umleiten
Scope: Alle DNS-Resolver intern
Zweck: Alle Hosts die noch beaconing tun, identifizieren
```

### Schritt 6.3 — Host-Isolation nach Bestätigung

**Isolation-Trigger:**
- Beaconing-Stdev < 10s (stark rhythmisch)
- Prozess ohne signierten Publisher kommuniziert nach extern
- Named Pipe mit C2-Signatur
- Zweite Verbindung nach Sinkholing

---

## Checkliste

```
□ IOC (IP/Domain/Hash) im Environment gesucht
□ Betroffene Hosts kartiert
□ Patient Zero und Zeitraum identifiziert
□ Beaconing-Intervall gemessen und bewertet
□ C2-Framework attributiert (wenn möglich)
□ Persistence auf betroffenen Hosts geprüft
□ DNS-Tunnel-Analyse durchgeführt
□ Firewall-IOC-Block gesetzt
□ DNS-Sinkhole konfiguriert
□ Betroffene Hosts isoliert
□ Vollständige IOC-Liste extrahiert (für Threat Intel)
□ Incident-Ticket dokumentiert
```

---

*HuntingThreats Enterprise Hunt Pack · Playbook PB-003 · v1.0*
