# Rule Index

**1029 detection rules** — v0.2.0 — generated `2026-06-07T15:52:31Z`

Use your browser's search (`Ctrl+F` / `Cmd+F`) to filter by rule ID,
name, pack, technique, or severity. For programmatic access, use
[`docs/data/rules.json`](https://github.com/cerberus8484/SIEM-Rules/blob/main/docs/data/rules.json).

---

## All Rules

| ID | Name | Pack | Platform | Severity | Conf | Technique |
|---|---|---|---|---|---|---|
| `SP-730001` | Backup-Job deaktiviert oder gelöscht | Backup / Resilience | splunk | **CRIT** | 88 | `T1490` |
| `SP-730003` | Backup-Repository gelöscht | Backup / Resilience | splunk | **CRIT** | 88 | `T1490` |
| `SP-730004` | Immutable / WORM-Modus deaktiviert (AWS S3 | Backup / Resilience | splunk | **CRIT** | 90 | `T1562` |
| `SP-730005` | Massenhaftes Löschen von Snapshots | Backup / Resilience | splunk | **CRIT** | 92 | `T1490` |
| `SP-730006` | Backup-Agent-Prozess terminiert | Backup / Resilience | splunk | **CRIT** | 92 | `T1489` |
| `SP-730008` | Azure Backup Recovery Services Vault gelöscht | Backup / Resilience | splunk | **CRIT** | 92 | `T1490` |
| `SP-730009` | GCP Backup Plan gelöscht oder deaktiviert | Backup / Resilience | splunk | **CRIT** | 90 | `T1490` |
| `SP-730010` | Ransomware Prep Chain: VSS + Backup-Kill + Service-Stop | Backup / Resilience | splunk | **CRIT** | 95 | `T1490` |
| `SP-730014` | Veeam Backup Repository Immutable Mode deaktiviert | Backup / Resilience | splunk | **CRIT** | 90 | `T1562` |
| `SP-730017` | Backup Encryption Key gelöscht (AWS KMS | Backup / Resilience | splunk | **CRIT** | 90 | `T1485` |
| `SP-730020` | Backup + Ransomware Frühindikator: Backup-Kill + Dat... | Backup / Resilience | splunk | **CRIT** | 95 | `T1486` |
| `SP-730002` | Backup Retention Policy drastisch reduziert | Backup / Resilience | splunk | HIGH | 80 | `T1490` |
| `SP-730007` | Backup Storage Credentials geändert | Backup / Resilience | splunk | HIGH | 80 | `T1552` |
| `SP-730011` | Backup Admin Login außerhalb Wartungsfenster | Backup / Resilience | splunk | HIGH | 78 | `T1078` |
| `SP-730012` | Backup Destination zu externem Endpunkt geändert | Backup / Resilience | splunk | HIGH | 80 | `T1537` |
| `SP-730013` | Backup-Datei direkt gelesen/kopiert von Nicht-Backup... | Backup / Resilience | splunk | HIGH | 82 | `T1552` |
| `SP-730015` | Backup Notification / Alert deaktiviert | Backup / Resilience | splunk | HIGH | 75 | `T1562` |
| `SP-730016` | Off-Site Replikation gestoppt oder pausiert | Backup / Resilience | splunk | HIGH | 80 | `T1490` |
| `SP-730018` | Restic / Borg Backup-Konfiguration geändert | Backup / Resilience | splunk | HIGH | 82 | `T1490` |
| `SP-730019` | S3 Bucket Versioning deaktiviert (Backup-Bucket | Backup / Resilience | splunk | HIGH | 85 | `T1562` |
| | | | | | | |
| `SP-104008` | Confidence: HIGH | Command & Control | splunk | **CRIT** | 90 | `T1071.001` |
| `SP-104020` | Confidence: HIGH | Command & Control | splunk | **CRIT** | 90 | `T1008` |
| `SP-104034` | Confidence: HIGH | Command & Control | splunk | **CRIT** | 90 | `T1090.003` |
| `SP-104002` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1095` |
| `SP-104003` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1095` |
| `SP-104004` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1571` |
| `SP-104005` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1071.004` |
| `SP-104006` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1071.004` |
| `SP-104007` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1571` |
| `SP-104009` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1071.001` |
| `SP-104010` | Confidence: MEDIUM | Command & Control | splunk | HIGH | 62 | `T1001.003` |
| `SP-104011` | Confidence: MEDIUM | Command & Control | splunk | HIGH | 62 | `T1071.004` |
| `SP-104012` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1095` |
| `SP-104013` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1071.001` |
| `SP-104014` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1573.002` |
| `SP-104015` | Confidence: MEDIUM | Command & Control | splunk | HIGH | 62 | `T1572` |
| `SP-104016` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1090.001` |
| `SP-104017` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1090.002` |
| `SP-104018` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1095` |
| `SP-104019` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1071.001` |
| `SP-104022` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1095` |
| `SP-104023` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1071.001` |
| `SP-104025` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1571` |
| `SP-104026` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1071.003` |
| `SP-104027` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1071.002` |
| `SP-104029` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1071.004` |
| `SP-104030` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1573.001` |
| `SP-104031` | Confidence: HIGH | Command & Control | splunk | HIGH | 78 | `T1071.001` |
| `SP-104032` | Confidence: MEDIUM | Command & Control | splunk | HIGH | 62 | `T1219` |
| `SP-104033` | Confidence: MEDIUM | Command & Control | splunk | HIGH | 62 | `T1071.001` |
| `SP-104035` | Confidence: MEDIUM | Command & Control | splunk | HIGH | 62 | `T1071.004` |
| `SP-104001` | Confidence: MEDIUM | Command & Control | splunk | MED | 62 | `T1071.001` |
| `SP-104021` | Confidence: MEDIUM | Command & Control | splunk | MED | 62 | `T1071.001` |
| `SP-104024` | Confidence: MEDIUM | Command & Control | splunk | MED | 62 | `T1571` |
| `SP-104028` | Confidence: MEDIUM | Command & Control | splunk | MED | 62 | `T1572` |
| | | | | | | |
| `SP-200001` | Root Account Console Login — kein MFA | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 98 | `T1078.004` |
| `SP-200004` | CloudTrail Logging deaktiviert (Blind Spot | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 97 | `T1562.008` |
| `SP-200005` | GuardDuty Detector gelöscht | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 97 | `T1562.001` |
| `SP-200006` | Neuer IAM Admin User erstellt | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 90 | `T1136.003` |
| `SP-200007` | AdministratorAccess Policy an Rolle/User angehängt | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 95 | `T1098` |
| `SP-200008` | Access Key für Root Account erstellt | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 99 | `T1078.004` |
| `SP-200015` | KMS Key für Löschung vorgemerkt | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 90 | `T1485` |
| `SP-200019` | AWS Config Recorder gestoppt | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 97 | `T1562.001` |
| `SP-200024` | RDS Snapshot öffentlich gemacht | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 92 | `T1537` |
| `SP-200025` | IAM Inline Policy mit Wildcard-Permissions | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 88 | `T1098` |
| `SP-200034` | Organizations Service Control Policy entfernt | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 90 | `T1562` |
| `SP-200035` | Vollständige Impact-Chain: GuardDuty + Config + Clou... | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 95 | `T1562` |
| `SP-201001` | Global Administrator Rolle vergeben | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 97 | `T1098.003` |
| `SP-201002` | MFA-Requirement für Nutzer deaktiviert | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 95 | `T1556` |
| `SP-201006` | Passwort-Spray — viele Fehlschläge von einer IP | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 90 | `T1110.003` |
| `SP-201015` | Azure AD Connect / Sync Konfiguration geändert | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 90 | `T1556.007` |
| `SP-201020` | High-Privilege Roles direkt (nicht via PIM) zugewiesen | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 95 | `T1098.003` |
| `SP-202002` | Mailbox auf externe Adresse weitergeleitet (Transpor... | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 95 | `T1048` |
| `SP-202006` | Admin-Rolle einem User zugewiesen | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 97 | `T1098.003` |
| `SP-202012` | Safe Attachments / Safe Links deaktiviert | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 92 | `T1562` |
| `SP-203003` | Owner/Editor Rolle an Nutzer oder SA vergeben | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 92 | `T1098` |
| `SP-203005` | Cloud Audit Log deaktiviert | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 88 | `T1562.008` |
| `SP-203011` | Cloud KMS Key gelöscht oder zerstört | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 95 | `T1485` |
| `SP-203013` | Organisation-Policy Constraint entfernt | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 90 | `T1562` |
| `SP-203020` | Vollständige Impact-Chain: Logging + Firewall + IAM ... | Cloud (AWS/Azure/M365/GCP) | splunk | **CRIT** | 95 | `T1562  +1` |
| `SP-200002` | Console Login ohne MFA — IAM User | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 85 | `T1078.004` |
| `SP-200003` | Brute Force Console Login — mehr als 10 Fehlschläge ... | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 80 | `T1110.001` |
| `SP-200010` | AssumeRole von unbekanntem externem Account | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 75 | `T1548` |
| `SP-200011` | S3 Bucket ACL auf Public gesetzt | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 90 | `T1537` |
| `SP-200012` | S3 Bucket Public Access Block deaktiviert | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 88 | `T1537` |
| `SP-200013` | Security Group Ingress 0.0.0.0/0 geöffnet | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 85 | `T1562.007` |
| `SP-200014` | VPC Flow Logs deaktiviert | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 95 | `T1562.008` |
| `SP-200016` | Secrets Manager Secret ausgelesen | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 80 | `T1552.001` |
| `SP-200017` | IAM Passwort-Policy abgeschwächt | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 90 | `T1556` |
| `SP-200018` | MFA-Gerät gelöscht oder deaktiviert | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 92 | `T1556` |
| `SP-200020` | CloudWatch Alarm gelöscht | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 85 | `T1562.001` |
| `SP-200023` | SSM SendCommand — Remote Code Execution | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 75 | `T1651` |
| `SP-200026` | API-Calls von Tor-Exit-Node | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 85 | `T1090.003` |
| `SP-200027` | Massenhafte API-Aufrufe — Enumeration (>100 Calls in... | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 82 | `T1580` |
| `SP-200030` | EC2 Snapshot öffentlich gemacht | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 90 | `T1537` |
| `SP-200031` | Route53 Hosted Zone Record geändert (DNS Hijack | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 80 | `T1584.002` |
| `SP-200032` | WAF-Regeln gelöscht oder deaktiviert | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 88 | `T1562` |
| `SP-200033` | EKS Cluster-Konfiguration geändert | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 78 | `T1098` |
| `SP-201003` | Conditional Access Policy geändert oder gelöscht | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 92 | `T1556` |
| `SP-201005` | OAuth App-Consent von Nutzer gewährt (Admin-Scope | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 80 | `T1528` |
| `SP-201007` | Unmögliche Reise — Login von zwei Standorten in kurz... | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 75 | `T1078.004` |
| `SP-201008` | Token-Diebstahl — Sign-in ohne bekanntes Gerät mit R... | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 78 | `T1528` |
| `SP-201009` | Privileged Identity Management (PIM) Aktivierung auß... | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 72 | `T1098.003` |
| `SP-201010` | Neuer Federated Identity Credential erstellt (Backdoor | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 82 | `T1550.001` |
| `SP-201012` | Massenhafte Passwort-Resets durch einen Admin | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 80 | `T1531` |
| `SP-201014` | App-Berechtigung mit hohem Scope gewährt (app2app | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 82 | `T1528` |
| `SP-201016` | Login von Anonymous/Tor-IP laut Azure Risky Sign-in | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 85 | `T1078.004` |
| `SP-201018` | Named Location (Whitelist IP) geändert | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 85 | `T1562` |
| `SP-202001` | Mailbox Forwarding Rule erstellt (T1114.003 | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 92 | `T1114.003` |
| `SP-202003` | Massendownload aus SharePoint / OneDrive | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 82 | `T1039` |
| `SP-202004` | External Sharing für ganze Site aktiviert | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 85 | `T1537` |
| `SP-202005` | OAuth App mit hohem Scope genehmigt | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 88 | `T1528` |
| `SP-202007` | Massenhafte E-Mail-Löschungen | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 80 | `T1070.008` |
| `SP-202011` | DLP-Richtlinie deaktiviert oder überschrieben | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 90 | `T1562` |
| `SP-202015` | Ungewöhnliche Exchange Web Services Aktivität (EWS API | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 83 | `T1114.002` |
| `SP-202016` | Power Automate Flow mit externen Webhook erstellt | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 80 | `T1048` |
| `SP-202017` | Hohe Anzahl Datei-Zugriffe kurz vor Off-Boarding (Da... | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 75 | `T1039` |
| `SP-202018` | Teams Nachricht mit verdächtigem Link versendet | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 78 | `T1566.002` |
| `SP-202019` | Audit-Logging für Mailbox deaktiviert | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 92 | `T1562.008` |
| `SP-203001` | Service Account Key erstellt (Persistenz | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 85 | `T1098` |
| `SP-203002` | IAM Policy Binding geändert (Rolle zugeteilt | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 80 | `T1098` |
| `SP-203004` | Cloud Logging Sink gelöscht oder deaktiviert | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 90 | `T1562.008` |
| `SP-203006` | GCS Bucket Public gemacht | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 92 | `T1537` |
| `SP-203008` | Compute Engine Instance mit SA-Scope erstellt | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 72 | `T1098` |
| `SP-203009` | SSH Public Key in Compute Engine Metadaten gesetzt | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 88 | `T1098.004` |
| `SP-203010` | Firewall-Regel für alle Quellen (0.0.0.0/0) erstellt | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 85 | `T1562.007` |
| `SP-203012` | Service Account Impersonation | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 80 | `T1548` |
| `SP-203014` | Massenhafte List/Get API-Calls — Enumeration | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 80 | `T1580` |
| `SP-203015` | GCS Bucket Versioning deaktiviert (Ransomware Vorber... | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 80 | `T1490` |
| `SP-203016` | API-Call von externem Angreifer-IP (Threat Intel | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 85 | `T1078` |
| `SP-203018` | Pub/Sub Subscription mit Push auf externe URL | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 80 | `T1048` |
| `SP-203019` | Secret Manager Secret ausgelesen | Cloud (AWS/Azure/M365/GCP) | splunk | HIGH | 78 | `T1552.001` |
| `SP-200009` | Neuer Access Key erstellt (Persistenz | Cloud (AWS/Azure/M365/GCP) | splunk | MED | 70 | `T1098` |
| `SP-200021` | Lambda-Funktion erstellt oder Code aktualisiert | Cloud (AWS/Azure/M365/GCP) | splunk | MED | 65 | `T1648` |
| `SP-200022` | EC2 UserData-Script bei Launch (Code Execution | Cloud (AWS/Azure/M365/GCP) | splunk | MED | 60 | `T1059` |
| `SP-200029` | IAM User-Erstellung OHNE sofortige MFA-Aktivierung | Cloud (AWS/Azure/M365/GCP) | splunk | MED | 72 | `T1136.003` |
| `SP-201004` | Neuer Service Principal / App Registration erstellt | Cloud (AWS/Azure/M365/GCP) | splunk | MED | 70 | `T1136.003` |
| `SP-201011` | Nutzer-Account deaktiviert dann sofort reaktiviert (... | Cloud (AWS/Azure/M365/GCP) | splunk | MED | 65 | `T1070` |
| `SP-201013` | Guest User hinzugefügt (External Access | Cloud (AWS/Azure/M365/GCP) | splunk | MED | 60 | `T1078.004` |
| `SP-201017` | Device-Join in Azure AD von unbekanntem System | Cloud (AWS/Azure/M365/GCP) | splunk | MED | 60 | `T1098` |
| `SP-201019` | Sign-in in Legacy-Auth-Protokoll (SMTP Auth, IMAP | Cloud (AWS/Azure/M365/GCP) | splunk | MED | 68 | `T1078` |
| `SP-202008` | Neue Postfach-Delegierung gesetzt | Cloud (AWS/Azure/M365/GCP) | splunk | MED | 70 | `T1098` |
| `SP-202009` | E-Mail-Suche über alle Postfächer (Compliance Search | Cloud (AWS/Azure/M365/GCP) | splunk | MED | 65 | `T1114` |
| `SP-202010` | Teams-Kanal mit externem Gast erstellt | Cloud (AWS/Azure/M365/GCP) | splunk | MED | 65 | `T1566` |
| `SP-202013` | Multi-Geo Einstellungen geändert (Datenstandort | Cloud (AWS/Azure/M365/GCP) | splunk | MED | 60 | `T1537` |
| `SP-202014` | Audit-Log-Suche durch Non-Admin User | Cloud (AWS/Azure/M365/GCP) | splunk | MED | 65 | `T1526` |
| `SP-202020` | Login von unbekanntem Land laut AAD Sign-in Risk | Cloud (AWS/Azure/M365/GCP) | splunk | MED | 68 | `T1078.004` |
| `SP-203007` | Cloud Function erstellt oder aktualisiert | Cloud (AWS/Azure/M365/GCP) | splunk | MED | 65 | `T1648` |
| `SP-203017` | Compute Instance mit externem IP gestartet | Cloud (AWS/Azure/M365/GCP) | splunk | MED | 65 | `T1095` |
| `SP-200028` | GetCallerIdentity — Recon-Abfrage | Cloud (AWS/Azure/M365/GCP) | splunk | LOW | 55 | `T1526` |
| | | | | | | |
| `SP-710001` | Privileged Pod erstellt | Container / Kubernetes | splunk | **CRIT** | 92 | `T1611` |
| `SP-710002` | hostPath Mount auf sensitiven Pfad (/, /etc, docker.... | Container / Kubernetes | splunk | **CRIT** | 92 | `T1611` |
| `SP-710004` | Neuer ClusterRoleBinding mit cluster-admin | Container / Kubernetes | splunk | **CRIT** | 92 | `T1548` |
| `SP-710005` | RBAC-Rolle mit Wildcard-Verben und Ressourcen | Container / Kubernetes | splunk | **CRIT** | 90 | `T1548` |
| `SP-710008` | Pod mit hostNetwork oder hostPID | Container / Kubernetes | splunk | **CRIT** | 92 | `T1611` |
| `SP-710009` | Deployment im kube-system Namespace geändert | Container / Kubernetes | splunk | **CRIT** | 88 | `T1543` |
| `SP-710010` | Admission Controller deaktiviert oder gelöscht | Container / Kubernetes | splunk | **CRIT** | 90 | `T1562` |
| `SP-710015` | Kubernetes Audit-Log deaktiviert oder Policy geändert | Container / Kubernetes | splunk | **CRIT** | 90 | `T1562.008` |
| `SP-710018` | Container-Escape via nsenter oder chroot (Host-Sicht | Container / Kubernetes | splunk | **CRIT** | 88 | `T1611` |
| `SP-710003` | kubectl exec in Produktions-Namespace | Container / Kubernetes | splunk | HIGH | 88 | `T1609` |
| `SP-710006` | Secret gelesen von unerwartetem ServiceAccount | Container / Kubernetes | splunk | HIGH | 85 | `T1552.007` |
| `SP-710007` | Container Image von unbekannter Registry | Container / Kubernetes | splunk | HIGH | 80 | `T1610` |
| `SP-710011` | Kubernetes API-Server von Pod aus aufgerufen | Container / Kubernetes | splunk | HIGH | 82 | `T1613` |
| `SP-710012` | NodePort / LoadBalancer für sensitive App erstellt | Container / Kubernetes | splunk | HIGH | 78 | `T1048` |
| `SP-710013` | ServiceAccount Token Auto-Mount in kritischem Pod | Container / Kubernetes | splunk | HIGH | 78 | `T1552.007` |
| `SP-710014` | Container läuft als Root (uid=0 | Container / Kubernetes | splunk | HIGH | 82 | `T1611` |
| `SP-710016` | InitContainer mit privilegierten Capabilities | Container / Kubernetes | splunk | HIGH | 85 | `T1611` |
| `SP-710019` | Crypto-Mining Verdacht (Mining Pool Domains | Container / Kubernetes | splunk | HIGH | 88 | `T1496` |
| `SP-710020` | Kubernetes Service-Account Token manuell gelesen | Container / Kubernetes | splunk | HIGH | 88 | `T1552.007` |
| `SP-710017` | Image mit 'latest'-Tag aus unbekannter Registry | Container / Kubernetes | splunk | MED | 72 | `T1610` |
| | | | | | | |
| `SP-810001` | ATO Kill Chain: Impossible Travel → MFA-Änderung → F... | Correlation / Multi-Stage | splunk | **CRIT** | 92 | `T1078 +2` |
| `SP-810002` | Cloud PrivEsc Chain: IAM Policy Change → AccessKey →... | Correlation / Multi-Stage | splunk | **CRIT** | 90 | `T1098.003 +2` |
| `SP-810003` | Ransomware Prep Chain: Backup-Kill → Admin Share → M... | Correlation / Multi-Stage | splunk | **CRIT** | 95 | `T1490 +2` |
| `SP-810007` | Kubernetes Attack Chain: Secret Read → Privileged Po... | Correlation / Multi-Stage | splunk | **CRIT** | 88 | `T1552.007 +2` |
| `SP-810008` | Phishing → Macro → Payload Drop Chain (1h | Correlation / Multi-Stage | splunk | **CRIT** | 88 | `T1566.001 +2` |
| `SP-810010` | Credential Theft → Lateral Movement → DCSync Chain (2h | Correlation / Multi-Stage | splunk | **CRIT** | 90 | `T1003.001 +2` |
| `SP-810011` | Defense Evasion Trifecta: AV-Stop + Log-Clear + FW-R... | Correlation / Multi-Stage | splunk | **CRIT** | 92 | `T1562.001 +2` |
| `SP-810014` | Cloud Identity Attack Chain: App Reg → Consent → Tok... | Correlation / Multi-Stage | splunk | **CRIT** | 90 | `T1550.001 +2` |
| `SP-810015` | Hypervisor Attack Chain: Admin Login → SSH Enabled →... | Correlation / Multi-Stage | splunk | **CRIT** | 88 | `T1133 +2` |
| `SP-810018` | Container Escape Chain: Privileged Pod → docker.sock... | Correlation / Multi-Stage | splunk | **CRIT** | 90 | `T1611 +1` |
| `SP-810019` | Email-to-Compromise Chain: Phishing → OAuth Consent ... | Correlation / Multi-Stage | splunk | **CRIT** | 90 | `T1566 +3` |
| `SP-810004` | Insider Exfil Chain: After-Hours Login → Mass Downlo... | Correlation / Multi-Stage | splunk | HIGH | 85 | `T1078 +2` |
| `SP-810005` | C2 Beacon Chain: New Process → DNS Beaconing → Proxy... | Correlation / Multi-Stage | splunk | HIGH | 85 | `T1071.001 +1` |
| `SP-810006` | Linux Persistence Chain: SSH Login → authorized_keys... | Correlation / Multi-Stage | splunk | HIGH | 85 | `T1021.004 +2` |
| `SP-810009` | Lateral Movement Chain: New Service + PsExec + SMB A... | Correlation / Multi-Stage | splunk | HIGH | 88 | `T1021.002 +1` |
| `SP-810012` | Supply Chain Attack Chain: Build Modified → Artifact... | Correlation / Multi-Stage | splunk | HIGH | 82 | `T1195.002 +1` |
| `SP-810013` | Data Discovery → Staging → Exfil Chain (4h | Correlation / Multi-Stage | splunk | HIGH | 85 | `T1083 +2` |
| `SP-810016` | Low-and-Slow Passwort Spray (verteilt über 24h, <5 F... | Correlation / Multi-Stage | splunk | HIGH | 85 | `T1110.003` |
| `SP-810017` | Service Account Abuse Chain: SVC Login → Admin Escal... | Correlation / Multi-Stage | splunk | HIGH | 85 | `T1078.002 +2` |
| `SP-810020` | Full Kill Chain Scorer — Phasen aggregieren zu Risik... | Correlation / Multi-Stage | splunk |  | 85 | `T1059 +3` |
| | | | | | | |
| `SP-103001` | Confidence: HIGH | Windows Credentials | splunk | **CRIT** | 81 | `T1003.001` |
| `SP-103002` | Confidence: HIGH | Windows Credentials | splunk | **CRIT** | 81 | `T1003.001` |
| `SP-103003` | Confidence: HIGH | Windows Credentials | splunk | **CRIT** | 81 | `T1003.001` |
| `SP-103004` | Confidence: HIGH | Windows Credentials | splunk | **CRIT** | 81 | `T1003.001` |
| `SP-103005` | Confidence: HIGH | Windows Credentials | splunk | **CRIT** | 81 | `T1003.001` |
| `SP-103006` | Confidence: HIGH | Windows Credentials | splunk | **CRIT** | 81 | `T1003.002` |
| `SP-103007` | Confidence: HIGH | Windows Credentials | splunk | **CRIT** | 81 | `T1003.003` |
| `SP-103008` | Confidence: HIGH | Windows Credentials | splunk | **CRIT** | 81 | `T1003.001` |
| `SP-103013` | Confidence: HIGH | Windows Credentials | splunk | **CRIT** | 81 | `T1003.004` |
| `SP-103014` | Confidence: HIGH | Windows Credentials | splunk | **CRIT** | 81 | `T1003.001` |
| `SP-103017` | Confidence: HIGH | Windows Credentials | splunk | **CRIT** | 81 | `T1003.001` |
| `SP-103018` | Confidence: HIGH | Windows Credentials | splunk | **CRIT** | 81 | `T1003.001` |
| `SP-103020` | Confidence: HIGH | Windows Credentials | splunk | **CRIT** | 81 | `T1003.001` |
| `SP-103021` | Confidence: HIGH | Windows Credentials | splunk | **CRIT** | 81 | `T1003.006` |
| `SP-103028` | Confidence: HIGH | Windows Credentials | splunk | **CRIT** | 81 | `T1003.001` |
| `SP-103032` | Confidence: HIGH | Windows Credentials | splunk | **CRIT** | 81 | `T1003.001` |
| `SP-103033` | Confidence: HIGH | Windows Credentials | splunk | **CRIT** | 81 | `T1003.002` |
| `SP-103034` | Confidence: HIGH | Windows Credentials | splunk | **CRIT** | 81 | `T1003.001` |
| `SP-103035` | Confidence: HIGH | Windows Credentials | splunk | **CRIT** | 81 | `T1556.001` |
| `SP-103009` | Confidence: HIGH | Windows Credentials | splunk | HIGH | 81 | `T1003.001` |
| `SP-103010` | Confidence: HIGH | Windows Credentials | splunk | HIGH | 81 | `T1555.003` |
| `SP-103011` | Confidence: HIGH | Windows Credentials | splunk | HIGH | 81 | `T1558.003` |
| `SP-103012` | Confidence: HIGH | Windows Credentials | splunk | HIGH | 81 | `T1558.004` |
| `SP-103015` | Confidence: HIGH | Windows Credentials | splunk | HIGH | 81 | `T1110.001` |
| `SP-103016` | Confidence: HIGH | Windows Credentials | splunk | HIGH | 81 | `T1110.003` |
| `SP-103019` | Confidence: HIGH | Windows Credentials | splunk | HIGH | 81 | `T1003.005` |
| `SP-103022` | Confidence: HIGH | Windows Credentials | splunk | HIGH | 81 | `T1056.001` |
| `SP-103023` | Confidence: HIGH | Windows Credentials | splunk | HIGH | 81 | `T1003.001` |
| `SP-103025` | Confidence: HIGH | Windows Credentials | splunk | HIGH | 81 | `T1552.002` |
| `SP-103026` | Confidence: MEDIUM | Windows Credentials | splunk | HIGH | 65 | `T1558.001` |
| `SP-103027` | Confidence: MEDIUM | Windows Credentials | splunk | HIGH | 65 | `T1558.002` |
| `SP-103029` | Confidence: MEDIUM | Windows Credentials | splunk | HIGH | 65 | `T1003.001` |
| `SP-103030` | Confidence: HIGH | Windows Credentials | splunk | HIGH | 81 | `T1110.001` |
| `SP-103031` | Confidence: HIGH | Windows Credentials | splunk | HIGH | 81 | `T1555.003` |
| `SP-103024` | Confidence: MEDIUM | Windows Credentials | splunk | MED | 65 | `T1552.001` |
| | | | | | | |
| `SP-760002` | Datenbank-Dump Befehl (mysqldump / pg_dump / expdp | Database | splunk | **CRIT** | 88 | `T1213` |
| `SP-760003` | Neuer Datenbank-Admin-Benutzer erstellt | Database | splunk | **CRIT** | 88 | `T1136` |
| `SP-760005` | xp_cmdshell aktiviert (MSSQL Remote Code Execution | Database | splunk | **CRIT** | 95 | `T1059` |
| `SP-760007` | Datenbank-Audit-Log deaktiviert | Database | splunk | **CRIT** | 90 | `T1562.008` |
| `SP-760011` | Backup / Export zu externem Netzwerkpfad | Database | splunk | **CRIT** | 88 | `T1537` |
| `SP-760012` | Datenbank-User Berechtigung eskaliert | Database | splunk | **CRIT** | 90 | `T1078` |
| `SP-760014` | SQL Injection Indikator in Query-Log | Database | splunk | **CRIT** | 88 | `T1190` |
| `SP-760019` | Verschlüsselte Spalte / TDE deaktiviert | Database | splunk | **CRIT** | 88 | `T1562` |
| `SP-760020` | Datenbank-Replikation gestoppt oder geändert | Database | splunk | **CRIT** | 88 | `T1485` |
| `SP-760001` | Massen-SELECT (>10.000 Zeilen in einer Query | Database | splunk | HIGH | 80 | `T1213` |
| `SP-760004` | Datenbank-Login außerhalb Wartungsfenster | Database | splunk | HIGH | 78 | `T1078` |
| `SP-760006` | Linked Server erstellt (MSSQL Lateral Movement Pfad | Database | splunk | HIGH | 88 | `T1021` |
| `SP-760008` | Sensitive Tabelle erstmals von diesem User abgefragt | Database | splunk | HIGH | 78 | `T1213` |
| `SP-760009` | Schema-Enumeration (information_schema / sys.tables ... | Database | splunk | HIGH | 82 | `T1213` |
| `SP-760010` | Externes Script in Datenbank ausgeführt (R/Python vi... | Database | splunk | HIGH | 88 | `T1059` |
| `SP-760013` | Login Brute Force (>10 Fails in 5 Min | Database | splunk | HIGH | 85 | `T1110.001` |
| `SP-760015` | Datenbank-Verbindung von ungewöhnlichem Host oder App | Database | splunk | HIGH | 78 | `T1078` |
| `SP-760016` | Gespeicherte Prozedur erstellt oder geändert | Database | splunk | HIGH | 78 | `T1505.001` |
| `SP-760017` | SQL Agent Job geändert (MSSQL Persistence | Database | splunk | HIGH | 82 | `T1053.002` |
| `SP-760018` | Row-Level Security deaktiviert | Database | splunk | HIGH | 82 | `T1562` |
| | | | | | | |
| `SP-800001` | Canary File geöffnet (Honeypot-Dokument | Deception / Canary | splunk | **CRIT** | 97 | `T1078` |
| `SP-800002` | Honey Credential genutzt (Fake Passwort aus Passwort... | Deception / Canary | splunk | **CRIT** | 98 | `T1078` |
| `SP-800003` | AWS Honey Token Access Key genutzt | Deception / Canary | splunk | **CRIT** | 98 | `T1552.005` |
| `SP-800004` | Honeypot Host via RDP kontaktiert | Deception / Canary | splunk | **CRIT** | 97 | `T1021.001` |
| `SP-800005` | Honeypot SSH Login Versuch | Deception / Canary | splunk | **CRIT** | 97 | `T1021.004` |
| `SP-800006` | Fake Admin Share zugegriffen (\\SERVER\ADMIN$ Honeypot | Deception / Canary | splunk | **CRIT** | 97 | `T1021.002` |
| `SP-800007` | Canary DNS Record abgefragt | Deception / Canary | splunk | **CRIT** | 97 | `T1071.004` |
| `SP-800008` | Honey API Endpoint aufgerufen | Deception / Canary | splunk | **CRIT** | 97 | `T1190` |
| `SP-800009` | Fake Service-Account genutzt | Deception / Canary | splunk | **CRIT** | 98 | `T1078` |
| `SP-800010` | Canary Datenbank-Tabelle abgefragt | Deception / Canary | splunk | **CRIT** | 97 | `T1213` |
| `SP-800011` | Canary E-Mail-Adresse hat E-Mail erhalten (Spear Phi... | Deception / Canary | splunk | **CRIT** | 97 | `T1566.001` |
| `SP-800012` | Canary Registry-Schlüssel gelesen (Windows Registry ... | Deception / Canary | splunk | **CRIT** | 97 | `T1012` |
| `SP-800013` | Netzwerk-Honeypot Service getriggert (unerwarteter Port | Deception / Canary | splunk | **CRIT** | 97 | `T1046` |
| `SP-800014` | Fake Backup-Datei zugegriffen | Deception / Canary | splunk | **CRIT** | 97 | `T1083` |
| `SP-800015` | Honey Zertifikat Private-Key zugegriffen | Deception / Canary | splunk | **CRIT** | 97 | `T1552.004` |
| | | | | | | |
| `SP-102003` | Confidence: HIGH | Windows Defense Evasion | splunk | **CRIT** | 90 | `T1055.012` |
| `SP-102012` | Confidence: HIGH | Windows Defense Evasion | splunk | **CRIT** | 90 | `T1055.013` |
| `SP-102015` | Confidence: HIGH | Windows Defense Evasion | splunk | **CRIT** | 90 | `T1562.001` |
| `SP-102022` | Confidence: HIGH | Windows Defense Evasion | splunk | **CRIT** | 90 | `T1562.006` |
| `SP-102030` | Confidence: HIGH | Windows Defense Evasion | splunk | **CRIT** | 90 | `T1562.001` |
| `SP-102034` | Confidence: HIGH | Windows Defense Evasion | splunk | **CRIT** | 90 | `T1055.001` |
| `SP-102035` | Confidence: HIGH | Windows Defense Evasion | splunk | **CRIT** | 90 | `T1027` |
| `SP-102001` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1055.001` |
| `SP-102002` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1055.002` |
| `SP-102004` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1036.003` |
| `SP-102005` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1036.005` |
| `SP-102006` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1055.003` |
| `SP-102007` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1562.001` |
| `SP-102008` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1027` |
| `SP-102010` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1562.002` |
| `SP-102011` | Confidence: MEDIUM | Windows Defense Evasion | splunk | HIGH | 62 | `T1027.002` |
| `SP-102013` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1036.004` |
| `SP-102014` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1070.001` |
| `SP-102016` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1027.004` |
| `SP-102017` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1055.008` |
| `SP-102018` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1036.001` |
| `SP-102019` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1562.004` |
| `SP-102020` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1070.006` |
| `SP-102021` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1027.001` |
| `SP-102023` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1055.009` |
| `SP-102024` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1562.001` |
| `SP-102025` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1036.007` |
| `SP-102027` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1218.011` |
| `SP-102028` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1027.005` |
| `SP-102029` | Confidence: MEDIUM | Windows Defense Evasion | splunk | HIGH | 62 | `T1055.015` |
| `SP-102031` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1218.005` |
| `SP-102032` | Confidence: HIGH | Windows Defense Evasion | splunk | HIGH | 78 | `T1070.004` |
| `SP-102009` | Confidence: MEDIUM | Windows Defense Evasion | splunk | MED | 62 | `T1070.004` |
| `SP-102026` | Confidence: HIGH | Windows Defense Evasion | splunk | MED | 78 | `T1070.003` |
| `SP-102033` | Confidence: HIGH | Windows Defense Evasion | splunk | MED | 78 | `T1562.001` |
| | | | | | | |
| `SP-720004` | bash aus (Code Injection Pattern | DevOps / CI-CD | splunk | **CRIT** | 88 | `T1059.004` |
| `SP-720010` | Secret in Build-Log exponiert (Patterns im CI-Output | DevOps / CI-CD | splunk | **CRIT** | 88 | `T1552` |
| `SP-720014` | Release Asset nach Signing ersetzt | DevOps / CI-CD | splunk | **CRIT** | 85 | `T1195.002` |
| `SP-720015` | Pipeline-Job nutzt privilegierten Container | DevOps / CI-CD | splunk | **CRIT** | 88 | `T1611` |
| `SP-720018` | npm/pip Package ähnlich wie bekanntes Paket (Typosqu... | DevOps / CI-CD | splunk | **CRIT** | 82 | `T1195.001` |
| `SP-720001` | GitHub Actions Workflow-Datei geändert | DevOps / CI-CD | splunk | HIGH | 82 | `T1053.005` |
| `SP-720002` | Neuer Deploy-Key zu Repository hinzugefügt | DevOps / CI-CD | splunk | HIGH | 85 | `T1098.001` |
| `SP-720003` | Self-Hosted Runner registriert | DevOps / CI-CD | splunk | HIGH | 85 | `T1053` |
| `SP-720005` | Repository Secret erstellt oder aktualisiert | DevOps / CI-CD | splunk | HIGH | 80 | `T1552` |
| `SP-720007` | Branch Protection Rule entfernt | DevOps / CI-CD | splunk | HIGH | 88 | `T1562` |
| `SP-720008` | Force Push auf geschützten Branch | DevOps / CI-CD | splunk | HIGH | 85 | `T1070` |
| `SP-720009` | Neuer Admin-Collaborator zu Repo hinzugefügt | DevOps / CI-CD | splunk | HIGH | 82 | `T1136` |
| `SP-720011` | Ungewöhnliche externe Verbindung vom CI-Runner | DevOps / CI-CD | splunk | HIGH | 78 | `T1071` |
| `SP-720013` | GitHub Personal Access Token mit breiten Rechten ers... | DevOps / CI-CD | splunk | HIGH | 80 | `T1552.001` |
| `SP-720019` | Terraform Plan/Apply mit Destroy-Operationen außerha... | DevOps / CI-CD | splunk | HIGH | 78 | `T1485` |
| `SP-720020` | Neues Org-Level Webhook zu nicht-internem Endpunkt | DevOps / CI-CD | splunk | HIGH | 82 | `T1048` |
| `SP-720006` | Dependency-Datei geändert (package.json/requirements... | DevOps / CI-CD | splunk | MED | 65 | `T1195.001` |
| `SP-720012` | Container Image mit 'latest' aus unbekannter Registr... | DevOps / CI-CD | splunk | MED | 65 | `T1610` |
| `SP-720016` | Direkt-Push auf main ohne Pull Request | DevOps / CI-CD | splunk | MED | 72 | `T1070` |
| `SP-720017` | Docker Registry Login von unbekanntem CI-Runner IP | DevOps / CI-CD | splunk | MED | 72 | `T1525` |
| | | | | | | |
| `SP-106021` | Confidence: HIGH | Discovery | splunk | **CRIT** | 85 | `T1069.002` |
| `SP-106031` | Confidence: HIGH | Discovery | splunk | **CRIT** | 85 | `T1082` |
| `SP-106002` | Confidence: HIGH | Discovery | splunk | HIGH | 73 | `T1087.002` |
| `SP-106003` | Confidence: HIGH | Discovery | splunk | HIGH | 73 | `T1069.002` |
| `SP-106004` | Confidence: HIGH | Discovery | splunk | HIGH | 73 | `T1018` |
| `SP-106009` | Confidence: HIGH | Discovery | splunk | HIGH | 73 | `T1069.001` |
| `SP-106011` | Confidence: HIGH | Discovery | splunk | HIGH | 73 | `T1012` |
| `SP-106015` | Confidence: HIGH | Discovery | splunk | HIGH | 73 | `T1087.002` |
| `SP-106016` | Confidence: HIGH | Discovery | splunk | HIGH | 73 | `T1046` |
| `SP-106022` | Confidence: HIGH | Discovery | splunk | HIGH | 73 | `T1087.002` |
| `SP-106024` | Confidence: HIGH | Discovery | splunk | HIGH | 73 | `T1018` |
| `SP-106030` | Confidence: HIGH | Discovery | splunk | HIGH | 73 | `T1087.002` |
| `SP-106033` | Confidence: HIGH | Discovery | splunk | HIGH | 73 | `T1046` |
| `SP-106034` | Confidence: MEDIUM | Discovery | splunk | HIGH | 57 | `T1040` |
| `SP-106035` | Confidence: HIGH | Discovery | splunk | HIGH | 73 | `T1069.002` |
| `SP-106001` | Confidence: HIGH | Discovery | splunk | MED | 73 | `T1082` |
| `SP-106006` | Confidence: HIGH | Discovery | splunk | MED | 73 | `T1018` |
| `SP-106008` | Confidence: MEDIUM | Discovery | splunk | MED | 57 | `T1083` |
| `SP-106010` | Confidence: HIGH | Discovery | splunk | MED | 73 | `T1087.001` |
| `SP-106013` | Confidence: HIGH | Discovery | splunk | MED | 73 | `T1082` |
| `SP-106014` | Confidence: HIGH | Discovery | splunk | MED | 73 | `T1135` |
| `SP-106017` | Confidence: HIGH | Discovery | splunk | MED | 73 | `T1082` |
| `SP-106018` | Confidence: HIGH | Discovery | splunk | MED | 73 | `T1201` |
| `SP-106020` | Confidence: HIGH | Discovery | splunk | MED | 73 | `T1007` |
| `SP-106025` | Confidence: HIGH | Discovery | splunk | MED | 73 | `T1082` |
| `SP-106026` | Confidence: MEDIUM | Discovery | splunk | MED | 57 | `T1010` |
| `SP-106027` | Confidence: HIGH | Discovery | splunk | MED | 73 | `T1033` |
| `SP-106029` | Confidence: MEDIUM | Discovery | splunk | MED | 57 | `T1217` |
| `SP-106032` | Confidence: MEDIUM | Discovery | splunk | MED | 57 | `T1083` |
| `SP-106005` | Confidence: HIGH | Discovery | splunk | LOW | 73 | `T1016` |
| `SP-106007` | Confidence: HIGH | Discovery | splunk | LOW | 73 | `T1049` |
| `SP-106012` | Confidence: HIGH | Discovery | splunk | LOW | 73 | `T1057` |
| `SP-106019` | Confidence: MEDIUM | Discovery | splunk | LOW | 57 | `T1082` |
| `SP-106023` | Confidence: HIGH | Discovery | splunk | LOW | 73 | `T1016` |
| `SP-106028` | Confidence: MEDIUM | Discovery | splunk | LOW | 57 | `T1082` |
| | | | | | | |
| `SP-790016` | Sensitive Keywords in ausgehendem HTTP POST-Body | DLP / Exfiltration | splunk | **CRIT** | 85 | `T1048.003` |
| `SP-790019` | Mehrere Exfil-Vektoren in kurzer Zeit (Staging-Indik... | DLP / Exfiltration | splunk | **CRIT** | 85 | `T1048` |
| `SP-790001` | Großer HTTP POST Upload (>50 MB in einer Session | DLP / Exfiltration | splunk | HIGH | 80 | `T1048.003` |
| `SP-790002` | Upload-Spike zu Cloud-Storage (>500MB/h | DLP / Exfiltration | splunk | HIGH | 82 | `T1567.002` |
| `SP-790003` | Komprimierung sensitiver Verzeichnisse | DLP / Exfiltration | splunk | HIGH | 82 | `T1560.001` |
| `SP-790005` | DNS-Query mit ungewöhnlich langer Subdomain (>50 Zei... | DLP / Exfiltration | splunk | HIGH | 82 | `T1048.003` |
| `SP-790006` | FTP Upload zu externem Host | DLP / Exfiltration | splunk | HIGH | 85 | `T1048.003` |
| `SP-790007` | SCP / SFTP Upload zu Nicht-Inventar-Host | DLP / Exfiltration | splunk | HIGH | 80 | `T1048.002` |
| `SP-790008` | Sensitive Dateitypen auf Removable Media kopiert | DLP / Exfiltration | splunk | HIGH | 80 | `T1052.001` |
| `SP-790009` | AWS CLI: Daten-Upload zu externem S3-Bucket | DLP / Exfiltration | splunk | HIGH | 85 | `T1537` |
| `SP-790010` | Git Push zu externem Repository (große Datenmenge | DLP / Exfiltration | splunk | HIGH | 78 | `T1048` |
| `SP-790011` | ZIP / RAR in Temp erstellt und sofort gelöscht | DLP / Exfiltration | splunk | HIGH | 82 | `T1560` |
| `SP-790012` | Daten-Staging im Webserver-Verzeichnis | DLP / Exfiltration | splunk | HIGH | 82 | `T1071.001` |
| `SP-790013` | Screenshot-Burst (>10 Screenshots in 5 Min | DLP / Exfiltration | splunk | HIGH | 80 | `T1113` |
| `SP-790014` | Clipboard-Zugriff durch ungewöhnlichen Prozess | DLP / Exfiltration | splunk | HIGH | 80 | `T1115` |
| `SP-790015` | ICMP Exfiltration (ungewöhnlich große / viele ICMP-P... | DLP / Exfiltration | splunk | HIGH | 82 | `T1048.003` |
| `SP-790017` | Neue externe SharePoint-Sharing-Links für große Bibl... | DLP / Exfiltration | splunk | HIGH | 80 | `T1567.001` |
| `SP-790018` | Datenbankabfrage-Ergebnis in Datei geschrieben und s... | DLP / Exfiltration | splunk | HIGH | 82 | `T1213` |
| `SP-790020` | rclone / rsync zu externem Storage-Endpoint | DLP / Exfiltration | splunk | HIGH | 85 | `T1537` |
| `SP-790004` | Base64-kodierte Daten in URL-Parametern (>100 Zeichen | DLP / Exfiltration | splunk | MED | 72 | `T1048.003` |
| | | | | | | |
| `SP-750016` | Executive Impersonation (CEO/CFO im Display-Name, ex... | Email Security | splunk | **CRIT** | 88 | `T1566.001` |
| `SP-750001` | DMARC-Fail-Cluster (>10 in 5 Min von gleicher Sender... | Email Security | splunk | HIGH | 82 | `T1566.001` |
| `SP-750002` | SPF-Fail mit internem Display-Name (CEO/CFO/IT Imper... | Email Security | splunk | HIGH | 85 | `T1566.001` |
| `SP-750003` | E-Mail mit .iso / .img / .vhd Anhang | Email Security | splunk | HIGH | 85 | `T1566.001` |
| `SP-750004` | E-Mail mit Makro-fähigem Office-Anhang (.xlsm/.docm/... | Email Security | splunk | HIGH | 85 | `T1566.001` |
| `SP-750005` | E-Mail von neu registrierter Domain (<30 Tage alt | Email Security | splunk | HIGH | 82 | `T1566.001` |
| `SP-750006` | Lookalike / Homoglyph Sender-Domain | Email Security | splunk | HIGH | 90 | `T1566.001` |
| `SP-750008` | E-Mail-Bombardierung (>50 E-Mails an gleiche Inbox i... | Email Security | splunk | HIGH | 82 | `T1498` |
| `SP-750009` | HTML-E-Mail mit obfuszierten Links (URL-Shortener / ... | Email Security | splunk | HIGH | 80 | `T1566.002` |
| `SP-750010` | Kalendar-Einladung mit externem Link von unbekanntem... | Email Security | splunk | HIGH | 80 | `T1566.001` |
| `SP-750011` | QR-Code im Anhang (Quishing | Email Security | splunk | HIGH | 82 | `T1566.001` |
| `SP-750012` | DocuSign / Adobe Sign Impersonation | Email Security | splunk | HIGH | 85 | `T1566.001` |
| `SP-750014` | Reply-Chain Injection (Antwort in interner E-Mail-Ke... | Email Security | splunk | HIGH | 82 | `T1566.001` |
| `SP-750015` | Passwort / Credential Keyword in Betreff extern gese... | Email Security | splunk | HIGH | 80 | `T1048.003` |
| `SP-750017` | Vishing / Voicemail-Phishing Anhang-Pattern | Email Security | splunk | HIGH | 82 | `T1566.001` |
| `SP-750018` | Intern → Extern: Massen-BCC (>10 externe Empfänger | Email Security | splunk | HIGH | 78 | `T1048.003` |
| `SP-750019` | Kein DMARC / SPF / DKIM auf interner Domain erkannt | Email Security | splunk | HIGH | 80 | `T1036` |
| `SP-750020` | Makro / Script-Anhang geblockt (Trend: Spike >10 in 1h | Email Security | splunk | HIGH | 85 | `T1566.001` |
| `SP-750007` | Reply-To-Adresse weicht von Sender-Domain ab | Email Security | splunk | MED | 75 | `T1566.001` |
| `SP-750013` | Großer Anhang extern gesendet (>10MB | Email Security | splunk | MED | 72 | `T1048.003` |
| | | | | | | |
| `SP-100004` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1562.001` |
| `SP-100006` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1003.001` |
| `SP-100011` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1059.001` |
| `SP-100013` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1059.001` |
| `SP-100021` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1059.001` |
| `SP-100041` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1543.003` |
| `SP-100051` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1490` |
| `SP-100052` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1055.001` |
| `SP-100054` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1003.002` |
| `SP-100055` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1003.003` |
| `SP-100056` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1490` |
| `SP-100062` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1546.003` |
| `SP-100065` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1546.003` |
| `SP-100079` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1490` |
| `SP-100087` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1546.003` |
| `SP-100089` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1562.001` |
| `SP-100090` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1047` |
| `SP-100091` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1566.001` |
| `SP-100097` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1546.003` |
| `SP-100099` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1059.001` |
| `SP-100100` | Confidence: HIGH | Windows Execution | splunk | **CRIT** | 90 | `T1546.003` |
| `SP-100001` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1059.001` |
| `SP-100002` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1059.001` |
| `SP-100003` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1059.001` |
| `SP-100005` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1059.001` |
| `SP-100007` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1059.001` |
| `SP-100008` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1059.001` |
| `SP-100009` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1059.001` |
| `SP-100010` | Confidence: MEDIUM | Windows Execution | splunk | HIGH | 62 | `T1027` |
| `SP-100012` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1021.006` |
| `SP-100014` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1053.005` |
| `SP-100015` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1562.006` |
| `SP-100016` | Confidence: MEDIUM | Windows Execution | splunk | HIGH | 62 | `T1059.001` |
| `SP-100017` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1056.001` |
| `SP-100018` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1070.001` |
| `SP-100020` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1134.001` |
| `SP-100022` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1490` |
| `SP-100023` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1041` |
| `SP-100024` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1562.001` |
| `SP-100026` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1218.005` |
| `SP-100027` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1218.010` |
| `SP-100028` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1218.011` |
| `SP-100029` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1140` |
| `SP-100030` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1197` |
| `SP-100031` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1059.005` |
| `SP-100032` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1218.004` |
| `SP-100033` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1218` |
| `SP-100034` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1218.003` |
| `SP-100035` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1218.008` |
| `SP-100037` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1218` |
| `SP-100038` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1218` |
| `SP-100039` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1218` |
| `SP-100040` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1127.001` |
| `SP-100044` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1047` |
| `SP-100045` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1547.001` |
| `SP-100046` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1136.001` |
| `SP-100047` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1053.005` |
| `SP-100049` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1218` |
| `SP-100050` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1218` |
| `SP-100053` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1543.003` |
| `SP-100058` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1218` |
| `SP-100059` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1059.003` |
| `SP-100060` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1218` |
| `SP-100061` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1047` |
| `SP-100063` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1047` |
| `SP-100064` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1047` |
| `SP-100066` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1566.001` |
| `SP-100067` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1566.001` |
| `SP-100068` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1566.001` |
| `SP-100069` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1105` |
| `SP-100070` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1059.005` |
| `SP-100071` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1566.001` |
| `SP-100072` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1059.005` |
| `SP-100073` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1059.005` |
| `SP-100074` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1137.006` |
| `SP-100075` | Confidence: MEDIUM | Windows Execution | splunk | HIGH | 62 | `T1559.001` |
| `SP-100076` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1047` |
| `SP-100077` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1047` |
| `SP-100078` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1547.001` |
| `SP-100080` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1566.001` |
| `SP-100082` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1137.001` |
| `SP-100084` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1105` |
| `SP-100085` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1047` |
| `SP-100086` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1547.001` |
| `SP-100092` | Confidence: MEDIUM | Windows Execution | splunk | HIGH | 62 | `T1047` |
| `SP-100093` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1566.001` |
| `SP-100095` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1218.011` |
| `SP-100098` | Confidence: HIGH | Windows Execution | splunk | HIGH | 78 | `T1566.001` |
| `SP-100019` | Confidence: MEDIUM | Windows Execution | splunk | MED | 62 | `T1560.001` |
| `SP-100025` | Confidence: MEDIUM | Windows Execution | splunk | MED | 62 | `T1059.001` |
| `SP-100036` | Confidence: HIGH | Windows Execution | splunk | MED | 78 | `T1218` |
| `SP-100042` | Confidence: MEDIUM | Windows Execution | splunk | MED | 62 | `T1482` |
| `SP-100043` | Confidence: MEDIUM | Windows Execution | splunk | MED | 62 | `T1218` |
| `SP-100048` | Confidence: HIGH | Windows Execution | splunk | MED | 78 | `T1053.005` |
| `SP-100057` | Confidence: HIGH | Windows Execution | splunk | MED | 78 | `T1218.007` |
| `SP-100083` | Confidence: MEDIUM | Windows Execution | splunk | MED | 62 | `T1047` |
| `SP-100088` | Confidence: HIGH | Windows Execution | splunk | MED | 78 | `T1566.001` |
| `SP-100096` | Confidence: MEDIUM | Windows Execution | splunk | MED | 62 | `T1047` |
| `SP-100081` | Confidence: MEDIUM | Windows Execution | splunk | LOW | 62 | `T1047` |
| `SP-100094` | Confidence: MEDIUM | Windows Execution | splunk | LOW | 62 | `T1087.002` |
| | | | | | | |
| `SP-107019` | Confidence: HIGH | Exfiltration | splunk | **CRIT** | 90 | `T1048` |
| `SP-107020` | Confidence: HIGH | Exfiltration | splunk | **CRIT** | 90 | `T1048` |
| `SP-107030` | Confidence: HIGH | Exfiltration | splunk | **CRIT** | 90 | `T1048` |
| `SP-107001` | Confidence: HIGH | Exfiltration | splunk | HIGH | 78 | `T1048.003` |
| `SP-107002` | Confidence: HIGH | Exfiltration | splunk | HIGH | 78 | `T1048.001` |
| `SP-107004` | Confidence: HIGH | Exfiltration | splunk | HIGH | 78 | `T1041` |
| `SP-107005` | Confidence: HIGH | Exfiltration | splunk | HIGH | 78 | `T1048` |
| `SP-107006` | Confidence: HIGH | Exfiltration | splunk | HIGH | 78 | `T1048` |
| `SP-107007` | Confidence: MEDIUM | Exfiltration | splunk | HIGH | 62 | `T1052.001` |
| `SP-107009` | Confidence: HIGH | Exfiltration | splunk | HIGH | 78 | `T1041` |
| `SP-107010` | Confidence: HIGH | Exfiltration | splunk | HIGH | 78 | `T1048.003` |
| `SP-107011` | Confidence: HIGH | Exfiltration | splunk | HIGH | 78 | `T1020` |
| `SP-107012` | Confidence: HIGH | Exfiltration | splunk | HIGH | 78 | `T1560.001` |
| `SP-107013` | Confidence: HIGH | Exfiltration | splunk | HIGH | 78 | `T1041` |
| `SP-107014` | Confidence: HIGH | Exfiltration | splunk | HIGH | 78 | `T1048` |
| `SP-107015` | Confidence: HIGH | Exfiltration | splunk | HIGH | 78 | `T1048.001` |
| `SP-107018` | Confidence: HIGH | Exfiltration | splunk | HIGH | 78 | `T1041` |
| `SP-107022` | Confidence: HIGH | Exfiltration | splunk | HIGH | 78 | `T1560` |
| `SP-107023` | Confidence: HIGH | Exfiltration | splunk | HIGH | 78 | `T1048` |
| `SP-107024` | Confidence: HIGH | Exfiltration | splunk | HIGH | 78 | `T1048` |
| `SP-107025` | Confidence: HIGH | Exfiltration | splunk | HIGH | 78 | `T1041` |
| `SP-107026` | Confidence: MEDIUM | Exfiltration | splunk | HIGH | 62 | `T1048` |
| `SP-107027` | Confidence: HIGH | Exfiltration | splunk | HIGH | 78 | `T1048` |
| `SP-107029` | Confidence: HIGH | Exfiltration | splunk | HIGH | 78 | `T1048` |
| `SP-107003` | Confidence: MEDIUM | Exfiltration | splunk | MED | 62 | `T1560.001` |
| `SP-107008` | Confidence: MEDIUM | Exfiltration | splunk | MED | 62 | `T1567.002` |
| `SP-107016` | Confidence: MEDIUM | Exfiltration | splunk | MED | 62 | `T1048` |
| `SP-107017` | Confidence: MEDIUM | Exfiltration | splunk | MED | 62 | `T1567` |
| `SP-107021` | Confidence: MEDIUM | Exfiltration | splunk | MED | 62 | `T1048` |
| `SP-107028` | Confidence: MEDIUM | Exfiltration | splunk | MED | 62 | `T1020` |
| | | | | | | |
| `SP-740001` | SSH auf ESXi-Host aktiviert | Hypervisor / VMware | splunk | **CRIT** | 88 | `T1133` |
| `SP-740002` | Neuer vCenter / ESXi Admin-Account erstellt | Hypervisor / VMware | splunk | **CRIT** | 88 | `T1136` |
| `SP-740003` | Massen-Snapshot-Löschung (>3 in 10 Min | Hypervisor / VMware | splunk | **CRIT** | 90 | `T1490` |
| `SP-740004` | vCenter SAML Zertifikat manipuliert | Hypervisor / VMware | splunk | **CRIT** | 88 | `T1550.001` |
| `SP-740005` | ESXi Lockdown-Modus deaktiviert | Hypervisor / VMware | splunk | **CRIT** | 88 | `T1562` |
| `SP-740007` | Virtuelle Festplatte (.vmdk) exportiert | Hypervisor / VMware | splunk | **CRIT** | 88 | `T1041` |
| `SP-740011` | Management-Netzwerk VLAN geändert | Hypervisor / VMware | splunk | **CRIT** | 85 | `T1565` |
| `SP-740013` | ESXi Ransomware Indikator (.args/.zoldon/.lock Erwei... | Hypervisor / VMware | splunk | **CRIT** | 95 | `T1486` |
| `SP-740014` | Hypervisor-Log geleert oder Syslog-Weiterleitung dea... | Hypervisor / VMware | splunk | **CRIT** | 88 | `T1070` |
| `SP-740015` | VM Memory Snapshot (mögliche Credential-Extraktion | Hypervisor / VMware | splunk | **CRIT** | 88 | `T1003` |
| `SP-740019` | Proxmox: Neuer Benutzer mit Admin-Rechten erstellt | Hypervisor / VMware | splunk | **CRIT** | 85 | `T1136` |
| `SP-740020` | Proxmox: CT / VM Backup deaktiviert oder gelöscht | Hypervisor / VMware | splunk | **CRIT** | 85 | `T1490` |
| `SP-740006` | VM-Konfigurationsdatei (.vmx) direkt geändert | Hypervisor / VMware | splunk | HIGH | 82 | `T1542` |
| `SP-740008` | VM zu unbekanntem Host geklont oder migriert (vMotion | Hypervisor / VMware | splunk | HIGH | 78 | `T1021` |
| `SP-740009` | ESXi Shell-Befehl via API ausgeführt (ESXi Shell API | Hypervisor / VMware | splunk | HIGH | 85 | `T1059` |
| `SP-740010` | Host-Level Firewall-Regel hinzugefügt | Hypervisor / VMware | splunk | HIGH | 82 | `T1562.004` |
| `SP-740012` | vSphere Web Client Login von unbekannter IP | Hypervisor / VMware | splunk | HIGH | 82 | `T1133` |
| `SP-740016` | DRS / HA Konfiguration außerhalb Wartungsfenster geä... | Hypervisor / VMware | splunk | HIGH | 75 | `T1565` |
| `SP-740018` | ESXi Host dem Cluster ohne Genehmigung hinzugefügt | Hypervisor / VMware | splunk | HIGH | 80 | `T1021` |
| `SP-740017` | VMware Tools in VM deaktiviert (Anti-Forensic | Hypervisor / VMware | splunk | MED | 72 | `T1562` |
| | | | | | | |
| `SP-700001` | Global Administrator direkt zugewiesen (kein PIM | Identity / IAM | splunk | **CRIT** | 90 | `T1078.004` |
| `SP-700003` | Break-Glass-Account angemeldet | Identity / IAM | splunk | **CRIT** | 95 | `T1078.004` |
| `SP-700007` | Conditional Access Policy geändert oder deaktiviert | Identity / IAM | splunk | **CRIT** | 88 | `T1556` |
| `SP-700010` | Nutzer zu Tier-0-Gruppe hinzugefügt (DA/EA/Schema Ad... | Identity / IAM | splunk | **CRIT** | 92 | `T1098.002` |
| `SP-700012` | Impossible Travel — gleicher User, zwei Länder in <1h | Identity / IAM | splunk | **CRIT** | 88 | `T1078.004` |
| `SP-701001` | Root-Account-Login | Identity / IAM | splunk | **CRIT** | 95 | `T1078.004` |
| `SP-701003` | API-Key für Root-Account erstellt | Identity / IAM | splunk | **CRIT** | 97 | `T1098.001` |
| `SP-701004` | AdministratorAccess Policy an User/Role gebunden | Identity / IAM | splunk | **CRIT** | 92 | `T1098.003` |
| `SP-701008` | Service Control Policy (SCP) von OU entfernt | Identity / IAM | splunk | **CRIT** | 90 | `T1562` |
| `SP-701013` | IAM Inline Policy mit Wildcard (Action:* / Resource:* | Identity / IAM | splunk | **CRIT** | 88 | `T1098.003` |
| `SP-701019` | Organizations LeaveOrganization oder RemoveAccount | Identity / IAM | splunk | **CRIT** | 95 | `T1531` |
| `SP-702003` | Okta Admin-Rolle vergeben | Identity / IAM | splunk | **CRIT** | 90 | `T1098` |
| `SP-703003` | ATO Chain: Failed Login → MFA-Änderung → Privileged ... | Identity / IAM | splunk | **CRIT** | 88 | `T1078` |
| `SP-703007` | Neuer Admin erstellt und innerhalb 10 Min genutzt | Identity / IAM | splunk | **CRIT** | 88 | `T1136` |
| `SP-703014` | Gleichzeitige Sessions aus verschiedenen Ländern (Un... | Identity / IAM | splunk | **CRIT** | 90 | `T1078` |
| `SP-700002` | MFA-Gerät eines privilegierten Nutzers gelöscht | Identity / IAM | splunk | HIGH | 88 | `T1556.006` |
| `SP-700004` | Service Principal Secret oder Zertifikat hinzugefügt | Identity / IAM | splunk | HIGH | 85 | `T1098.001` |
| `SP-700005` | Federated Credential zu Service Principal hinzugefügt | Identity / IAM | splunk | HIGH | 85 | `T1550.001` |
| `SP-700006` | OAuth App mit hochsensiblen Scopes genehmigt | Identity / IAM | splunk | HIGH | 82 | `T1528` |
| `SP-700008` | Cross-Tenant Access Policy geändert | Identity / IAM | splunk | HIGH | 80 | `T1078.004` |
| `SP-700009` | PIM-Einstellung geändert (Activation ohne Approval | Identity / IAM | splunk | HIGH | 82 | `T1078.004` |
| `SP-700011` | Application Impersonation Role (EWS-Missbrauch | Identity / IAM | splunk | HIGH | 85 | `T1114.002` |
| `SP-700013` | Anmeldung von anonymem Proxy / Tor | Identity / IAM | splunk | HIGH | 82 | `T1090` |
| `SP-700014` | Passwort-Spray (>10 verschiedene Accounts, gleiches IP | Identity / IAM | splunk | HIGH | 90 | `T1110.003` |
| `SP-700015` | Bulk Guest-Einladung (>10 in 1h | Identity / IAM | splunk | HIGH | 80 | `T1078.004` |
| `SP-700016` | Verzeichnis-Rollenzuweisung außerhalb Geschäftszeiten | Identity / IAM | splunk | HIGH | 80 | `T1078.004` |
| `SP-700017` | Authentication Method Policy geändert (SSPR / Passwo... | Identity / IAM | splunk | HIGH | 82 | `T1556` |
| `SP-700019` | Token-Diebstahl-Indikator (Refresh Token von neuer I... | Identity / IAM | splunk | HIGH | 80 | `T1550.001` |
| `SP-700020` | MFA Push-Bombing (>3 Pushes in 5 Min | Identity / IAM | splunk | HIGH | 88 | `T1621` |
| `SP-701002` | IAM-User ohne MFA erstellt und sofort API-Key generiert | Identity / IAM | splunk | HIGH | 88 | `T1136.003` |
| `SP-701005` | Passwort-Policy geschwächt (min length < 14 | Identity / IAM | splunk | HIGH | 85 | `T1556` |
| `SP-701006` | MFA-Gerät eines Users gelöscht | Identity / IAM | splunk | HIGH | 90 | `T1556.006` |
| `SP-701007` | Cross-Account IAM-Role erstellt | Identity / IAM | splunk | HIGH | 82 | `T1098.003` |
| `SP-701009` | User in kurzer Zeit zu vielen Gruppen hinzugefügt (>... | Identity / IAM | splunk | HIGH | 85 | `T1098` |
| `SP-701010` | Assume Role auf hochprivilegierte Rolle (außerhalb n... | Identity / IAM | splunk | HIGH | 80 | `T1548` |
| `SP-701011` | GetCredentialsForIdentity (Cognito Credential Theft | Identity / IAM | splunk | HIGH | 78 | `T1528` |
| `SP-701012` | AccessKey von neuer IP / neuer Region genutzt | Identity / IAM | splunk | HIGH | 78 | `T1552.005` |
| `SP-701014` | Permission Boundary entfernt | Identity / IAM | splunk | HIGH | 88 | `T1548` |
| `SP-701015` | IAM Access Analyzer deaktiviert | Identity / IAM | splunk | HIGH | 88 | `T1562` |
| `SP-701016` | Account-level Public Access Block deaktiviert | Identity / IAM | splunk | HIGH | 88 | `T1537` |
| `SP-701017` | Enumeration Burst (>50 ListPolicies/GetUser/ListRole... | Identity / IAM | splunk | HIGH | 85 | `T1069.003` |
| `SP-701018` | IAM-Rolle an EC2/Lambda weitergegeben (Privilege Esc... | Identity / IAM | splunk | HIGH | 82 | `T1548` |
| `SP-702001` | MFA-Faktor-Registrierung von neuem Gerät | Identity / IAM | splunk | HIGH | 82 | `T1556.006` |
| `SP-702002` | MFA-Faktor durch Admin zurückgesetzt | Identity / IAM | splunk | HIGH | 88 | `T1556.006` |
| `SP-702004` | Authentication Policy geändert | Identity / IAM | splunk | HIGH | 85 | `T1556` |
| `SP-702005` | API-Token erstellt | Identity / IAM | splunk | HIGH | 85 | `T1098.001` |
| `SP-702006` | Netzwerkzone geändert oder deaktiviert (Zone-Bypass | Identity / IAM | splunk | HIGH | 85 | `T1562` |
| `SP-702007` | Passwort-Reset für mehrere User (>5 in 10 Min | Identity / IAM | splunk | HIGH | 85 | `T1531` |
| `SP-702009` | OAuth App mit riskanten Scopes genehmigt | Identity / IAM | splunk | HIGH | 82 | `T1528` |
| `SP-702010` | Session-Cookie-Hijack (gleiche Session, neue IP/User... | Identity / IAM | splunk | HIGH | 82 | `T1550.004` |
| `SP-702011` | MFA Push-Bombing / Fatigue (>3 Push-Requests in 5 Min | Identity / IAM | splunk | HIGH | 90 | `T1621` |
| `SP-702014` | Okta Verify Gerät still hinzugefügt (kein User-Prompt | Identity / IAM | splunk | HIGH | 85 | `T1556.006` |
| `SP-702017` | Brute-Force-Erfolg (Fails dann Success | Identity / IAM | splunk | HIGH | 88 | `T1110.001` |
| `SP-702018` | Login aus neuem Land für Admin-Account | Identity / IAM | splunk | HIGH | 80 | `T1078` |
| `SP-702019` | Nutzer-Account deaktiviert und sofort reaktiviert (M... | Identity / IAM | splunk | HIGH | 82 | `T1098` |
| `SP-702020` | Okta Admin-Session von unbekanntem IP-Bereich | Identity / IAM | splunk | HIGH | 85 | `T1078` |
| `SP-703001` | MFA Fatigue Attack — Push-Flood von gleicher IP | Identity / IAM | splunk | HIGH | 85 | `T1621` |
| `SP-703002` | Credential Stuffing Burst (viele Accounts, gleiche I... | Identity / IAM | splunk | HIGH | 88 | `T1110.004` |
| `SP-703004` | Service-Account interaktiv eingeloggt (sollte nie in... | Identity / IAM | splunk | HIGH | 85 | `T1078.002` |
| `SP-703005` | Geteiltes Privileged Account (gleichzeitige Sessions... | Identity / IAM | splunk | HIGH | 80 | `T1078` |
| `SP-703008` | Login von Tor / bekannten VPN-Provider-IPs | Identity / IAM | splunk | HIGH | 82 | `T1090.003` |
| `SP-703010` | Reaktivierter Account sofort genutzt (<5 Min nach En... | Identity / IAM | splunk | HIGH | 85 | `T1078` |
| `SP-703011` | Passwort geändert + sofort Massenaktionen (Datenabfluss | Identity / IAM | splunk | HIGH | 82 | `T1114` |
| `SP-703012` | Session Token von unterschiedlicher IP genutzt | Identity / IAM | splunk | HIGH | 85 | `T1550.004` |
| `SP-703013` | Inaktiver Account genutzt (>90 Tage kein Login | Identity / IAM | splunk | HIGH | 82 | `T1078` |
| `SP-703015` | Admin-Rolle temporär hinzugefügt und sofort entfernt... | Identity / IAM | splunk | HIGH | 85 | `T1098` |
| `SP-700018` | Named Location hinzugefügt oder gelöscht (CAP-Bypass | Identity / IAM | splunk | MED | 75 | `T1556` |
| `SP-701020` | Langlebige Credentials (>90 Tage) aktiv genutzt | Identity / IAM | splunk | MED | 72 | `T1552.005` |
| `SP-702008` | Account wiederholt entsperrt (>3 in 1h — mögliche AT... | Identity / IAM | splunk | MED | 75 | `T1078` |
| `SP-702012` | SCIM API Massen-Zugriff (>100 Calls in 5 Min | Identity / IAM | splunk | MED | 72 | `T1087` |
| `SP-702013` | App-Zuweisung zu Allen Nutzern (Massenfreigabe | Identity / IAM | splunk | MED | 72 | `T1098` |
| `SP-702015` | Nutzer-Profil durch Nicht-Besitzer geändert | Identity / IAM | splunk | MED | 75 | `T1098` |
| `SP-702016` | Verdächtiger User-Agent in Okta-Events (Automation/S... | Identity / IAM | splunk | MED | 72 | `T1087` |
| `SP-703006` | Admin-Login außerhalb Geschäftszeiten (vor 07:00 ode... | Identity / IAM | splunk | MED | 72 | `T1078` |
| `SP-703009` | Login aus nie-zuvor-gesehenem Land für diesen Nutzer | Identity / IAM | splunk | MED | 70 | `T1078` |
| | | | | | | |
| `SP-108001` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1490` |
| `SP-108002` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1490` |
| `SP-108003` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1490` |
| `SP-108004` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1490` |
| `SP-108005` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1490` |
| `SP-108006` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1486` |
| `SP-108007` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1486` |
| `SP-108008` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1486` |
| `SP-108010` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1490` |
| `SP-108011` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1486` |
| `SP-108012` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1490` |
| `SP-108014` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1489` |
| `SP-108015` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1490` |
| `SP-108016` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1486` |
| `SP-108017` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1490` |
| `SP-108018` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1561.001` |
| `SP-108019` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1486` |
| `SP-108021` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1490` |
| `SP-108024` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1489` |
| `SP-108026` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1490` |
| `SP-108027` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1490` |
| `SP-108028` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1486` |
| `SP-108029` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1490` |
| `SP-108030` | Confidence: HIGH | Impact | splunk | **CRIT** | 90 | `T1486` |
| `SP-108009` | Confidence: HIGH | Impact | splunk | HIGH | 78 | `T1489` |
| `SP-108013` | Confidence: HIGH | Impact | splunk | HIGH | 78 | `T1486` |
| `SP-108020` | Confidence: HIGH | Impact | splunk | HIGH | 78 | `T1489` |
| `SP-108022` | Confidence: HIGH | Impact | splunk | HIGH | 78 | `T1486` |
| `SP-108023` | Confidence: HIGH | Impact | splunk | HIGH | 78 | `T1490` |
| `SP-108025` | Confidence: MEDIUM | Impact | splunk | HIGH | 62 | `T1486` |
| | | | | | | |
| `SP-110002` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1566.001` |
| `SP-110005` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1566.001` |
| `SP-110006` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1566.001` |
| `SP-110007` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1190` |
| `SP-110008` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1203` |
| `SP-110012` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1190` |
| `SP-110015` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1566.001` |
| `SP-110016` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1203` |
| `SP-110017` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1566.001` |
| `SP-110018` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1566.001` |
| `SP-110021` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1190` |
| `SP-110024` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1203` |
| `SP-110026` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1190` |
| `SP-110029` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1566.001` |
| `SP-110030` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1566.001` |
| `SP-110031` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1190` |
| `SP-110032` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1566.001` |
| `SP-110035` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1566.001` |
| `SP-110036` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1566.001` |
| `SP-110038` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1190` |
| `SP-110040` | Confidence: HIGH | Initial Access | splunk | **CRIT** | 90 | `T1566.001` |
| `SP-110001` | Confidence: HIGH | Initial Access | splunk | HIGH | 78 | `T1566.001` |
| `SP-110003` | Confidence: HIGH | Initial Access | splunk | HIGH | 78 | `T1204.002` |
| `SP-110004` | Confidence: HIGH | Initial Access | splunk | HIGH | 78 | `T1566.002` |
| `SP-110009` | Confidence: HIGH | Initial Access | splunk | HIGH | 78 | `T1566.001` |
| `SP-110011` | Confidence: HIGH | Initial Access | splunk | HIGH | 78 | `T1566.001` |
| `SP-110013` | Confidence: HIGH | Initial Access | splunk | HIGH | 78 | `T1566.001` |
| `SP-110014` | Confidence: MEDIUM | Initial Access | splunk | HIGH | 62 | `T1204.002` |
| `SP-110019` | Confidence: HIGH | Initial Access | splunk | HIGH | 78 | `T1204.001` |
| `SP-110020` | Confidence: HIGH | Initial Access | splunk | HIGH | 78 | `T1566.001` |
| `SP-110022` | Confidence: HIGH | Initial Access | splunk | HIGH | 78 | `T1566.001` |
| `SP-110023` | Confidence: HIGH | Initial Access | splunk | HIGH | 78 | `T1566.002` |
| `SP-110025` | Confidence: HIGH | Initial Access | splunk | HIGH | 78 | `T1566.001` |
| `SP-110027` | Confidence: HIGH | Initial Access | splunk | HIGH | 78 | `T1566.001` |
| `SP-110028` | Confidence: HIGH | Initial Access | splunk | HIGH | 78 | `T1204.002` |
| `SP-110033` | Confidence: HIGH | Initial Access | splunk | HIGH | 78 | `T1204.002` |
| `SP-110034` | Confidence: HIGH | Initial Access | splunk | HIGH | 78 | `T1566.002` |
| `SP-110037` | Confidence: MEDIUM | Initial Access | splunk | HIGH | 62 | `T1204.001` |
| `SP-110039` | Confidence: HIGH | Initial Access | splunk | HIGH | 78 | `T1566.001` |
| `SP-110010` | Confidence: MEDIUM | Initial Access | splunk | MED | 62 | `T1204.001` |
| | | | | | | |
| `SP-105009` | Confidence: HIGH | Lateral Movement | splunk | **CRIT** | 90 | `T1570` |
| `SP-105015` | Confidence: HIGH | Lateral Movement | splunk | **CRIT** | 90 | `T1534` |
| `SP-105016` | Confidence: HIGH | Lateral Movement | splunk | **CRIT** | 90 | `T1021.001` |
| `SP-105024` | Confidence: HIGH | Lateral Movement | splunk | **CRIT** | 90 | `T1021.002` |
| `SP-105025` | Confidence: HIGH | Lateral Movement | splunk | **CRIT** | 90 | `T1534` |
| `SP-105030` | Confidence: HIGH | Lateral Movement | splunk | **CRIT** | 90 | `T1021.001` |
| `SP-105036` | Confidence: HIGH | Lateral Movement | splunk | **CRIT** | 90 | `T1021.001` |
| `SP-105038` | Confidence: HIGH | Lateral Movement | splunk | **CRIT** | 90 | `T1534` |
| `SP-105040` | Confidence: HIGH | Lateral Movement | splunk | **CRIT** | 90 | `T1021.006` |
| `SP-105001` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.001` |
| `SP-105002` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.002` |
| `SP-105003` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.006` |
| `SP-105004` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.006` |
| `SP-105005` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1047` |
| `SP-105006` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.006` |
| `SP-105007` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.002` |
| `SP-105008` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.002` |
| `SP-105010` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.002` |
| `SP-105012` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.005` |
| `SP-105013` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.003` |
| `SP-105014` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.003` |
| `SP-105017` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.006` |
| `SP-105018` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1047` |
| `SP-105019` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.002` |
| `SP-105020` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.006` |
| `SP-105021` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.006` |
| `SP-105022` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.006` |
| `SP-105023` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.001` |
| `SP-105026` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.006` |
| `SP-105027` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.002` |
| `SP-105028` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1570` |
| `SP-105029` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.006` |
| `SP-105032` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.003` |
| `SP-105033` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1047` |
| `SP-105034` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.006` |
| `SP-105037` | Confidence: HIGH | Lateral Movement | splunk | HIGH | 78 | `T1021.006` |
| `SP-105039` | Confidence: MEDIUM | Lateral Movement | splunk | HIGH | 62 | `T1021.001` |
| `SP-105011` | Confidence: MEDIUM | Lateral Movement | splunk | MED | 62 | `T1021.004` |
| `SP-105031` | Confidence: MEDIUM | Lateral Movement | splunk | MED | 62 | `T1021.002` |
| `SP-105035` | Confidence: MEDIUM | Lateral Movement | splunk | MED | 62 | `T1021.002` |
| | | | | | | |
| `SP-300004` | systemd Service Unit in unüblichem Pfad erstellt | Linux Hunt | splunk | **CRIT** | 92 | `T1543.002` |
| `SP-300009` | Schreibzugriff auf /etc/ssh/sshd_config | Linux Hunt | splunk | **CRIT** | 92 | `T1556.004` |
| `SP-300011` | Schreibzugriff auf /etc/sudoers oder /etc/sudoers.d | Linux Hunt | splunk | **CRIT** | 95 | `T1548.003` |
| `SP-300012` | LD_PRELOAD in /etc/environment oder /etc/ld.so.prelo... | Linux Hunt | splunk | **CRIT** | 92 | `T1574.006` |
| `SP-301006` | /etc/sudoers direkt modifiziert | Linux Hunt | splunk | **CRIT** | 95 | `T1548.003` |
| `SP-301007` | pkexec oder polkit Exploit-Pattern | Linux Hunt | splunk | **CRIT** | 88 | `T1068` |
| `SP-301008` | Dirty Pipe / Dirty COW Indikator — memfd_create mit ... | Linux Hunt | splunk | **CRIT** | 80 | `T1068` |
| `SP-301010` | chroot Jail Escape (mount in Container | Linux Hunt | splunk | **CRIT** | 85 | `T1611` |
| `SP-301011` | Neuer UID=0 User angelegt (Backdoor Root | Linux Hunt | splunk | **CRIT** | 95 | `T1136.001` |
| `SP-301015` | Manipulation von /proc/PID/mem (Process Injection | Linux Hunt | splunk | **CRIT** | 88 | `T1055` |
| `SP-302003` | Auditd oder Syslog Service gestoppt | Linux Hunt | splunk | **CRIT** | 95 | `T1562.001` |
| `SP-302011` | Kernel Modul geladen von unüblichem Pfad (Rootkit | Linux Hunt | splunk | **CRIT** | 92 | `T1014` |
| `SP-303001` | /etc/shadow ausgelesen | Linux Hunt | splunk | **CRIT** | 95 | `T1003.008` |
| `SP-303003` | Mimikatz-ähnliches Verhalten — /proc/*/mem lesen | Linux Hunt | splunk | **CRIT** | 90 | `T1003.007` |
| `SP-300002` | Schreibzugriff auf /etc/crontab oder /etc/cron.d | Linux Hunt | splunk | HIGH | 85 | `T1053.003` |
| `SP-300005` | Schreibzugriff auf ~/.bashrc oder ~/.bash_profile | Linux Hunt | splunk | HIGH | 80 | `T1546.004` |
| `SP-300006` | Schreibzugriff auf /etc/profile.d | Linux Hunt | splunk | HIGH | 85 | `T1546.004` |
| `SP-300007` | SUID Binary an unüblichem Ort gesetzt | Linux Hunt | splunk | HIGH | 85 | `T1548.001` |
| `SP-300008` | Neuer SSH Authorized Key hinzugefügt | Linux Hunt | splunk | HIGH | 90 | `T1098.004` |
| `SP-300010` | Neues Konto in /etc/passwd oder /etc/shadow angelegt | Linux Hunt | splunk | HIGH | 88 | `T1136.001` |
| `SP-300013` | Neues Init-Script in /etc/init.d | Linux Hunt | splunk | HIGH | 82 | `T1037.004` |
| `SP-300015` | Schreibzugriff auf /var/spool/cron/crontabs | Linux Hunt | splunk | HIGH | 88 | `T1053.003` |
| `SP-301003` | SUID-Binary missbraucht (bekannte GTFOBins | Linux Hunt | splunk | HIGH | 85 | `T1548.001` |
| `SP-301005` | Capability-Setting via setcap | Linux Hunt | splunk | HIGH | 88 | `T1548.001` |
| `SP-301009` | Python / Perl / Ruby als root ausgeführt (sudo shell... | Linux Hunt | splunk | HIGH | 82 | `T1548.003` |
| `SP-301012` | su zu Root nach Fehlschlägen (Brute Force | Linux Hunt | splunk | HIGH | 80 | `T1548.003` |
| `SP-301013` | Docker Gruppe Mitgliedschaft für normalen User (Dock... | Linux Hunt | splunk | HIGH | 82 | `T1611` |
| `SP-302002` | Prozess mit gelöschter Binary (Fileless | Linux Hunt | splunk | HIGH | 85 | `T1620` |
| `SP-302004` | Audit-Regeln gelöscht (auditctl -D | Linux Hunt | splunk | HIGH | 90 | `T1562.001` |
| `SP-302007` | /tmp oder /dev/shm als Binary-Ausführungsort | Linux Hunt | splunk | HIGH | 88 | `T1027` |
| `SP-302008` | LD_PRELOAD Hijacking via Environment | Linux Hunt | splunk | HIGH | 90 | `T1574.006` |
| `SP-302010` | SELinux oder AppArmor deaktiviert | Linux Hunt | splunk | HIGH | 92 | `T1562.001` |
| `SP-302013` | Binary in /proc/PID/fd existiert ohne Datei auf Disk | Linux Hunt | splunk | HIGH | 78 | `T1620` |
| `SP-302014` | Netzwerkinterface in Promiscuous Mode gesetzt (Sniffing | Linux Hunt | splunk | HIGH | 85 | `T1040` |
| `SP-303002` | /etc/passwd gelesen durch unbekanntes Binary | Linux Hunt | splunk | HIGH | 80 | `T1003.008` |
| `SP-303004` | SSH Private Keys gelesen (nicht durch SSH-Agent | Linux Hunt | splunk | HIGH | 85 | `T1552.004` |
| `SP-303005` | Credential-Dateien in ~/.aws oder ~/.gcp gelesen | Linux Hunt | splunk | HIGH | 85 | `T1552.001` |
| `SP-303006` | Keylogger-API: inotifywait auf /dev/input | Linux Hunt | splunk | HIGH | 80 | `T1056.001` |
| `SP-303007` | strace auf SSH oder sudo Prozess (Credential Harvesting | Linux Hunt | splunk | HIGH | 82 | `T1003.007` |
| `SP-303009` | /proc/[PID]/environ ausgelesen (ENV vars mit Passwör... | Linux Hunt | splunk | HIGH | 80 | `T1552.007` |
| `SP-303010` | sudo Passwort via SUDO_ASKPASS oder visudo Manipulation | Linux Hunt | splunk | HIGH | 80 | `T1548.003` |
| `SP-303011` | Python Keychain / DBUS Secret Service Zugriff | Linux Hunt | splunk | HIGH | 78 | `T1555.004` |
| `SP-303012` | Passwort-Spray via SSH — viele Auth-Fehlschläge von ... | Linux Hunt | splunk | HIGH | 88 | `T1110.003` |
| `SP-300001` | Neuer Crontab-Eintrag für User | Linux Hunt | splunk | MED | 72 | `T1053.003` |
| `SP-300003` | Neue systemd Service Unit erstellt | Linux Hunt | splunk | MED | 70 | `T1543.002` |
| `SP-300014` | AT-Job erstellt (Einmal-Persistenz | Linux Hunt | splunk | MED | 65 | `T1053.001` |
| `SP-301002` | sudo NOPASSWD Eintrag genutzt (ungewöhnlicher Command | Linux Hunt | splunk | MED | 65 | `T1548.003` |
| `SP-301004` | Kernel Exploit Versuch — dmesg / /proc/kallsyms gelesen | Linux Hunt | splunk | MED | 68 | `T1082` |
| `SP-301014` | Unix Socket Missbrauch (namespaced root | Linux Hunt | splunk | MED | 65 | `T1068` |
| `SP-302001` | History-Datei gelöscht oder deaktiviert | Linux Hunt | splunk | MED | 80 | `T1070.003` |
| `SP-302005` | Timestomping via touch -t | Linux Hunt | splunk | MED | 72 | `T1070.006` |
| `SP-302006` | Binaries mit UPX gepackt oder gestripped | Linux Hunt | splunk | MED | 70 | `T1027.002` |
| `SP-302009` | Schreibzugriff auf /proc/PID/attr/exec (SELinux Labe... | Linux Hunt | splunk | MED | 65 | `T1562` |
| `SP-302012` | Dateisystem-Attribut mit chattr gesetzt (immutable | Linux Hunt | splunk | MED | 70 | `T1222.002` |
| `SP-302015` | Systemd Timer als Persistence-Alternative | Linux Hunt | splunk | MED | 68 | `T1053.006` |
| `SP-303008` | OpenSSL / GPG private Key ungeschützt exportiert | Linux Hunt | splunk | MED | 68 | `T1552` |
| `SP-301001` | sudo -l Auflistung durch normalen User | Linux Hunt | splunk | LOW | 55 | `T1548.003` |
| | | | | | | |
| `SP-780002` | LaunchDaemon in /Library/LaunchDaemons erstellt (Sys... | macOS | splunk | **CRIT** | 88 | `T1543.004` |
| `SP-780005` | TCC-Datenbank direkt modifiziert (Privacy-Bypass | macOS | splunk | **CRIT** | 88 | `T1548.004` |
| `SP-780008` | Gatekeeper deaktiviert (spctl --master-disable | macOS | splunk | **CRIT** | 92 | `T1553.001` |
| `SP-780009` | SIP (System Integrity Protection) deaktiviert | macOS | splunk | **CRIT** | 92 | `T1562` |
| `SP-780013` | sudoers Datei modifiziert | macOS | splunk | **CRIT** | 90 | `T1548.003` |
| `SP-780015` | Jamf / MDM-Enrollment entfernt | macOS | splunk | **CRIT** | 88 | `T1562` |
| `SP-780001` | LaunchAgent in ~/Library/LaunchAgents erstellt (User... | macOS | splunk | HIGH | 85 | `T1543.001` |
| `SP-780003` | Login Item hinzugefügt (Legacy Persistence | macOS | splunk | HIGH | 82 | `T1547.015` |
| `SP-780004` | osascript führt Shell-Befehl aus | macOS | splunk | HIGH | 85 | `T1059.002` |
| `SP-780006` | Keychain-Zugriff durch ungewöhnlichen Prozess | macOS | splunk | HIGH | 85 | `T1555.001` |
| `SP-780007` | Nicht signiertes Binary in User-Pfad ausgeführt | macOS | splunk | HIGH | 82 | `T1036` |
| `SP-780010` | Kernel Extension (kext) geladen | macOS | splunk | HIGH | 82 | `T1547.006` |
| `SP-780011` | Python / Ruby / Perl One-Liner mit Download-Exec Pat... | macOS | splunk | HIGH | 85 | `T1059.006` |
| `SP-780012` | curl / wget Download in /tmp + bash Ausführung | macOS | splunk | HIGH | 88 | `T1059.004` |
| `SP-780014` | SSH authorized_keys geändert | macOS | splunk | HIGH | 88 | `T1098.004` |
| `SP-780016` | Applikations-Bundle nach Installation geändert (Code... | macOS | splunk | HIGH | 82 | `T1036.001` |
| `SP-780017` | /etc/hosts modifiziert | macOS | splunk | HIGH | 85 | `T1565.001` |
| `SP-780018` | Screen Recording ohne TCC-Prompt (Screen Capture | macOS | splunk | HIGH | 80 | `T1113` |
| `SP-780020` | crontab installiert (ungewöhnlich auf macOS | macOS | splunk | HIGH | 82 | `T1053.003` |
| `SP-780019` | defaults write für ungewöhnliche Persistence (Dock /... | macOS | splunk | MED | 72 | `T1543` |
| | | | | | | |
| `SP-400001` | Firewall-Regel für bekannten C2-Port erstellt | Network Infrastructure | splunk | HIGH | 82 | `T1571` |
| `SP-400002` | Ausgehende Verbindung zu bekannten Tor-Ports | Network Infrastructure | splunk | HIGH | 90 | `T1090.003` |
| `SP-400003` | Massenhafte ausgehende Verbindungen (Port Scan | Network Infrastructure | splunk | HIGH | 85 | `T1046` |
| `SP-400004` | Firewall-Regeländerung außerhalb Wartungsfenster | Network Infrastructure | splunk | HIGH | 78 | `T1562.004` |
| `SP-400005` | DMZ → Internes Netz direkt (East-West Lateral | Network Infrastructure | splunk | HIGH | 80 | `T1021` |
| `SP-400006` | Ausgehende SMB Verbindungen (445) nach extern | Network Infrastructure | splunk | HIGH | 88 | `T1021.002` |
| `SP-400007` | Große Datenmenge ausgehend (>1GB in 1h | Network Infrastructure | splunk | HIGH | 80 | `T1041` |
| `SP-400008` | ICMP Tunnel — große ICMP Pakete (>512 Byte | Network Infrastructure | splunk | HIGH | 78 | `T1095` |
| `SP-400009` | Verbindung zu dynamischen DNS (DDNS) Domains | Network Infrastructure | splunk | HIGH | 82 | `T1568.001` |
| `SP-400011` | Verbindungen zu kurz lebenden IP-Ranges (Bulletproof... | Network Infrastructure | splunk | HIGH | 80 | `T1583.003` |
| `SP-400012` | Port-Hopping C2 Beaconing — gleiche Ziel-IP auf vers... | Network Infrastructure | splunk | HIGH | 80 | `T1571` |
| `SP-400013` | Verbindung zu RDP (3389) von extern nach intern | Network Infrastructure | splunk | HIGH | 85 | `T1021.001` |
| `SP-400014` | Hochvolumige DNS Exfiltration — viele Subdomains ein... | Network Infrastructure | splunk | HIGH | 85 | `T1048.003` |
| `SP-400015` | VPN-Verbindung von Land mit hohem Risiko | Network Infrastructure | splunk | HIGH | 72 | `T1133` |
| `SP-401001` | Domain Fronting — Host-Header weicht von SNI ab | Network Infrastructure | splunk | HIGH | 82 | `T1090.004` |
| `SP-401003` | HTTP POST auf unübliche Ports (nicht 80/443 | Network Infrastructure | splunk | HIGH | 78 | `T1041` |
| `SP-401005` | Verbindung zu frisch registrierter Domain (<30 Tage alt | Network Infrastructure | splunk | HIGH | 78 | `T1583.001` |
| `SP-401006` | Hohe Anfragehäufigkeit mit kleinen gleichmäßigen Int... | Network Infrastructure | splunk | HIGH | 80 | `T1071.001` |
| `SP-401007` | HTTP Tunneling über CONNECT zu nicht-HTTPS-Port | Network Infrastructure | splunk | HIGH | 82 | `T1572` |
| `SP-401008` | Verbindung zu Pastebin / GitHub Gist / Telegram API | Network Infrastructure | splunk | HIGH | 80 | `T1102` |
| `SP-401009` | DGA-Verdacht — hohe Entropie im Hostnamen | Network Infrastructure | splunk | HIGH | 78 | `T1568.002` |
| `SP-401010` | DNS TXT Record mit langen Base64-Strings (DNS-Exfil | Network Infrastructure | splunk | HIGH | 88 | `T1048.003` |
| `SP-401011` | Hohe NXDOMAIN-Rate von einem Host (DGA Beaconing | Network Infrastructure | splunk | HIGH | 85 | `T1568.002` |
| `SP-401013` | Subdomain-Enumeration (> 50 unique Subdomains einer ... | Network Infrastructure | splunk | HIGH | 85 | `T1595.003` |
| `SP-401014` | Fast Flux — DNS TTL < 60 Sekunden | Network Infrastructure | splunk | HIGH | 80 | `T1568.001` |
| `SP-401015` | Homoglyph / Look-alike Domain zu bekanntem Unternehmen | Network Infrastructure | splunk | HIGH | 90 | `T1566.002` |
| `SP-400010` | IPv6 Tunneling über IPv4 (6in4, Teredo | Network Infrastructure | splunk | MED | 70 | `T1572` |
| `SP-401002` | Base64-encodierter String in HTTP-URL | Network Infrastructure | splunk | MED | 70 | `T1132.001` |
| `SP-401004` | User-Agent mit bekannten Tool-Signaturen | Network Infrastructure | splunk | MED | 72 | `T1071.001` |
| `SP-401012` | DNS over HTTPS (DoH) zu unbekannten Servern | Network Infrastructure | splunk | MED | 68 | `T1071.004` |
| | | | | | | |
| `SP-101003` | Confidence: HIGH | Windows Persistence | splunk | **CRIT** | 90 | `T1547.004` |
| `SP-101004` | Confidence: HIGH | Windows Persistence | splunk | **CRIT** | 90 | `T1546.010` |
| `SP-101006` | Confidence: HIGH | Windows Persistence | splunk | **CRIT** | 90 | `T1553.006` |
| `SP-101007` | Confidence: HIGH | Windows Persistence | splunk | **CRIT** | 90 | `T1547.008` |
| `SP-101011` | Confidence: HIGH | Windows Persistence | splunk | **CRIT** | 90 | `T1547.006` |
| `SP-101014` | Confidence: HIGH | Windows Persistence | splunk | **CRIT** | 90 | `T1547.012` |
| `SP-101018` | Confidence: HIGH | Windows Persistence | splunk | **CRIT** | 90 | `T1562.001` |
| `SP-101019` | Confidence: HIGH | Windows Persistence | splunk | **CRIT** | 90 | `T1546.011` |
| `SP-101024` | Confidence: HIGH | Windows Persistence | splunk | **CRIT** | 90 | `T1546.003` |
| `SP-101043` | Confidence: HIGH | Windows Persistence | splunk | **CRIT** | 90 | `T1053.005` |
| `SP-101048` | Confidence: HIGH | Windows Persistence | splunk | **CRIT** | 90 | `T1053.005` |
| `SP-101052` | Confidence: HIGH | Windows Persistence | splunk | **CRIT** | 90 | `T1053.005` |
| `SP-101063` | Confidence: HIGH | Windows Persistence | splunk | **CRIT** | 90 | `T1543.003` |
| `SP-101069` | Confidence: HIGH | Windows Persistence | splunk | **CRIT** | 90 | `T1574.011` |
| `SP-101074` | Confidence: HIGH | Windows Persistence | splunk | **CRIT** | 90 | `T1543.003` |
| `SP-101077` | Confidence: HIGH | Windows Persistence | splunk | **CRIT** | 90 | `T1543.003` |
| `SP-101078` | Confidence: HIGH | Windows Persistence | splunk | **CRIT** | 90 | `T1543.003` |
| `SP-101079` | Confidence: HIGH | Windows Persistence | splunk | **CRIT** | 90 | `T1543.003` |
| `SP-101001` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1547.001` |
| `SP-101002` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1547.001` |
| `SP-101005` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1546.012` |
| `SP-101008` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1137.001` |
| `SP-101009` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1546.002` |
| `SP-101010` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1546.015` |
| `SP-101012` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1574.012` |
| `SP-101013` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1112` |
| `SP-101015` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1021.001` |
| `SP-101016` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1548.002` |
| `SP-101017` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1562.004` |
| `SP-101020` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1546.013` |
| `SP-101021` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1548.002` |
| `SP-101023` | Confidence: MEDIUM | Windows Persistence | splunk | HIGH | 62 | `T1197` |
| `SP-101025` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1546.001` |
| `SP-101026` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1053.005` |
| `SP-101027` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1053.005` |
| `SP-101028` | Confidence: MEDIUM | Windows Persistence | splunk | HIGH | 62 | `T1053.005` |
| `SP-101029` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1053.005` |
| `SP-101030` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1053.005` |
| `SP-101031` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1053.005` |
| `SP-101033` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1053.005` |
| `SP-101035` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1053.005` |
| `SP-101036` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1053.005` |
| `SP-101037` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1053.005` |
| `SP-101038` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1053.005` |
| `SP-101039` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1053.005` |
| `SP-101040` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1053.005` |
| `SP-101042` | Confidence: MEDIUM | Windows Persistence | splunk | HIGH | 62 | `T1053.005` |
| `SP-101044` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1053.005` |
| `SP-101045` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1053.005` |
| `SP-101046` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1547.001` |
| `SP-101047` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1053.005` |
| `SP-101049` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1547.001` |
| `SP-101051` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1053.005` |
| `SP-101053` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1053.005` |
| `SP-101054` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1053.005` |
| `SP-101055` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1053.005` |
| `SP-101056` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1543.003` |
| `SP-101057` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1543.003` |
| `SP-101058` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1543.003` |
| `SP-101059` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1543.003` |
| `SP-101061` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1543.003` |
| `SP-101062` | Confidence: MEDIUM | Windows Persistence | splunk | HIGH | 62 | `T1543.003` |
| `SP-101064` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1543.003` |
| `SP-101065` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1543.003` |
| `SP-101066` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1574.010` |
| `SP-101067` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1543.003` |
| `SP-101068` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1543.003` |
| `SP-101071` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1543.003` |
| `SP-101072` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1543.003` |
| `SP-101073` | Confidence: MEDIUM | Windows Persistence | splunk | HIGH | 62 | `T1543.003` |
| `SP-101075` | Confidence: HIGH | Windows Persistence | splunk | HIGH | 78 | `T1543.003` |
| `SP-101076` | Confidence: MEDIUM | Windows Persistence | splunk | HIGH | 62 | `T1543.003` |
| `SP-101022` | Confidence: MEDIUM | Windows Persistence | splunk | MED | 62 | `T1112` |
| `SP-101032` | Confidence: MEDIUM | Windows Persistence | splunk | MED | 62 | `T1053.005` |
| `SP-101034` | Confidence: MEDIUM | Windows Persistence | splunk | MED | 62 | `T1053.005` |
| `SP-101041` | Confidence: HIGH | Windows Persistence | splunk | MED | 78 | `T1053.005` |
| `SP-101050` | Confidence: MEDIUM | Windows Persistence | splunk | MED | 62 | `T1547.001` |
| `SP-101060` | Confidence: HIGH | Windows Persistence | splunk | MED | 78 | `T1543.003` |
| `SP-101070` | Confidence: HIGH | Windows Persistence | splunk | MED | 78 | `T1543.003` |
| `SP-101080` | Confidence: MEDIUM | Windows Persistence | splunk | MED | 62 | `T1543.003` |
| | | | | | | |
| `SP-109014` | Confidence: HIGH | Privilege Escalation | splunk | **CRIT** | 90 | `T1574.012` |
| `SP-109018` | Confidence: HIGH | Privilege Escalation | splunk | **CRIT** | 90 | `T1055.002` |
| `SP-109019` | Confidence: HIGH | Privilege Escalation | splunk | **CRIT** | 90 | `T1068` |
| `SP-109023` | Confidence: HIGH | Privilege Escalation | splunk | **CRIT** | 90 | `T1055.012` |
| `SP-109026` | Confidence: HIGH | Privilege Escalation | splunk | **CRIT** | 90 | `T1068` |
| `SP-109028` | Confidence: HIGH | Privilege Escalation | splunk | **CRIT** | 90 | `T1548.002` |
| `SP-109031` | Confidence: HIGH | Privilege Escalation | splunk | **CRIT** | 90 | `T1546.007` |
| `SP-109037` | Confidence: HIGH | Privilege Escalation | splunk | **CRIT** | 90 | `T1068` |
| `SP-109038` | Confidence: HIGH | Privilege Escalation | splunk | **CRIT** | 90 | `T1548.002` |
| `SP-109039` | Confidence: HIGH | Privilege Escalation | splunk | **CRIT** | 90 | `T1134.001` |
| `SP-109001` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1548.002` |
| `SP-109002` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1548.002` |
| `SP-109003` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1548.002` |
| `SP-109004` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1134.001` |
| `SP-109005` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1134.002` |
| `SP-109006` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1574.002` |
| `SP-109007` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1548.002` |
| `SP-109008` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1548.002` |
| `SP-109009` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1548.001` |
| `SP-109010` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1574.001` |
| `SP-109011` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1548.002` |
| `SP-109012` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1134.001` |
| `SP-109013` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1548.003` |
| `SP-109015` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1055.001` |
| `SP-109016` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1134.003` |
| `SP-109017` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1548.002` |
| `SP-109020` | Confidence: MEDIUM | Privilege Escalation | splunk | HIGH | 62 | `T1068` |
| `SP-109021` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1574.007` |
| `SP-109022` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1548.002` |
| `SP-109024` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1548.002` |
| `SP-109025` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1134.004` |
| `SP-109027` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1055.003` |
| `SP-109029` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1574.011` |
| `SP-109030` | Confidence: MEDIUM | Privilege Escalation | splunk | HIGH | 62 | `T1055.004` |
| `SP-109032` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1078.003` |
| `SP-109033` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1548.002` |
| `SP-109034` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1134.001` |
| `SP-109035` | Confidence: MEDIUM | Privilege Escalation | splunk | HIGH | 62 | `T1055.011` |
| `SP-109036` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1548.004` |
| `SP-109040` | Confidence: HIGH | Privilege Escalation | splunk | HIGH | 78 | `T1548.002` |
| | | | | | | |
| `SP-770012` | VPN-Verbindung nach Off-Boarding (Account deaktivier... | VPN / Remote Access | splunk | **CRIT** | 88 | `T1078` |
| `SP-770013` | Unmögliche Reise (zwei VPN-Logins, unterschiedliche ... | VPN / Remote Access | splunk | **CRIT** | 90 | `T1078` |
| `SP-770015` | VPN-Zugriff auf OT / ICS / SCADA Segment | VPN / Remote Access | splunk | **CRIT** | 88 | `T1021` |
| `SP-770019` | Jump Host ohne VPN-Prefix direkt aus Internet erreicht | VPN / Remote Access | splunk | **CRIT** | 88 | `T1133` |
| `SP-770001` | Login aus neuem Land für diesen User (erstmalig | VPN / Remote Access | splunk | HIGH | 78 | `T1078` |
| `SP-770002` | Login aus Hochrisiko-Land | VPN / Remote Access | splunk | HIGH | 80 | `T1078` |
| `SP-770003` | Viele Failed Logins vor Erfolg (Brute Force | VPN / Remote Access | splunk | HIGH | 88 | `T1110.001` |
| `SP-770004` | Admin-VPN außerhalb Geschäftszeiten | VPN / Remote Access | splunk | HIGH | 80 | `T1078` |
| `SP-770005` | Gleichzeitige VPN-Sessions von verschiedenen IPs (Cr... | VPN / Remote Access | splunk | HIGH | 82 | `T1078` |
| `SP-770006` | VPN-Login von Tor Exit Node oder bekanntem VPN-Provider | VPN / Remote Access | splunk | HIGH | 85 | `T1090.003` |
| `SP-770008` | Hohe Bandbreite auf VPN-Session (>1 GB/h | VPN / Remote Access | splunk | HIGH | 80 | `T1048` |
| `SP-770010` | VPN-Policy / Split-Tunnel Konfiguration geändert | VPN / Remote Access | splunk | HIGH | 80 | `T1562` |
| `SP-770011` | Service Account nutzt VPN (sollte API/Automation ver... | VPN / Remote Access | splunk | HIGH | 85 | `T1078.002` |
| `SP-770014` | ZTNA Policy Exception genehmigt | VPN / Remote Access | splunk | HIGH | 80 | `T1562` |
| `SP-770016` | Direkter RDP / SSH ohne VPN von extern | VPN / Remote Access | splunk | HIGH | 82 | `T1133` |
| `SP-770017` | VPN-Log-Weiterleitung gestoppt (Blind Spot | VPN / Remote Access | splunk | HIGH | 80 | `T1562.006` |
| `SP-770020` | Massen-VPN-Login (Password Spray auf VPN Gateway | VPN / Remote Access | splunk | HIGH | 88 | `T1110.003` |
| `SP-770007` | Neues Gerät über VPN verbunden (unbekannte Device ID | VPN / Remote Access | splunk | MED | 72 | `T1133` |
| `SP-770009` | Kurze wiederkehrende VPN-Sessions (Beaconing-Pattern | VPN / Remote Access | splunk | MED | 72 | `T1071` |
| `SP-770018` | Zertifikat-Basierte VPN-Auth mit abgelaufenem Zertif... | VPN / Remote Access | splunk | MED | 72 | `T1133` |
| | | | | | | |
| `SP-500001` | SQL Injection in HTTP-Request | Web Application | splunk | **CRIT** | 88 | `T1190` |
| `SP-500004` | Web Shell Zugriff (bekannte Web Shell Pattern | Web Application | splunk | **CRIT** | 92 | `T1505.003` |
| `SP-500005` | Log4Shell Exploit (CVE-2021-44228 | Web Application | splunk | **CRIT** | 95 | `T1190` |
| `SP-500006` | Spring4Shell Exploit (CVE-2022-22965 | Web Application | splunk | **CRIT** | 90 | `T1190` |
| `SP-500007` | File Upload mit gefährlicher Erweiterung | Web Application | splunk | **CRIT** | 88 | `T1505.003` |
| `SP-500008` | SSRF — Zugriff auf interne Metadaten-Endpunkte | Web Application | splunk | **CRIT** | 92 | `T1552.005` |
| `SP-500009` | Command Injection in URL Parameter | Web Application | splunk | **CRIT** | 88 | `T1059` |
| `SP-500012` | PHP Wrapper Exploit (php://input, php://filter | Web Application | splunk | **CRIT** | 92 | `T1190` |
| `SP-500014` | Exchange ProxyShell (CVE-2021-34473 / 34523 | Web Application | splunk | **CRIT** | 90 | `T1190` |
| `SP-500015` | OGNL Injection (Confluence CVE-2022-26134 | Web Application | splunk | **CRIT** | 92 | `T1190` |
| `SP-500002` | Directory Traversal / Path Traversal | Web Application | splunk | HIGH | 85 | `T1190` |
| `SP-500003` | XSS-Versuch in Request-Parameter | Web Application | splunk | HIGH | 82 | `T1190` |
| `SP-500011` | API Auth-Bypass — fehlende oder manipulierte Bearer-... | Web Application | splunk | HIGH | 78 | `T1190` |
| `SP-500010` | Scanner-Erkennung — hohe Request-Rate von einer IP | Web Application | splunk | MED | 80 | `T1595.002` |
| `SP-500013` | Massenhafter 404 von einer IP — Wordlist Scan | Web Application | splunk | MED | 82 | `T1595.002` |
| | | | | | | |
| `SP-600001` | Cobalt Strike Named Pipe — Standard-Signaturen | Threat Intelligence | unknown | **CRIT** | 92 | `T1071` |
| `SP-600003` | Cobalt Strike Teamserver Default Port 50050 | Threat Intelligence | unknown | **CRIT** | 90 | `T1571` |
| `SP-600004` | Cobalt Strike Artifact Kit — Payload-Staging aus Temp | Threat Intelligence | unknown | **CRIT** | 88 | `T1055` |
| `SP-600005` | Cobalt Strike Process Injection via CreateRemoteThread | Threat Intelligence | unknown | **CRIT** | 90 | `T1055.003` |
| `SP-600007` | Cobalt Strike Jump psexec (T1570 | Threat Intelligence | unknown | **CRIT** | 92 | `T1570` |
| `SP-600012` | Cobalt Strike SMB Beacon — named pipe über SMB zu la... | Threat Intelligence | unknown | **CRIT** | 92 | `T1021.002` |
| `SP-601001` | LockBit 3.0 — VSS + bcdedit + Service-Stop Sequenz | Threat Intelligence | unknown | **CRIT** | 95 | `T1490` |
| `SP-601002` | LockBit 3.0 — Datei-Erweiterung .lockbit erkannt | Threat Intelligence | unknown | **CRIT** | 97 | `T1486` |
| `SP-601003` | LockBit 3.0 — Ransom Note Dateiname | Threat Intelligence | unknown | **CRIT** | 98 | `T1486` |
| `SP-601004` | LockBit 3.0 — AV/EDR Dienste gestoppt (bekannte Liste | Threat Intelligence | unknown | **CRIT** | 92 | `T1562.001` |
| `SP-601005` | LockBit 3.0 — cmd /c del nach Verschlüsselung (Self-... | Threat Intelligence | unknown | **CRIT** | 88 | `T1070.004` |
| `SP-601006` | BlackCat/ALPHV — Rust-Binary von /tmp oder /dev/shm ... | Threat Intelligence | unknown | **CRIT** | 80 | `T1204` |
| `SP-601007` | BlackCat/ALPHV — Erweiterung .sykffle oder .zoldon | Threat Intelligence | unknown | **CRIT** | 98 | `T1486` |
| `SP-601008` | BlackCat/ALPHV — Ransom Note RECOVER-*-FILES.txt | Threat Intelligence | unknown | **CRIT** | 98 | `T1486` |
| `SP-601009` | BlackCat — Windows Volume Shadow Copy via WMI | Threat Intelligence | unknown | **CRIT** | 90 | `T1490` |
| `SP-601010` | Ransomware-Vorstufe: Recon + Staging + Impact in 1h | Threat Intelligence | unknown | **CRIT** | 90 | `T1486 +1` |
| `SP-602013` | mavinject — Process Injection via Microsoft Tool | Threat Intelligence | unknown | **CRIT** | 92 | `T1055` |
| `SP-602020` | LOLBin Burst — 3 oder mehr verschiedene LOLBins in 1... | Threat Intelligence | unknown | **CRIT** | 92 | `T1218` |
| `SP-600002` | Cobalt Strike Default Beacon HTTP User-Agent | Threat Intelligence | unknown | HIGH | 78 | `T1071.001` |
| `SP-600006` | Cobalt Strike PPID-Spoofing — unerwarteter Parent | Threat Intelligence | unknown | HIGH | 85 | `T1134.004` |
| `SP-600008` | Cobalt Strike Malleable-C2 — HTTP URI mit zufälligem... | Threat Intelligence | unknown | HIGH | 75 | `T1071.001` |
| `SP-600009` | Cobalt Strike Token Impersonation (SeDebugPrivilege ... | Threat Intelligence | unknown | HIGH | 80 | `T1134` |
| `SP-600010` | Cobalt Strike Execute-Assembly — clr.dll in ungewöhn... | Threat Intelligence | unknown | HIGH | 82 | `T1055.004` |
| `SP-600011` | Cobalt Strike Screenshot / Keylogger via GetForegrou... | Threat Intelligence | unknown | HIGH | 78 | `T1056` |
| `SP-602001` | certutil — Download / Base64-Decode | Threat Intelligence | unknown | HIGH | 92 | `T1105` |
| `SP-602002` | bitsadmin — Download oder Transfer | Threat Intelligence | unknown | HIGH | 88 | `T1197` |
| `SP-602003` | mshta — Remote HTA Ausführung | Threat Intelligence | unknown | HIGH | 90 | `T1218.005` |
| `SP-602004` | regsvr32 — Squiblydoo (COM Scriptlet | Threat Intelligence | unknown | HIGH | 90 | `T1218.010` |
| `SP-602005` | rundll32 — Remote DLL oder JavaScript | Threat Intelligence | unknown | HIGH | 88 | `T1218.011` |
| `SP-602006` | wmic — Remote Code Execution oder Process Creation | Threat Intelligence | unknown | HIGH | 85 | `T1047` |
| `SP-602007` | cmstp — UAC-Bypass via INF | Threat Intelligence | unknown | HIGH | 88 | `T1218.003` |
| `SP-602008` | InstallUtil — Bypass Application Whitelisting | Threat Intelligence | unknown | HIGH | 88 | `T1218.004` |
| `SP-602009` | MSBuild — In-Memory Build (Code Execution | Threat Intelligence | unknown | HIGH | 85 | `T1127.001` |
| `SP-602010` | PresentationHost — XBAP Execution | Threat Intelligence | unknown | HIGH | 80 | `T1218` |
| `SP-602011` | pcalua — Proxy Execution via Application Compatibility | Threat Intelligence | unknown | HIGH | 82 | `T1218` |
| `SP-602012` | SyncAppvPublishingServer — PowerShell Bypass | Threat Intelligence | unknown | HIGH | 85 | `T1218` |
| `SP-602014` | Odbcconf — DLL Registration Proxy | Threat Intelligence | unknown | HIGH | 85 | `T1218.008` |
| `SP-602015` | Scriptrunner / Appvlp — AppLocker Bypass | Threat Intelligence | unknown | HIGH | 88 | `T1218` |
| `SP-602016` | Msiexec — Remote MSI Installation | Threat Intelligence | unknown | HIGH | 82 | `T1218.007` |
| `SP-602017` | Finger — Download via Finger Protocol | Threat Intelligence | unknown | HIGH | 85 | `T1071` |
| `SP-602018` | Desktopimgdownldr — Download via Desktop Image | Threat Intelligence | unknown | HIGH | 88 | `T1105` |
| `SP-602019` | IEExec — Internet Explorer Proxy Execution | Threat Intelligence | unknown | HIGH | 85 | `T1218` |

---

## By Platform

**Splunk** — 987 rules

## By Severity

- **CRITICAL**: 304
- **HIGH**: 606
- **MEDIUM**: 108
- **LOW**: 10

---

*Auto-generated by `tools/generate_rule_catalog.py` — do not edit manually.*
