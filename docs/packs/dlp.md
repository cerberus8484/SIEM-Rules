# DLP / Exfiltration Pack

**20 rules — Splunk — multi-vector exfiltration**

The DLP pack detects data exfiltration across multiple channels: DNS tunneling,
large HTTP POST to external destinations, cloud storage abuse, rclone, and
multi-vector correlation chains.

---

## Pack Summary

| Property | Value |
|---|---|
| Pack Directory | `dlp/` |
| ID Range | SP-790001 – SP-790020 |
| Platforms | Splunk |
| Rules | 20 |
| Key Sources | dns:logs, proxy:logs, dlp:alerts, netflow |
| MITRE Tactics | Exfiltration, Collection |

---

## Rule Inventory

| Rule ID | Name | Severity | Confidence | Technique |
|---|---|---|---|---|
| SP-790001 | DNS Tunneling (Long Subdomain >50 chars) | HIGH | 82 | T1071.004 |
| SP-790002 | Large HTTP POST to Non-Corporate Domain | HIGH | 78 | T1048.003 |
| SP-790003 | rclone to External Cloud Storage | CRITICAL | 92 | T1567.002 |
| SP-790004 | Mass File Access Before Termination | HIGH | 80 | T1213 |
| SP-790005 | USB Storage Write (Large Volume) | HIGH | 78 | T1052.001 |
| SP-790006 | Email Attachment with Sensitive Keywords | HIGH | 75 | T1048 |
| SP-790007 | FTP/SFTP to Personal Server | HIGH | 82 | T1048.002 |
| SP-790008 | Compression Before Exfil (zip/7z > 100MB) | HIGH | 78 | T1560.001 |
| SP-790009 | Cloud Sync Tool Installed | MEDIUM | 65 | T1567 |
| SP-790010 | Printer Spooled Large Document (No Print) | MEDIUM | 62 | T1048 |
| SP-790011 | Screenshot Tool Spawned by Script | HIGH | 78 | T1113 |
| SP-790012 | Multi-Vector Exfil Chain | CRITICAL | 88 | T1041/T1048/T1567 |
| SP-790013 | Steganography Tool Detected | HIGH | 80 | T1027.003 |
| SP-790014 | Data Staging in Temp Directory | HIGH | 75 | T1074.001 |
| SP-790015 | HTTP Range Requests Pattern (Fragmented Exfil) | HIGH | 78 | T1048.003 |
| SP-790016 | Mega.nz / Gofile Upload | HIGH | 82 | T1567.002 |
| SP-790017 | Git Push to External Repository | HIGH | 80 | T1567.001 |
| SP-790018 | DLP Policy Override by User | HIGH | 80 | T1562 |
| SP-790019 | Sensitive Data in URL Parameter | MEDIUM | 65 | T1048.003 |
| SP-790020 | Cross-Border Data Transfer (GDPR Trigger) | HIGH | 75 | T1048 |
