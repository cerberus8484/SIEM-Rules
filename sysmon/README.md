# Sysmon Configurations — HuntingThreats

Scenario-based Sysmon XML configurations aligned with the SIEM rule packs.
Each config is tuned for a specific threat model — pick one based on your environment
and current hunt objective. Configs can be stacked by merging `<EventFiltering>` blocks,
but start with one and measure the event volume before adding more.

---

## Scenario Selection Matrix

| Config | Use when | Event volume | MITRE coverage |
|---|---|---|---|
| [`base-detection.xml`](#base-detectionxml) | Always-on production baseline | Low–Medium | T1059, T1547, T1053, T1543, T1055, T1003, T1490 |
| [`ransomware-precursors.xml`](#ransomware-precursorsxml) | Ransomware threat model, backup environments | Very Low | T1490, T1489, T1486, T1070 |
| [`credential-theft-lateral-movement.xml`](#credential-theft-lateral-movementxml) | Post-breach, IR investigation, AD environments | Medium | T1003, T1558, T1550, T1021, T1047 |
| [`initial-access-execution.xml`](#initial-access-executionxml) | Phishing-heavy environments, user workstations | Medium | T1566, T1204, T1059, T1218, T1105 |
| [`threat-hunting-full.xml`](#threat-hunting-fullxml) | Active threat hunt, honeypots, IR nodes | High | All tactics |

---

## Quick Start

### Install Sysmon (first time)

```powershell
# Download Sysmon from Microsoft Sysinternals
# https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

# Install with a config
sysmon64.exe -accepteula -i base-detection.xml

# Verify installation
Get-Service Sysmon64
```

### Update an existing config

```powershell
sysmon64.exe -c sysmon\base-detection.xml
```

### Uninstall

```powershell
sysmon64.exe -u
```

### View current schema

```powershell
sysmon64.exe -s
```

### Check events (PowerShell)

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Select-Object -First 20 |
  Format-List TimeCreated, Id, Message
```

---

## Config Reference

### `base-detection.xml`

**Scenario:** Always-on production baseline. Balanced signal-to-noise ratio.

**Use for:** Any environment as the default config. Start here.

**Events covered:**
| Event | Description |
|---|---|
| 1 — ProcessCreate | Suspicious process chains, excludes Windows noise |
| 3 — NetworkConnect | Scripting engines + suspicious ports (4444, 31337, 50050, ...) |
| 7 — ImageLoad | Unsigned DLLs in LSASS + winlogon |
| 8 — CreateRemoteThread | All (low volume, high signal) |
| 10 — ProcessAccess | LSASS access |
| 11 — FileCreate | Suspicious extensions + user/temp locations |
| 12/13 — RegistryEvent | Autostart, services, AMSI, LSA, scheduled tasks |
| 19/20/21 — WmiEvent | All WMI subscriptions |
| 22 — DnsQuery | All (excludes Microsoft CDN) |

**SIEM packs:** All packs (general baseline)

---

### `ransomware-precursors.xml`

**Scenario:** Ransomware pre-encryption kill chain detection.

**Use for:** Any environment with backup infrastructure, especially if running
Veeam, Windows Backup, or SQL Server. This config is intentionally narrow —
every event it generates should be investigated.

**Events covered:**
| Event | Description |
|---|---|
| 1 — ProcessCreate | VSS deletion, bcdedit recovery disable, backup service kill, wbadmin, cipher |
| 11 — FileCreate | Ransom notes (HOW_TO_DECRYPT, README_DECRYPT, ...) + 20 ransomware extensions |
| 13 — RegistryEvent | Boot recovery keys (BCD, RecoveryEnabled, BootStatusPolicy), VSS service |
| 22 — DnsQuery | Tor .onion resolvers + tor2web proxies |

**SIEM packs:** `backup-resilience` (SP-730001–SP-730020), `correlation` (SP-810019 Backup Wiper Chain)

**Note:** This config pairs with correlation rule SP-810019 which scores multi-stage
ransomware precursor chains and escalates when 3+ indicators fire within 10 minutes.

---

### `credential-theft-lateral-movement.xml`

**Scenario:** Post-compromise credential harvesting and lateral movement.

**Use for:** Domain controllers, file servers, Active Directory environments.
Deploy during IR investigations or when a compromised account is suspected.

**Events covered:**
| Event | Description |
|---|---|
| 1 — ProcessCreate | Mimikatz, procdump+lsass, comsvcs MiniDump, ntdsutil, secretsdump, PsExec, WMI remote, Rubeus, Kerberoast, reg save SAM/SECURITY |
| 3 — NetworkConnect | SMB (445/139), WMI (135), RDP (3389), WinRM (5985/5986) |
| 8 — CreateRemoteThread | All (excludes browsers + Defender) |
| 10 — ProcessAccess | LSASS access (excludes query-only masks 0x1000, 0x100000, 0x0400) |
| 11 — FileCreate | .dmp/.mdmp files, ntds.dit, SAM/SECURITY/SYSTEM, .kirbi tickets |
| 17/18 — PipeEvent | Named pipes: PSEXESVC, mimikatz, Cobalt Strike defaults, Meterpreter, Empire, RemCom |

**SIEM packs:** `credential_access`, `lateral_movement`, `identity`

**Tune per environment:** Add your EDR agent path to the ProcessAccess exclusion block.

---

### `initial-access-execution.xml`

**Scenario:** Entry point detection — phishing, Office macros, LOLBins, download cradles.

**Use for:** User workstations, email gateway endpoints. Critical for environments
with heavy Office usage where macro-enabled documents are expected.

**Events covered:**
| Event | Description |
|---|---|
| 1 — ProcessCreate | Office spawning shells, encoded PowerShell (-EncodedCommand/-enc/IEX), certutil/bitsadmin download cradles, mshta, regsvr32/scrobj, wscript/cscript from AppData/Temp, rundll32 with HTTP, InstallUtil, Add-Type, wmic process call create |
| 3 — NetworkConnect | Office apps + scripting engines (wscript/cscript/mshta/regsvr32/certutil/bitsadmin/InstallUtil) making outbound connections |
| 11 — FileCreate | Executables/scripts dropped outside Program Files and Windows directories |
| 22 — DnsQuery | Subdomains > 50 chars (DGA/tunneling), .onion resolvers |

**SIEM packs:** `execution`, `initial_access`

**Note:** Generates moderate noise on developer machines (npm scripts, build tools).
Add exceptions for known build tools in the ProcessCreate exclude block.

---

### `threat-hunting-full.xml`

**Scenario:** Comprehensive event collection for active threat hunting.

**Use for:**
- Dedicated threat hunting nodes / honeypots
- IR investigations (temporary deployment — max 72h in production)
- Lab environments and detection research
- SOC Tier 3 hunt operations

**⚠️ Warning:** High event volume. Do not deploy permanently in large production
environments without SIEM-side filtering. Measure events/minute with `Get-WinEvent`
before routing to your SIEM.

**Events covered (ALL Sysmon event types):**
| Event | Description |
|---|---|
| 1 — ProcessCreate | All (minimal noise exclusions) |
| 2 — FileCreateTime | All — timestomping (T1070.006) |
| 3 — NetworkConnect | All outbound (excludes svchost, lsass, loopback, port 53) |
| 5 — ProcessTerminate | All (short-lived process detection) |
| 6 — DriverLoad | All unsigned drivers (T1543.003, T1547.006) |
| 7 — ImageLoad | All unsigned DLLs (T1055, T1574) |
| 8 — CreateRemoteThread | All (excludes Defender only) |
| 9 — RawAccessRead | All (excludes svchost, Defender, defrag) — T1006 |
| 10 — ProcessAccess | All (excludes svchost, wininit, masks 0x1000/0x100000) |
| 11 — FileCreate | All (minimal noise exclusions) |
| 12/13/14 — RegistryEvent | Full persistence key coverage |
| 15 — FileCreateStreamHash | ADS — all except Zone.Identifier (T1564.004) |
| 17/18 — PipeEvent | All except standard Windows system pipes |
| 19/20/21 — WmiEvent | All |
| 22 — DnsQuery | All (excludes Microsoft/Akamai CDN) |
| 23 — FileDelete | Executable and script deletions (T1070.004) |
| 25 — ProcessTampering | All — Herpaderping, Ghosting, Hollowing (T1055) |

**Measure event volume before deploying to SIEM:**

```powershell
# Count events per minute after deployment (wait 5 minutes)
$start = (Get-Date).AddMinutes(-5)
$events = Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    StartTime = $start
}
Write-Host "Events in last 5 min: $($events.Count)"
Write-Host "Events per minute: $([math]::Round($events.Count / 5, 0))"
```

---

## SIEM Pack Correlation

| Config | Primary packs | Rule IDs |
|---|---|---|
| `base-detection.xml` | All | SP-100xxx through SP-810xxx |
| `ransomware-precursors.xml` | backup-resilience, correlation | SP-730001–SP-730020, SP-810019 |
| `credential-theft-lateral-movement.xml` | credential_access, lateral_movement, identity | SP-200xxx, SP-300xxx, SP-500xxx |
| `initial-access-execution.xml` | execution, initial_access | SP-100xxx, SP-initial_access-xxx |
| `threat-hunting-full.xml` | All | All packs |

---

## Combining Configs

When running an IR investigation, combine the lateral movement + ransomware configs
by merging their `<EventFiltering>` blocks:

```xml
<!-- Example: IR config = credential-theft + ransomware-precursors -->
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256,MD5,IMPHASH</HashAlgorithms>
  <CheckRevocation/>
  <EventFiltering>
    <!-- Paste all RuleGroups from credential-theft-lateral-movement.xml -->
    <!-- Paste all RuleGroups from ransomware-precursors.xml -->
  </EventFiltering>
</Sysmon>
```

Rule group names are unique across configs — no conflicts.

---

## Tuning Guide

### Too many false positives in ProcessCreate?
Add the path to the exclude block:
```xml
<ProcessCreate onmatch="exclude">
  <Image condition="begin with">C:\Program Files\YourTool\</Image>
</ProcessCreate>
```

### Too many false positives in ProcessAccess (LSASS)?
Add your EDR/AV agent to the exclude block:
```xml
<ProcessAccess onmatch="exclude">
  <SourceImage condition="begin with">C:\Program Files\CrowdStrike\</SourceImage>
</ProcessAccess>
```

### NetworkConnect firing on known-good remote management?
Exclude by destination IP range (WinRM internal range):
```xml
<NetworkConnect onmatch="exclude">
  <DestinationIp condition="begin with">10.0.0.</DestinationIp>
</NetworkConnect>
```

---

## Reference

- [Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK](https://attack.mitre.org)
- [SIEM-Rules coverage matrix](../COVERAGE.md)
