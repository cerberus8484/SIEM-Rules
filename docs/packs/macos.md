# macOS Pack

**20 rules — Splunk — LaunchAgent, TCC, Gatekeeper**

The macOS pack detects persistence, privilege escalation, and defense evasion
specific to macOS environments using ESF (Endpoint Security Framework) and
Unified Log telemetry.

---

## Pack Summary

| Property | Value |
|---|---|
| Pack Directory | `macos/` |
| ID Range | SP-780001 – SP-780020 |
| Platforms | Splunk |
| Rules | 20 |
| Key Sources | macos:unified_log, macos:esf |
| MITRE Tactics | Persistence, Privilege Escalation, Defense Evasion |

---

## Rule Inventory

| Rule ID | Name | Severity | Confidence | Technique |
|---|---|---|---|---|
| SP-780001 | LaunchAgent Created in User Domain | HIGH | 82 | T1543.001 |
| SP-780002 | LaunchDaemon Created (System-Wide) | CRITICAL | 90 | T1543.004 |
| SP-780003 | TCC Database Modified Directly | CRITICAL | 92 | T1548 |
| SP-780004 | Gatekeeper Disabled (spctl --master-disable) | CRITICAL | 95 | T1553.001 |
| SP-780005 | SIP (System Integrity Protection) Disabled | CRITICAL | 95 | T1562.010 |
| SP-780006 | DYLD_INSERT_LIBRARIES Set | HIGH | 82 | T1574.006 |
| SP-780007 | Cron Job Created via crontab | HIGH | 78 | T1053.003 |
| SP-780008 | Login Item Added via AppleScript | HIGH | 80 | T1547.015 |
| SP-780009 | osascript Executing Remote URL | CRITICAL | 88 | T1059.002 |
| SP-780010 | Bash Profile (.bash_profile) Modified | HIGH | 78 | T1546.004 |
| SP-780011 | Sudo Timestamp Extended | HIGH | 80 | T1548.003 |
| SP-780012 | Kernel Extension (kext) Loaded | CRITICAL | 88 | T1547.006 |
| SP-780013 | XPC Service Planted | HIGH | 82 | T1543 |
| SP-780014 | Screenshot/Microphone Permission Granted | HIGH | 78 | T1125 |
| SP-780015 | Homebrew Package with Post-Install Script | MEDIUM | 65 | T1195.001 |
| SP-780016 | Dock Application Modified | MEDIUM | 62 | T1547 |
| SP-780017 | Login Window Agent Modified | CRITICAL | 90 | T1547 |
| SP-780018 | Remote Management (ARD) Enabled | HIGH | 80 | T1021.005 |
| SP-780019 | Finder Extension Injected | HIGH | 82 | T1546 |
| SP-780020 | Transparent Proxy Config Modified | HIGH | 78 | T1090 |
