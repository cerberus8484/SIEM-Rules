# Linux Pack

**~60 rules — Splunk + QRadar**

The Linux pack detects persistence, privilege escalation, and defense evasion
on Linux servers using auditd, syslog, and endpoint telemetry.

---

## Pack Summary

| Property | Value |
|---|---|
| Pack Directory | `linux/` |
| ID Range | SP-300001 – SP-399999 |
| Platforms | Splunk, QRadar |
| Key Sources | linux:audit, syslog, bash_history |

---

## Key Rules

| Rule ID | Name | Severity | Technique |
|---|---|---|---|
| SP-310001 | Crontab Modified by Non-Root | HIGH | T1053.003 |
| SP-310002 | Systemd Unit File Created | HIGH | T1543.002 |
| SP-310003 | SUID Binary Created | CRITICAL | T1548.001 |
| SP-310004 | Sudo Rule Modified | HIGH | T1548.003 |
| SP-310005 | /etc/passwd Edited Directly | CRITICAL | T1136.001 |
| SP-310006 | Auditd Service Stopped | CRITICAL | T1562.012 |
| SP-310007 | SSH Authorized Keys Modified | HIGH | T1098.004 |
| SP-310008 | LD_PRELOAD Set in Profile | HIGH | T1574.006 |
| SP-310009 | History File Cleared | HIGH | T1070.003 |
| SP-310010 | Kernel Module Loaded (insmod) | HIGH | T1547.006 |
| SP-310011 | /tmp Executable Created and Run | HIGH | T1059 |
| SP-310012 | Base64 Decode Pipe to Shell | HIGH | T1027 |
| SP-310013 | Reverse Shell Pattern (bash -i) | CRITICAL | T1059.004 |
| SP-310014 | NSS Library Replaced | CRITICAL | T1556.003 |
| SP-310015 | PAM Configuration Modified | CRITICAL | T1556.003 |

---

## Example: Reverse Shell Detection

```splunk-spl
`comment("
SP-310013 | Reverse Shell Pattern
tactic=Execution | technique=T1059.004
severity=CRITICAL | confidence=88
platform=splunk | status=stable | version=1.0
")`
index=linux (sourcetype=linux:audit OR sourcetype=syslog)
| where match(cmd, "(?i)bash\s+-i\s+>&\s*/dev/tcp|nc\s+-e\s+/bin/bash|python.*socket.*connect|perl.*socket.*connect")
| eval rule_id="SP-310013"
| eval tactic="Execution", technique="T1059.004"
| eval severity="CRITICAL", confidence=88
| table _time host user cmd parent_process rule_id severity confidence
```
