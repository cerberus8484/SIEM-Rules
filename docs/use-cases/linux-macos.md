# Linux & macOS

Use cases for Linux and macOS endpoint detections.

**Rule packs:** `linux`, `macos`

---

## UC-041 — Linux — Crontab Persistence {#uc-041}

**Threat:** Attacker adds a cron job to maintain persistence or schedule recurring
execution of a payload. Detectable by monitoring crontab modifications.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 72 |
| **MITRE** | T1053.003 — Scheduled Task/Job: Cron |
| **Data Sources** | Linux auditd, Syslog, Falco |
| **Rule IDs** | SP-linux-001 |

### Splunk SPL

```spl
index=linux (sourcetype="linux_audit" OR sourcetype="syslog")
| where match(_raw, "(?i)(crontab|/etc/cron\.|/var/spool/cron)")
    AND match(_raw, "(?i)(WRITE|CREATE|ADD|MODIFY|chmod|wget|curl|/tmp/|/dev/shm/|nc |ncat |bash -i)")
| rex field=_raw "user=(?P<user>\S+)"
| rex field=_raw "cmd=(?P<cmd>.+)"
| table _time, host, user, cmd
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Host",
    username AS "User",
    "Command" AS "CommandLine",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    "LogSourceType" IN ('Linux OS', 'Unix OS')
    AND (
        LOWER("Command") LIKE '%crontab -e%'
        OR LOWER("filename") LIKE '%/etc/cron%'
        OR LOWER("filename") LIKE '%/var/spool/cron%'
    )
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. List all crontabs: `crontab -l -u <user>` and `cat /etc/cron*`
2. Examine the added job — what command does it execute?
3. Check if the script/binary in the cron job is malicious
4. Remove unauthorized cron job: `crontab -r` or edit crontab manually
5. Enable auditd watches on `/etc/cron*` and `/var/spool/cron/` for ongoing monitoring

---

## UC-042 — Linux — SUID Binary Created {#uc-042}

**Threat:** Attacker creates or modifies a binary with the SUID bit set, allowing
any user to execute it with root privileges. Common privilege escalation technique.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 82 |
| **MITRE** | T1548.001 — Abuse Elevation Control Mechanism: Setuid and Setgid |
| **Data Sources** | Linux auditd |
| **Rule IDs** | SP-linux-003 |

### Splunk SPL

```spl
index=linux sourcetype="linux_audit"
| where match(_raw, "(?i)(chmod.*[+]s|chmod.*4[0-9]{3}|chmod.*2[0-9]{3})")
    OR match(_raw, "(?i)(fchmod|fchmodat).*4[0-9]{3}")
| rex field=_raw "exe=\"(?P<exe>[^\"]+)\""
| rex field=_raw "a[0-3]=\"(?P<target>[^\"]+)\""
| where NOT match(target, "(?i)(/bin/|/sbin/|/usr/bin/|/usr/sbin/)")
| table _time, host, user, exe, target
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Host",
    username AS "User",
    "process" AS "Process",
    "filename" AS "Target File",
    "Command" AS "CommandLine",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    "LogSourceType" IN ('Linux OS', 'Unix OS')
    AND QIDNAME(qid) LIKE '%chmod%'
    AND (
        LOWER("Command") LIKE '%+s%'
        OR LOWER("Command") LIKE '%4755%'
        OR LOWER("Command") LIKE '%4777%'
        OR LOWER("Command") LIKE '%2755%'
    )
    AND "filename" NOT LIKE '/bin/%'
    AND "filename" NOT LIKE '/usr/bin/%'
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. List all non-standard SUID binaries: `find / -perm /4000 -not -path "/bin/*" -not -path "/usr/*" 2>/dev/null`
2. Remove SUID bit from unauthorized binary: `chmod -s <file>`
3. Check when and by whom the binary was created/modified (`stat <file>`, `ls -la`)
4. If the binary is malicious: quarantine and analyze
5. Enable auditd rule: `-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F perm=x`

---

## UC-043 — macOS — LaunchAgent Persistence {#uc-043}

**Threat:** Attacker creates a LaunchAgent plist to execute code at user login.
macOS equivalent of Windows Run key persistence.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 75 |
| **MITRE** | T1543.001 — Create or Modify System Process: Launch Agent |
| **Data Sources** | macOS Unified Log, ESF (Endpoint Security Framework) |
| **Rule IDs** | SP-macos-001 |

### Splunk SPL

```spl
index=macos (sourcetype="macos:asl" OR sourcetype="macos:unified")
| where match(_raw, "(?i)(~/Library/LaunchAgents/|/Library/LaunchAgents/|/Library/LaunchDaemons/)")
    AND match(_raw, "(?i)(create|write|chmod|plistbuddy|defaults write)")
| rex field=_raw "path=(?P<plist_path>[^\s]+\.plist)"
| table _time, host, user, plist_path, _raw
| sort -_time
```

### QRadar AQL

```sql
SELECT
    sourceip AS "Host",
    username AS "User",
    "filename" AS "Plist Path",
    "Command" AS "CommandLine",
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events
WHERE
    "LogSourceType" = 'Apple macOS'
    AND (
        "filename" LIKE '%/Library/LaunchAgents/%'
        OR "filename" LIKE '%/Library/LaunchDaemons/%'
    )
    AND QIDNAME(qid) IN ('File Created', 'File Modified')
LAST 24 HOURS
ORDER BY starttime DESC
```

### Response Actions

1. Inspect the plist: `cat ~/Library/LaunchAgents/<name>.plist`
2. Check the `ProgramArguments` key — what binary/script does it execute?
3. Unload and remove if malicious: `launchctl unload <plist> && rm <plist>`
4. Scan the executed binary with XProtect / Malwarebytes
5. Check for similar plists across all user accounts on the machine
