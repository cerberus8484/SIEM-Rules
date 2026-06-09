# Linux & macOS Security — Extended

Extended Linux and macOS threat detection beyond UC-041–043.

**Rule packs:** `linux`, `macos`

---

## UC-121 — Sudoers File Modified {#uc-121}

**Threat:** Attacker modifies `/etc/sudoers` or drops a file in `/etc/sudoers.d/` to grant
themselves persistent root access. This is a stealthy persistence mechanism that survives
user password resets.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 92 |
| **MITRE** | T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching |
| **Data Sources** | Linux auditd, inotify logs |
| **Rule IDs** | SP-linux-004 |

### Splunk SPL

```spl
index=linux sourcetype IN ("linux_audit","syslog","auditd")
| where match(_raw,"(?i)(SYSCALL.*openat.*sudoers|write.*\/etc\/sudoers|/etc/sudoers\.d/)")
    OR match(_raw,"(?i)(execve.*visudo|echo.*sudoers|tee.*sudoers|sed.*sudoers)")
| table _time, host, user, _raw
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "Message" AS "Audit Event", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Linux OS'
    AND ("Message" LIKE '%/etc/sudoers%'
        OR "Message" LIKE '%sudoers.d%')
    AND ("Message" LIKE '%WRITE%' OR "Message" LIKE '%CREATE%'
        OR "Message" LIKE '%execve%visudo%')
    AND username NOT IN ('root','ansible','puppet')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Review current sudoers contents: `visudo -c && cat /etc/sudoers && ls /etc/sudoers.d/`
2. Remove unauthorized NOPASSWD entries
3. Check file ownership and modification time: `stat /etc/sudoers`
4. Check git history or backup to identify what changed
5. Consider using `sudo` with a centralized identity provider (LDAP, FreeIPA, Active Directory)

---

## UC-122 — SSH Authorized Keys Modified {#uc-122}

**Threat:** Attacker adds their public key to `~/.ssh/authorized_keys` on a compromised host
to maintain persistent SSH access that survives password changes.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 90 |
| **MITRE** | T1098.004 — Account Manipulation: SSH Authorized Keys |
| **Data Sources** | Linux auditd, file integrity monitoring |
| **Rule IDs** | SP-linux-005 |

### Splunk SPL

```spl
index=linux sourcetype IN ("linux_audit","auditd","syslog")
| where match(_raw,"(?i)(authorized_keys|authorized_keys2)")
    AND match(_raw,"(?i)(SYSCALL.*write|SYSCALL.*openat|OPEN.*W_OK|CREATE)")
    AND NOT match(_raw,"(?i)(ansible|puppet|chef)")
| table _time, host, user, _raw
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "filename" AS "File Modified", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Linux OS'
    AND ("filename" LIKE '%authorized_keys%' OR "filename" LIKE '%authorized_keys2%')
    AND ("Message" LIKE '%WRITE%' OR "Message" LIKE '%CREATE%')
    AND username NOT IN ('ansible','puppet','root-provisioner')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Review the current contents of the authorized_keys file
2. Remove unauthorized keys
3. Check the SSH daemon configuration: `sshd_config` — `AuthorizedKeysFile` directive
4. Force all SSH connections to use a certificate authority (OpenSSH CA) instead of individual keys
5. Enable file integrity monitoring (FIM) on all `~/.ssh/` directories

---

## UC-123 — LD_PRELOAD Injection {#uc-123}

**Threat:** Attacker sets `LD_PRELOAD` to inject a malicious shared library into
any subsequently executed process. The injected library can intercept functions like
`getuid()`, `strcmp()`, or libc functions to hide activity or steal credentials.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 85 |
| **MITRE** | T1574.006 — Hijack Execution Flow: LD_PRELOAD |
| **Data Sources** | Linux auditd, process audit |
| **Rule IDs** | SP-linux-006 |

### Splunk SPL

```spl
index=linux sourcetype IN ("linux_audit","auditd","syslog")
| where match(_raw,"(?i)(LD_PRELOAD|LD_LIBRARY_PATH.*\/tmp|LD_LIBRARY_PATH.*\/dev\/shm)")
    OR (match(_raw,"(?i)execve") AND match(_raw,"(?i)LD_PRELOAD"))
| table _time, host, user, _raw
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "Command" AS "Command", "EnvironmentVars" AS "Env",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Linux OS'
    AND ("EnvironmentVars" LIKE '%LD_PRELOAD%'
        OR "Message" LIKE '%LD_PRELOAD%')
    AND username NOT IN ('root','oracle','www-data')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Identify the library being preloaded — inspect and hash it
2. Check for persistence in `/etc/ld.so.preload` (system-wide LD_PRELOAD)
3. LD_PRELOAD from temporary directories (/tmp, /dev/shm) is extremely suspicious
4. Remove the malicious library and clean up any persistence mechanism
5. Consider restricting `LD_PRELOAD` usage via SELinux/AppArmor policy

---

## UC-124 — /etc/passwd or /etc/shadow Modified {#uc-124}

**Threat:** Direct modification of `/etc/passwd` or `/etc/shadow` to add a root-level
account or change a password hash — stealthy backdoor persistence.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 93 |
| **MITRE** | T1136.001 — Create Account: Local Account |
| **Data Sources** | Linux auditd, file integrity monitoring |
| **Rule IDs** | SP-linux-007 |

### Splunk SPL

```spl
index=linux sourcetype IN ("linux_audit","auditd")
| where match(_raw,"(?i)(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow)")
    AND match(_raw,"(?i)(SYSCALL.*write|CREATE|OPEN.*W_OK)")
    AND NOT match(_raw,"(?i)(passwd\.lock|shadow\.lock|/etc/passwd-|/etc/shadow-)")
| table _time, host, user, _raw
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "filename" AS "File", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Linux OS'
    AND ("filename" IN ('/etc/passwd','/etc/shadow','/etc/group','/etc/gshadow'))
    AND ("Message" LIKE '%WRITE%' OR "Message" LIKE '%CREATE%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Immediately review `/etc/passwd` for any new UID 0 accounts or unexpected entries
2. Compare against known-good baseline (from configuration management)
3. Check `/etc/shadow` — were any password hashes changed?
4. Consider centralizing authentication (LDAP, FreeIPA) to eliminate local account management
5. Enable immutable flag: `chattr +i /etc/passwd /etc/shadow` (prevents modification without root override)

---

## UC-125 — Potential Rootkit Indicators on Linux {#uc-125}

**Threat:** Rootkits hide processes, files, or network connections at the kernel level.
Indicators include discrepancies between `ps` and `/proc`, hidden modules, or syscall table hooks.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 80 |
| **MITRE** | T1014 — Rootkit |
| **Data Sources** | Linux auditd, rkhunter/chkrootkit logs, process monitoring |
| **Rule IDs** | SP-linux-008 |

### Splunk SPL

```spl
index=linux sourcetype IN ("syslog","linux_audit","rkhunter")
| where match(_raw,"(?i)(rkhunter.*WARNING|chkrootkit.*INFECTED|rootkit.*found|hidden.*process|hidden.*file|LKM.*hidden|insmod.*\/tmp|modprobe.*suspicious)")
    OR match(_raw,"(?i)(syscall.*table.*hooked|kernel.*module.*suspicious)")
| table _time, host, _raw
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", "Message" AS "Rootkit Alert",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Linux OS'
    AND (LOWER("Message") LIKE '%rootkit%'
        OR LOWER("Message") LIKE '%rkhunter%warning%'
        OR LOWER("Message") LIKE '%hidden process%'
        OR LOWER("Message") LIKE '%chkrootkit%infected%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. **Do not trust any output from the compromised host** — attacker may have tampered with tools
2. Boot from a live CD/USB and run rkhunter, chkrootkit, and AIDE from trusted media
3. Compare kernel module list from trusted media vs. live system
4. Forensic image the disk before any remediation
5. Rebuild the host from scratch — rootkits generally cannot be cleanly removed

---

## UC-126 — macOS TCC Database Modified {#uc-126}

**Threat:** Transparency, Consent, and Control (TCC) database controls app permissions
(camera, microphone, screen recording, Files access). Attackers modify TCC.db to grant
themselves these permissions without user consent.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 85 |
| **MITRE** | T1548 — Abuse Elevation Control Mechanism |
| **Data Sources** | macOS Unified Log, Endpoint Security Framework |
| **Rule IDs** | SP-macos-002 |

### Splunk SPL

```spl
index=macos sourcetype IN ("macos:unifiedlog","macos:esf")
| where match(_raw,"(?i)(TCC\.db|TCC/TCC\.db|tccd|transparency.*consent.*control)")
    AND match(_raw,"(?i)(write|modify|chmod|chown|sqlite3.*TCC)")
    AND NOT match(process,"(?i)(tccd|SecurityAgent|SystemUIServer|com\.apple\.tcc)")
| table _time, host, user, process, _raw
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "process" AS "Process", "filename" AS "File",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Apple macOS'
    AND ("filename" LIKE '%TCC.db%' OR "filename" LIKE '%TCC/TCC%')
    AND "process" NOT IN ('tccd','SecurityAgent','SystemUIServer')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Review the TCC database for unauthorized permission grants
2. Run `tccutil reset All` to revoke all TCC permissions for suspicious apps
3. Check what app was granted permissions and whether it's known-malicious
4. Consider enabling System Integrity Protection (SIP) to protect TCC.db
5. Deploy macOS EDR (Jamf Protect, CrowdStrike Falcon for Mac) for TCC monitoring

---

## UC-127 — macOS Login Items / LaunchAgent Added (Non-Apple) {#uc-127}

**Threat:** Malware installs a persistent LaunchAgent or adds itself to Login Items
to survive reboots. Any non-Apple, non-known-vendor LaunchAgent in ~/Library/LaunchAgents
deserves investigation.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 78 |
| **MITRE** | T1543.001 — Create or Modify System Process: Launch Agent |
| **Data Sources** | macOS Unified Log, Endpoint Security Framework |
| **Rule IDs** | SP-macos-003 |

### Splunk SPL

```spl
index=macos sourcetype IN ("macos:unifiedlog","macos:esf")
| where match(filename,"(?i)(~/Library/LaunchAgents/|/Library/LaunchAgents/|/Library/LaunchDaemons/)")
    AND match(_raw,"(?i)(CREATE|WRITE|com\.(?!apple|google|microsoft|adobe|zoom|slack))")
    AND NOT match(process,"(?i)(ManagedClient|mdmclient|jamf|sophos|crowdstrike)")
| table _time, host, user, process, filename
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "process" AS "Installing Process", "filename" AS "LaunchAgent File",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Apple macOS'
    AND ("filename" LIKE '%Library/LaunchAgents%' OR "filename" LIKE '%Library/LaunchDaemons%')
    AND "process" NOT IN ('ManagedClient','mdmclient','jamf','com.apple.installer')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Inspect the plist file: `plutil -p ~/Library/LaunchAgents/<suspicious>.plist`
2. Identify the binary it points to — is it signed? Hash it on VirusTotal
3. Remove the LaunchAgent and any associated binary
4. Use `launchctl list | grep -v com.apple` to see all active user agents
5. Enable macOS Gatekeeper + notarization requirement to prevent unsigned code execution

---

## UC-128 — Gatekeeper Disabled on macOS {#uc-128}

**Threat:** Attacker or user disables macOS Gatekeeper to allow unsigned/unnotarized
apps to run. This removes a key defense against unverified code execution.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 88 |
| **MITRE** | T1553.001 — Subvert Trust Controls: Gatekeeper Bypass |
| **Data Sources** | macOS Unified Log, process audit |
| **Rule IDs** | SP-macos-004 |

### Splunk SPL

```spl
index=macos sourcetype IN ("macos:unifiedlog","macos:esf","syslog")
| where match(_raw,"(?i)(spctl.*--master-disable|defaults write com\.apple\.LaunchServices LSQuarantine -bool NO|sudo.*spctl.*disable)")
| table _time, host, user, _raw
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "Command" AS "Command", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Apple macOS'
    AND (LOWER("Command") LIKE '%spctl%master-disable%'
        OR LOWER("Command") LIKE '%lsquarantine%false%'
        OR LOWER("Command") LIKE '%spctl%disable%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Re-enable Gatekeeper: `sudo spctl --master-enable`
2. Investigate why it was disabled — was it for a specific unsigned application?
3. Check what was installed/executed after Gatekeeper was disabled
4. Enforce Gatekeeper state via MDM policy (Jamf, Mosyle)
5. Require all corporate software to be notarized by Apple

---

## UC-129 — Linux Reverse Shell via Bash/Python/Perl {#uc-129}

**Threat:** Attacker executes a reverse shell to establish a command channel back to
their infrastructure. Common patterns: bash -i >& /dev/tcp/..., python -c socket.connect(),
perl -e use Socket.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 88 |
| **MITRE** | T1059.004 — Command and Scripting Interpreter: Unix Shell |
| **Data Sources** | Linux auditd, process audit |
| **Rule IDs** | SP-linux-009 |

### Splunk SPL

```spl
index=linux sourcetype IN ("linux_audit","auditd","syslog")
| where match(_raw,"(?i)(bash.*-i.*>.*&.*\/dev\/tcp|python.*socket\.connect|perl.*use\s+Socket|ruby.*TCPSocket|nc.*-e.*\/bin\/(ba)?sh)")
    OR match(_raw,"(?i)(sh.*-i.*>.*\/dev\/tcp|\/dev\/tcp\/[0-9]|exec\s+[0-9]<>\/dev\/tcp)")
| table _time, host, user, _raw
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "Command" AS "Command", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Linux OS'
    AND (LOWER("Command") LIKE '%/dev/tcp/%'
        OR (LOWER("Command") LIKE '%python%' AND LOWER("Command") LIKE '%socket.connect%')
        OR (LOWER("Command") LIKE '%perl%' AND LOWER("Command") LIKE '%use socket%')
        OR LOWER("Command") LIKE '%bash -i%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Trace the parent process — how was the reverse shell triggered? (web shell, cron, service?)
2. Block the external connection destination at the firewall
3. Isolate the host immediately — active C2 communication
4. Review all bash_history, auth.log, web server access logs
5. Determine initial access vector (web exploitation, credential attack, supply chain)

---

## UC-130 — Cron Job Added as Root on Linux {#uc-130}

**Threat:** Attacker adds a cron job running as root to maintain persistent execution.
Root crons in `/etc/cron.d/`, `/etc/crontab`, or direct edit of `/var/spool/cron/crontabs/root`
provide highly privileged, time-based persistence.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 82 |
| **MITRE** | T1053.003 — Scheduled Task/Job: Cron |
| **Data Sources** | Linux auditd, file integrity monitoring |
| **Rule IDs** | SP-linux-010 |

### Splunk SPL

```spl
index=linux sourcetype IN ("linux_audit","auditd")
| where match(_raw,"(?i)(/etc/cron\.d|/etc/crontab|/var/spool/cron/crontabs/root|/etc/cron\.hourly|/etc/cron\.daily)")
    AND match(_raw,"(?i)(SYSCALL.*write|CREATE|OPEN.*W_OK)")
    AND NOT match(_raw,"(?i)(anacron|cron.*backup|logrotate|apt)")
| table _time, host, user, _raw
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "filename" AS "Cron File", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'Linux OS'
    AND ("filename" LIKE '%/etc/cron%' OR "filename" LIKE '%/var/spool/cron%')
    AND ("Message" LIKE '%WRITE%' OR "Message" LIKE '%CREATE%')
    AND username NOT IN ('root-provisioner','ansible','crond')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Review the new cron entry: `crontab -l -u root` and `/etc/cron.d/`
2. Identify what command the cron runs
3. Remove the unauthorized cron entry
4. Consider implementing AIDE or Tripwire FIM on all cron directories
5. Audit all existing cron jobs for suspicious entries: `grep -r . /etc/cron* /var/spool/cron/`
