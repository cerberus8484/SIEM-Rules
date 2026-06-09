# Persistence — Extended

Extended persistence detection beyond UC-023–026.

**Rule packs:** `windows_sysmon`

---

## UC-176 — COM Object Hijacking {#uc-176}

**Threat:** Attacker registers a malicious COM object under `HKCU\Software\Classes\CLSID`
that overrides a legitimate HKLM CLSID. When a trusted process loads the COM object,
it executes the attacker's code under the trusted process identity.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 80 |
| **MITRE** | T1546.015 — Event Triggered Execution: Component Object Model Hijacking |
| **Data Sources** | Sysmon Event 13 (RegistryValueSet) |
| **Rule IDs** | SP-persist-001 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| where match(TargetObject,"(?i)HKCU\\Software\\Classes\\CLSID\\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}}\\InprocServer32")
    AND NOT match(User,"(?i)(SYSTEM|\$$)")
    AND NOT match(Image,"(?i)(msiexec|setup|install|Microsoft\.Installer)")
| table _time, host, User, Image, TargetObject, Details
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "TargetObject" AS "CLSID Registry Key", "Details" AS "DLL Path",
    "process" AS "Setting Process", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Registry value set'
    AND "TargetObject" LIKE '%HKCU%Classes%CLSID%InprocServer32%'
    AND username NOT LIKE '%$' AND username != 'SYSTEM'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Identify which CLSID was hijacked and which trusted process loads it
2. Inspect the DLL path in Details — check hash, signature, and origin
3. Delete the HKCU override key to restore the legitimate COM registration
4. Check for scheduled task or other trigger that loads the hijacked COM object
5. Deploy AppLocker or WDAC to restrict DLL loading paths

---

## UC-177 — Image File Execution Options (IFEO) Debugger {#uc-177}

**Threat:** Attacker sets an IFEO debugger key to hijack execution of any program.
E.g., setting debugger for `sethc.exe` (Sticky Keys) to `cmd.exe` provides a SYSTEM
shell at the login screen without credentials.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 92 |
| **MITRE** | T1546.012 — Event Triggered Execution: Image File Execution Options Injection |
| **Data Sources** | Sysmon Event 13, Windows Security 4657 |
| **Rule IDs** | SP-persist-002 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| where match(TargetObject,"(?i)SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options")
    AND match(Details,"(?i)(cmd\.exe|powershell\.exe|wscript|cscript|mshta|regsvr32)")
| table _time, host, User, TargetObject, Details
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "TargetObject" AS "IFEO Key", "Details" AS "Debugger Set",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Registry value set'
    AND "TargetObject" LIKE '%Image File Execution Options%'
    AND ("Details" LIKE '%cmd.exe%' OR "Details" LIKE '%powershell.exe%'
        OR "Details" LIKE '%wscript%' OR "Details" LIKE '%mshta%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Remove the debugger key: `reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f`
2. Audit ALL IFEO entries for unexpected debuggers: `Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*"`
3. This technique is also used by AV products — validate before removing
4. Disable accessibility feature abuse: configure Group Policy to disable Ease of Access at logon screen
5. Investigate who set the key and what else they modified

---

## UC-178 — AppCert / AppInit DLL Persistence {#uc-178}

**Threat:** AppCert DLLs are loaded into every process that calls `CreateProcess`.
AppInit_DLLs are loaded into every process that loads user32.dll. Both provide
system-wide DLL injection persistence — any process startup executes attacker code.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 88 |
| **MITRE** | T1546.009 — Event Triggered Execution: AppCert DLLs |
| **Data Sources** | Sysmon Events 13/7 |
| **Rule IDs** | SP-persist-003 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| where match(TargetObject,"(?i)(HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls|HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows.*AppInit_DLLs)")
    AND Details NOT IN ("","0")
| table _time, host, User, TargetObject, Details
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "TargetObject" AS "Registry Key", "Details" AS "DLL Value",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Registry value set'
    AND ("TargetObject" LIKE '%AppCertDlls%' OR "TargetObject" LIKE '%AppInit_DLLs%')
    AND "Details" NOT IN ('','0')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Immediately clear the value: `Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name "AppInit_DLLs" -Value ""`
2. Inspect the DLL referenced in the value
3. Check all running processes for the loaded DLL (Sysmon Event 7)
4. Disable AppInit DLLs loading: Set `LoadAppInit_DLLs` = 0
5. Note: Enable Secure Boot + ELAM to prevent AppInit_DLLs persistence

---

## UC-179 — Office Add-in Persistence {#uc-179}

**Threat:** Attacker installs a malicious Office add-in (.xla, .xlam, .ppa, .ppam, .wll)
that loads automatically when Word, Excel, or PowerPoint opens, providing persistent
macro-based execution under the user context.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 78 |
| **MITRE** | T1137.006 — Office Application Startup: Add-ins |
| **Data Sources** | Sysmon Events 11/13 |
| **Rule IDs** | SP-persist-004 |

### Splunk SPL

```spl
| union
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
     | where match(TargetFilename,"(?i)(\\AppData\\Roaming\\Microsoft\\AddIns\\|\\AppData\\Roaming\\Microsoft\\Excel\\XLSTART\\|\\AppData\\Roaming\\Microsoft\\Word\\STARTUP\\).*\.(xla|xlam|ppa|ppam|wll|dotm|dot)")
     | eval detection="Add-In File Created"]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
     | where match(TargetObject,"(?i)(HKCU.*Excel.*XLSTART|HKCU.*Word.*Startup|HKCU.*Addins.*OPEN)")
     | eval detection="Office Add-In Registry Key Set"]
| table _time, host, User, TargetFilename, TargetObject, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "filename" AS "Add-In File", QIDNAME(qid) AS "Event",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE (QIDNAME(qid) = 'Sysmon - File created' OR QIDNAME(qid) = 'Sysmon - Registry value set')
    AND ("filename" LIKE '%AddIns%.xlam%' OR "filename" LIKE '%XLSTART%.xla%'
        OR "TargetObject" LIKE '%XLSTART%' OR "TargetObject" LIKE '%Word%Startup%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Review the add-in file content — is it signed? What macros does it contain?
2. Remove the add-in file and registry key
3. Disable Office add-ins via Group Policy if not required for business
4. Enable Protected View for all externally sourced Office documents
5. Deploy Attack Surface Reduction (ASR) rule: Block Win32 API calls from Office macros

---

## UC-180 — Screensaver Executable Modified {#uc-180}

**Threat:** The screensaver binary path is replaced with a malicious executable.
The screensaver runs as the logged-on user after the timeout period — persistence
with user-level privileges that triggers when the system is idle.

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | 85 |
| **MITRE** | T1546.002 — Event Triggered Execution: Screensaver |
| **Data Sources** | Sysmon Event 13 |
| **Rule IDs** | SP-persist-005 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| where match(TargetObject,"(?i)(HKCU\\Control Panel\\Desktop\\SCRNSAVE\.EXE|HKCU\\Control Panel\\Desktop\\ScreenSaveActive)")
    AND (NOT match(Details,"(?i)(C:\\Windows\\System32\\.*\.scr)") OR Details="1")
| table _time, host, User, Image, TargetObject, Details
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "TargetObject" AS "Registry Key", "Details" AS "New Value",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - Registry value set'
    AND "TargetObject" LIKE '%SCRNSAVE.EXE%'
    AND "Details" NOT LIKE 'C:\\Windows\\System32\\%'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Examine the binary set as screensaver — hash, signature, strings
2. Reset to legitimate screensaver via registry or GPO
3. Consider disabling screensavers entirely via GPO and using screen lock timeout instead
4. Audit all machines for unexpected SCRNSAVE.EXE registry values
5. Investigate parent process that modified the registry key

---

## UC-181 — Startup Folder Drop (New Executable) {#uc-181}

**Threat:** Malware copies itself to the Windows Startup folder
(`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`) or system-wide startup
(`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\`) for persistence
that executes on every user logon.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 82 |
| **MITRE** | T1547.001 — Registry Run Keys / Startup Folder |
| **Data Sources** | Sysmon Event 11 |
| **Rule IDs** | SP-persist-006 |

### Splunk SPL

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| where match(TargetFilename,"(?i)(\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\|\\Start Menu\\Programs\\StartUp\\).*\.(exe|bat|cmd|ps1|vbs|lnk|js|hta)")
    AND NOT match(Image,"(?i)(msiexec|explorer|TrustedInstaller)")
| table _time, host, User, Image, TargetFilename
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Host", username AS "User",
    "filename" AS "Startup File", "process" AS "Creating Process",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE QIDNAME(qid) = 'Sysmon - File created'
    AND "filename" LIKE '%Start Menu%Programs%Startup%'
    AND "process" NOT IN ('msiexec.exe','TrustedInstaller.exe','explorer.exe')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Inspect the file placed in the startup folder — hash it, check signature
2. Remove from startup folder and run an endpoint AV scan
3. Check what the process does when executed
4. Monitor the startup folder via GPO to restrict write access
5. Enable Windows Defender ASR rule: Block executable content from email client and webmail
