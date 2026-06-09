# DevOps & CI/CD Security

Use cases for detecting supply chain attacks, secret exposure, and pipeline abuse.

**Rule packs:** `devops_cicd`

---

## UC-131 — Hardcoded Secret Pushed to Git Repository {#uc-131}

**Threat:** Developer accidentally (or maliciously) commits an API key, password, or
private key directly to source code. Once pushed, the secret is permanently in git history
even if later removed.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 92 |
| **MITRE** | T1552.001 — Unsecured Credentials: Credentials in Files |
| **Data Sources** | GitHub/GitLab Webhook events, SAST/secret scanning |
| **Rule IDs** | SP-cicd-001 |

### Splunk SPL

```spl
index=github OR index=gitlab sourcetype IN ("github:webhooks","gitlab:events")
| where match(_raw,"(?i)(secret.*pushed|secret_scanning_alert|gitleaks|trufflehog)")
    OR (eventType="push" AND match(commit.message,"(?i)(password|api.?key|secret|token|private.?key|credentials)"))
| table _time, repository.full_name, pusher.name, commit.id, commit.message
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Developer", "repository" AS "Repository",
    "commitId" AS "Commit", "alertType" AS "Secret Type",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" IN ('GitHub','GitLab')
    AND ("eventType" = 'secret_scanning_alert'
        OR LOWER("Message") LIKE '%hardcoded%'
        OR LOWER("Message") LIKE '%api key%committed%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Rotate the exposed secret immediately — assume it has been harvested
2. Remove the secret from git history: `git filter-branch` or BFG Repo Cleaner
3. Enable GitHub/GitLab secret scanning and push protection on all repositories
4. Send the exposed secret hash to `api.github.com/repos/{owner}/{repo}/secret-scanning/alerts`
5. Implement pre-commit hooks (detect-secrets, gitleaks) to prevent future incidents

---

## UC-132 — Malicious Package Installed via npm/pip {#uc-132}

**Threat:** Developer or build pipeline installs a malicious package
(typosquatting, dependency confusion, compromised package) that runs code at install time.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 80 |
| **MITRE** | T1195.001 — Supply Chain Compromise: Compromise Software Dependencies |
| **Data Sources** | Build server logs, npm/pip audit logs, Sysmon Event 1 |
| **Rule IDs** | SP-cicd-002 |

### Splunk SPL

```spl
| union
    [search index=cicd OR index=build sourcetype IN ("jenkins","github_actions","gitlab_ci")
     | where match(_raw,"(?i)(npm install|pip install|yarn add|poetry add)")
         AND match(_raw,"(?i)(postinstall.*curl|postinstall.*wget|postinstall.*bash|postinstall.*python -c)")
     | eval detection="Suspicious postinstall Hook"]
    [search index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
     | where match(Image,"(?i)(node\.exe|python\.exe|pip\.exe)")
         AND Initiated="true"
         AND NOT match(DestinationIp,"(?i)^(10\.|192\.168\.|127\.)")
     | bucket _time span=5m
     | stats count, dc(DestinationIp) as UniqueIPs by Image, host, _time
     | where UniqueIPs >= 3
     | eval detection="Package Manager Beaconing"]
| table _time, host, user, detection, _raw
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Build Server", username AS "User",
    "PackageName" AS "Package", "Command" AS "Install Command",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" IN ('Jenkins','GitHub Actions','GitLab CI')
    AND (LOWER("Command") LIKE '%postinstall%curl%'
        OR LOWER("Command") LIKE '%postinstall%wget%'
        OR LOWER("Command") LIKE '%postinstall%bash%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Identify the package and check if it's in `npm audit` / `pip audit` results
2. Check if the postinstall script made network connections or dropped files
3. Quarantine the build environment and rotate any credentials accessible there
4. Enable private registry with package allowlists (Artifactory, Azure Artifacts)
5. Implement `npm install --ignore-scripts` for untrusted packages

---

## UC-133 — GitHub Actions Secret Exfiltration {#uc-133}

**Threat:** Malicious workflow or compromised action exfiltrates GitHub Actions secrets
(via curl to external URL, printenv, or echoing to logs). Secrets should never appear
in workflow logs.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 88 |
| **MITRE** | T1552 — Unsecured Credentials |
| **Data Sources** | GitHub Audit Log, GitHub Actions workflow logs |
| **Rule IDs** | SP-cicd-003 |

### Splunk SPL

```spl
index=github sourcetype="github:audit"
| where action IN ("workflows.created","workflows.updated")
    AND match(_raw,"(?i)(curl.*secrets|echo.*secrets|env.*TOKEN|printenv.*SECRET|wget.*secrets)")
| table _time, actor, org, repo, action, _raw
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Actor", "repository" AS "Repo",
    "workflow" AS "Workflow", "Message" AS "Suspicious Step",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'GitHub'
    AND ("action" = 'workflows.created' OR "action" = 'workflows.updated')
    AND (LOWER("Message") LIKE '%curl%secrets%'
        OR LOWER("Message") LIKE '%echo%secrets%'
        OR LOWER("Message") LIKE '%printenv%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Rotate all GitHub Actions secrets in the affected repository immediately
2. Review the workflow file for the exfiltration logic
3. Check the outbound connection destination for threat intelligence
4. Enable GitHub Actions secret masking — secrets should never appear in logs
5. Restrict workflow permissions to minimum required (read-only by default)

---

## UC-134 — Pipeline Injection via Untrusted Input {#uc-134}

**Threat:** CI/CD pipeline executes untrusted user-controlled input (e.g., PR branch name,
commit message, issue title) directly in a shell step — enabling code injection.
Common in GitHub Actions `${{ github.event.issue.title }}` patterns.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 80 |
| **MITRE** | T1059 — Command and Scripting Interpreter |
| **Data Sources** | GitHub Audit Log, CI/CD workflow logs |
| **Rule IDs** | SP-cicd-004 |

### Splunk SPL

```spl
index=github sourcetype="github:webhooks"
| where eventType IN ("pull_request","issues","push")
| where match(head_commit.message,"(?i)(\$\(|`.*`|&&|;|>.*\/etc\/|curl.*\|.*sh|wget.*\|.*bash)")
    OR match(pull_request.head.ref,"(?i)(\$\(|`|&&|;|>\/|curl|wget)")
| table _time, repository.full_name, sender.login, head_commit.message, pull_request.head.ref
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "User", "repository" AS "Repo",
    "branchName" AS "Branch/Input", "commitMessage" AS "Message",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'GitHub'
    AND ("branchName" LIKE '%$(%' OR "branchName" LIKE '%`%'
        OR "commitMessage" LIKE '%;%curl%' OR "commitMessage" LIKE '%&&%wget%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Never interpolate untrusted GitHub context directly into shell commands
2. Use `${{ toJSON(github.event.issue.title) }}` as an environment variable, never inline
3. Set `permissions: read-all` at the workflow level
4. Review affected workflow runs for signs of successful injection
5. Require code review for all workflow file changes (`.github/workflows/**`)

---

## UC-135 — Unverified Docker Image Used in Production Build {#uc-135}

**Threat:** Production build pipeline uses a Docker image from an untrusted, unverified,
or outdated source. Compromised base images can include backdoors or cryptominers.

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | 75 |
| **MITRE** | T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain |
| **Data Sources** | Docker daemon logs, CI/CD build logs, registry audit |
| **Rule IDs** | SP-cicd-005 |

### Splunk SPL

```spl
index=docker OR index=cicd sourcetype IN ("docker:daemon","jenkins","github_actions")
| where match(_raw,"(?i)(FROM\s+(?!your-registry|gcr\.io|mcr\.microsoft|registry\.redhat)[a-zA-Z0-9]+)")
    AND match(_raw,"(?i)(FROM.*:latest|FROM.*:master|pull.*:latest)")
| table _time, host, user, _raw
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Build Host", username AS "User",
    "imageName" AS "Docker Image", "imageTag" AS "Tag",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" IN ('Docker','Jenkins','GitHub Actions')
    AND "imageTag" IN ('latest','master','main')
    AND "imageName" NOT LIKE 'your-registry.io/%'
    AND "imageName" NOT LIKE 'gcr.io/%'
    AND "imageName" NOT LIKE 'mcr.microsoft.com/%'
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Pin all Docker images to specific digest (SHA256), never use `:latest`
2. Scan images with Trivy or Snyk before use: `trivy image <image>:<tag>`
3. Use only images from approved private registry
4. Enable Docker Content Trust (DCT): `DOCKER_CONTENT_TRUST=1`
5. Implement image admission control (OPA, Kyverno) in Kubernetes

---

## UC-136 — Terraform Destroy Run Against Production {#uc-136}

**Threat:** `terraform destroy` executed against production infrastructure — whether
accidental, malicious, or via compromised CI/CD pipeline. Can delete entire cloud environments.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 92 |
| **MITRE** | T1485 — Data Destruction |
| **Data Sources** | Terraform Cloud/Enterprise audit, CI/CD logs, AWS CloudTrail |
| **Rule IDs** | SP-cicd-006 |

### Splunk SPL

```spl
| union
    [search index=terraform OR index=cicd
     | where match(_raw,"(?i)(terraform.*destroy|tf.*destroy)") AND match(_raw,"(?i)(prod|production|prd)")
     | eval detection="Terraform Destroy CLI"]
    [search index=terraform sourcetype="terraform:audit"
     | where run.operation="destroy" AND match(workspace.name,"(?i)(prod|production|prd)")
     | eval detection="Terraform Cloud Destroy Run"]
| table _time, host, user, workspace.name, run.id, detection
| sort -_time
```

### QRadar AQL

```sql
SELECT username AS "Actor", "workspace" AS "Workspace",
    "operation" AS "Operation", "runId" AS "Run ID",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" = 'HashiCorp Terraform'
    AND "operation" = 'destroy'
    AND ("workspace" LIKE '%prod%' OR "workspace" LIKE '%production%')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. **Immediately check if apply was run** — if pending, cancel the run
2. Use Terraform Cloud run approvals: require second team member sign-off for destroy
3. Implement Sentinel policy: deny destroy on workspaces tagged `environment=production`
4. Check the run was initiated from an authorized principal and CI/CD pipeline
5. Enable AWS Config resource recording to restore state from last known-good snapshot

---

## UC-137 — CI Runner Privilege Escalation {#uc-137}

**Threat:** CI/CD runner process escapes its container or executes privileged commands
on the host. Particularly dangerous for runners with mounted Docker socket or
privileged mode enabled.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 85 |
| **MITRE** | T1611 — Escape to Host |
| **Data Sources** | Build logs, Sysmon Event 1/3, Docker audit |
| **Rule IDs** | SP-cicd-007 |

### Splunk SPL

```spl
index=cicd OR index=windows OR index=linux
| where match(_raw,"(?i)(docker.*--privileged|docker.*-v\s+\/var\/run\/docker\.sock|mount.*\/proc\/|docker.*--pid=host)")
    OR (match(ParentImage,"(?i)(gitlab-runner|jenkins|runner)") AND match(Image,"(?i)(docker|nsenter|chroot)"))
| table _time, host, user, _raw
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Runner Host", username AS "User",
    "Command" AS "Command", "ParentProcessName" AS "Parent",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" IN ('Linux OS','Docker')
    AND (LOWER("Command") LIKE '%docker%--privileged%'
        OR LOWER("Command") LIKE '%-v /var/run/docker.sock%'
        OR LOWER("Command") LIKE '%nsenter%')
    AND "ParentProcessName" IN ('gitlab-runner','jenkins-slave','runner-agent')
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Revoke privileged mode from all CI runners immediately
2. Audit which jobs have access to the Docker socket — remove unless absolutely required
3. Use Docker-in-Docker (DinD) with appropriate network isolation instead
4. Consider rootless Docker or Podman for CI builds
5. Implement Falco rules to alert on privileged container launch in CI namespace

---

## UC-138 — Dependency Confusion Attack Vector {#uc-138}

**Threat:** Internal package name (`company-internal-lib`) exists on public npm/PyPI with a
higher version number from an attacker. Build system pulls the public version instead of the
internal one, executing attacker-controlled code.

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | 82 |
| **MITRE** | T1195.001 — Supply Chain Compromise |
| **Data Sources** | Build logs, npm/pip install logs, network telemetry |
| **Rule IDs** | SP-cicd-008 |

### Splunk SPL

```spl
index=cicd OR index=build sourcetype IN ("jenkins","npm","pip","yarn")
| where match(_raw,"(?i)(npm.*install|pip.*install|yarn.*add).*internal")
| join type=left package [inputlookup internal_packages.csv as pkg | table pkg.name, pkg.registry]
| where pkg.registry="internal" AND match(_raw,"(?i)(registry\.npmjs\.org|pypi\.org)")
| table _time, host, user, _raw
| sort -_time
```

### QRadar AQL

```sql
SELECT sourceip AS "Build Server", username AS "User",
    "PackageName" AS "Package", "Registry" AS "Source Registry",
    DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS "Time"
FROM events WHERE "LogSourceType" IN ('Jenkins','GitHub Actions')
    AND "Registry" IN ('registry.npmjs.org','pypi.org')
    AND "PackageName" IN (
        SELECT DISTINCT "name" FROM reference_sets WHERE name='Internal-Package-Names'
    )
LAST 24 HOURS ORDER BY starttime DESC
```

### Response Actions
1. Check if the package was actually pulled from the public registry — compare file hash
2. If public registry package installed: quarantine build environment, rotate secrets
3. Configure npm/pip to use private registry ONLY: set `registry` in `.npmrc`, `index-url` in pip.conf
4. Register your internal package names on public registries as empty placeholders
5. Use `npm install --registry https://your-registry.example.com` with scope enforcement
