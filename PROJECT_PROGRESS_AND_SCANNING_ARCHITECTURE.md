# Project Progress & Security Scanning Architecture

## Executive Summary & System Overview

This platform is an enterprise-grade **Application Security Posture Management (ASPM) and Continuous Compliance System**. It orchestrates a multi-engine security scanner fleet (Semgrep, CodeQL, Trivy, OSV-Scanner), performs deterministic risk scoring, maintains strict repository finding isolation, and enforces **SOC 2 Type II Trust Services Criteria** with automated auditor verification proof and SLA tracking.

---

## 1. System Ingestion & Repository Connection Flow

```
+-----------------------------------------------------------------------------------+
|                           Repository Ingestion Phase                              |
+-----------------------------------------------------------------------------------+
|  1. Ingestion Method:                                                             |
|     - GitHub Personal Access Token (PAT): Authenticates with GitHub API to        |
|       dynamically discover user/organization repositories & private repositories. |
|     - Direct Repository URL: Any public/private Git repository or local workspace |
|       path (e.g., https://github.com/org/repo.git or local folder).              |
|                                                                                   |
|  2. Pre-Flight Validation Engine:                                                 |
|     - Checks network reachability, credential permissions, and git HEAD.          |
|     - Queries available branches (main, master, staging, dev) and commits.        |
|     - Validates repository root manifests (package.json, requirements.txt, etc.). |
|                                                                                   |
|  3. System Registration & Isolation:                                              |
|     - Registers repository with UUID, tenant ID, and configuration metadata.      |
|     - Allocates isolated finding storage space tagged by repository ID.           |
+-----------------------------------------------------------------------------------+
```

---

## 2. End-to-End Scanning Lifecycle

When a scan is triggered (manually via UI, API call, or CI/CD webhook), the backend executes a 10-stage orchestrated pipeline:

```
[Trigger Scan]
       │
       ▼
[Stage 1: Scan Job Initialization]
       │ (Generates ScanJob ID, transitions status to RUNNING, logs audit event)
       ▼
[Stage 2: Git Resolution & Isolated Workspace Checkout]
       │ (Resolves commit SHA, creates 0700 temporary directory, performs clean checkout)
       ▼
[Stage 3: Repository Profiling & Language Analysis]
       │ (Detects languages, frameworks, package managers, IaC, containers)
       ▼
[Stage 4: Dynamic Scan Planning]
       │ (Selects optimal engines: Semgrep for SAST/Secrets, Trivy/OSV for SCA, CodeQL)
       ▼
[Stage 5: Parallel Multi-Scanner Execution]
       │ (Runs Semgrep, CodeQL, Trivy, OSV-Scanner against isolated local workspace)
       ▼
[Stage 6: Raw Artifact & Evidence Digesting]
       │ (Captures stdout/stderr, generates SHA-256 evidence digests)
       ▼
[Stage 7: Correlation, Normalization & Deduplication]
       │ (Merges multi-engine reports into CanonicalSecurityFinding records)
       ▼
[Stage 8: Deterministic Risk Scoring Engine]
       │ (Calculates CVSS v3, exploitability, asset criticality, exposure)
       ▼
[Stage 9: SOC 2 Type II Compliance Evaluation]
       │ (Evaluates findings against CC1–CC9, A1, C1, PI1 with SLA deadlines)
       ▼
[Stage 10: Workspace Destruction & Final Audit Record]
       │ (Securely deletes 0700 temp workspace, transitions status to COMPLETED)
       ▼
[Updated Dashboard & Findings Table]
```

---

## 3. How Scanning Executes in the Local Engine

### A. Isolated Temporary Workspace Provisioning
1. The backend `GitService` (`app/services/git_service.py`) generates a cryptographically random directory in `/tmp/scans/{tenant_id}/{scan_id}` with strict `0700` POSIX file permissions.
2. The repository is cloned or checked out directly at the exact target commit SHA, ensuring non-repudiation and reproducible scan results.

### B. Repository Analysis (`RepositoryAnalyzer`)
Before running any scanner, the engine scans the project root to build a `RepositoryProfile`:
- **Languages**: Identifies file extensions (`.py`, `.ts`, `.tsx`, `.js`, `.go`, `.java`, etc.).
- **Package Managers & Manifests**:
  - Node.js: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
  - Python: `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml`
  - Go: `go.mod`, `go.sum`
- **Infrastructure as Code (IaC)**: `.tf`, Kubernetes YAML, CloudFormation.
- **Container Targets**: `Dockerfile`, `docker-compose.yml`.

### C. Multi-Scanner Fleet Execution
The `ScanPlanner` activates specialized scanner adapters based on detected technologies:

| Scanner Engine | Primary Function | Targets & Rules |
| :--- | :--- | :--- |
| **Semgrep** | Fast AST SAST & Secret Detection | Checks source code against OWASP Top 10, CWE-89 (SQLi), CWE-79 (XSS), CWE-798 (Hardcoded Secrets). |
| **CodeQL** | Semantic Data Flow & Taint Tracking | Identifies deep untrusted input paths traversing from HTTP sources to sink execution points. |
| **Trivy** | Vulnerability & Misconfiguration Scanner | Scans package manifests, container base images, and OS-level packages against NVD/CVE databases. |
| **OSV-Scanner** | Open Source Vulnerability Database | Queries Google's OSV database across lockfiles (`package-lock.json`, `Pipfile.lock`) for known GHSA/CVE advisories. |

Each scanner executes in an isolated subprocess with resource limits (timeout caps, CPU quotas). Both stdout and stderr are captured and stored in the database.

---

## 4. Finding Correlation, Deduplication & Normalization

When multiple scanners detect the same underlying vulnerability (for example, Semgrep and Trivy both flagging an insecure library or injection sink), the `FindingCorrelationService` (`app/services/correlation_service.py`) prevents duplicate clutter:

1. **Fingerprint Computation**:
   A deterministic SHA-256 fingerprint is calculated:
   $$\text{Fingerprint} = \text{SHA256}(\text{repo\_id} + \text{file\_path} + \text{rule\_family} + \text{cwe\_id} + \text{package\_name})$$
2. **Canonical Finding Creation**:
   - If a finding with this fingerprint already exists for the repository, the engine updates its `detected_by_scanners` array (e.g. `["semgrep", "trivy", "codeql"]`).
   - If new, a `CanonicalSecurityFinding` record is created.
3. **Repository Scope Enforcement**:
   - Every finding is explicitly linked to `repository_id` and `repository_name`.
   - UI views and API queries filter strictly by repository ID, preventing cross-repository finding contamination.
   - When a user rescans a repository, only findings belonging to that repository are updated or marked resolved.

---

## 5. Deterministic Risk Scoring & SLA Management

The platform avoids arbitrary "High/Medium/Low" labels by using a deterministic formula (`RiskEngine`):

$$\text{Risk Score} = (\text{CVSS Base Score} \times 0.5) + (\text{Exploitability Factor} \times 0.25) + (\text{Asset Criticality} \times 0.15) + (\text{Exposure Factor} \times 0.10)$$

### SLA Remediation Policy:
- **CRITICAL Severity**: **7 Calendar Days** SLA window.
- **HIGH Severity**: **30 Calendar Days** SLA window.
- **MEDIUM / LOW Severity**: **90 Calendar Days** SLA window.

Every finding calculates an exact `remediation_due_at` timestamp. If a finding remains open past this deadline, it is automatically marked as an **SLA Policy Breach**, triggering an audit deficiency in the SOC 2 compliance tab.

---

## 6. SOC 2 Type II Continuous Compliance Engine

The compliance engine is dedicated exclusively to **SOC 2 Type II**, covering the **full suite of Trust Services Criteria (TSC) and Common Criteria (CC1 through CC9)**:

| SOC 2 Criteria | Category | Audit Scope & Verification Control |
| :--- | :--- | :--- |
| **CC1.1** | Control Environment | Secure coding governance, baseline policy documentation, and mandatory repository scan attachments. |
| **CC2.1** | Communication & Information | SLA breach notification dispatch and security telemetry reporting to engineering teams. |
| **CC3.2** | Risk Assessment | Deterministic threat scoring based on CVSS metrics, exploitability likelihood, and asset criticality. |
| **CC4.1** | Monitoring Activities | Continuous automated multi-engine scanning across all branches (Semgrep, CodeQL, Trivy, OSV). |
| **CC5.1** | Control Activities | Pre-deployment branch protection rules, automated PR security status checks, and gate enforcement. |
| **CC6.1** | Logical Access Controls | Perimeter execution boundaries, isolation of remote code execution, and prevention of sandbox breakouts. |
| **CC6.6** | Boundary Protections | Ingress filtering and web application sanitization defending against XSS, SQLi, SSRF, and path traversal. |
| **CC6.7** | Cryptographic Protection | Zero plain-text API keys, passwords, or private tokens committed to source code repositories. |
| **CC6.8** | Vulnerability Management | Continuous scanning with strict SLA remediation enforcement (7-day Critical, 30-day High). |
| **CC7.1** | System Operations | Software Composition Analysis (SCA) and SBOM tracking against public CVE/GHSA advisories. |
| **CC7.2** | Anomaly Detection | Runtime threat monitoring, WAF filtering alignment, and anomalous query pattern detection. |
| **CC8.1** | Change Management | Automated pre-merge security evaluation gates in CI/CD pipelines before merge into production. |
| **CC9.2** | Risk Mitigation | Third-party open-source dependency risk management and automated version upgrade controls. |
| **A1.1** | Availability Criteria | System resiliency assurance preventing Denial of Service (DoS) and resource exhaustion attacks. |
| **C1.1** | Confidentiality Criteria | Data exfiltration prevention safeguarding customer records and sensitive secrets from leakage. |
| **PI1.1** | Processing Integrity | Strict input validation schemas ensuring complete, valid, and accurate transaction processing. |

### Finding-Level Compliance Integration:
When viewing any individual finding in the **Finding Details View**, clicking the **COMPLIANCE** tab displays:
1. The mapped SOC 2 criteria matching that vulnerability taxonomy (e.g. RCE maps to `CC6.1`, `CC6.8`, `CC7.1`, `CC8.1`, `CC3.2`, `C1.1`).
2. Category filter pills (`All SOC 2 Criteria`, `Logical Access (CC6)`, `Operations (CC7)`, `Change Management (CC8)`, `Risk Assessment (CC3)`, `Monitoring (CC4/5)`, `Availability & Confidentiality`).
3. Auditor verification proof required during a formal SOC 2 audit.
4. SLA remediation deadline window.

---

## 7. Cryptographic Evidence & Verification Trail

To satisfy external SOC 2 auditors:
1. **SHA-256 Digest**: For every scanner execution, a SHA-256 hash is computed over the raw output, target commit SHA, and scanner version.
2. **Immutable Audit Trail**: All actions (`SCAN_STARTED`, `SCAN_CHECKOUT`, `SCAN_COMPLETED`, `JIRA_TICKET_CREATED`, `FIX_VERIFIED`) are persisted in the `AuditLog` database with timestamps and actor metadata.
3. **Automated Verification Loop**:
   - Engineers can enter a fix commit SHA in the Finding Details View and click **Verify Fix**.
   - The engine triggers an on-demand re-check. If the vulnerability is no longer present, its status transitions to `RESOLVED`, satisfying the associated SOC 2 control.

---

## 8. Frontend Architecture & Enterprise UX

Built using React, Vite, TailwindCSS, and Lucide icons:
- **Tab 1: Connected Repositories**:
  - Pre-flight ingestion modal (PAT token or direct Git URL).
  - Monitored repositories list with health badges, last scan date, critical defect count, and direct "Scan Now" actions.
- **Tab 2: Vulnerability Findings**:
  - Real-time search, severity filters (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), scanner engine filter, and status toggles.
  - Multi-scanner badge tags showing which engines confirmed the finding.
  - Interactive Finding Details View with 7 specialized sub-tabs: Overview, Code Location, Risk Assessment, SOC 2 Compliance, Cryptographic Evidence, Remediation Guide, and Audit Trail.
- **Tab 3: Scanner Fleet**:
  - Live status and telemetry for Semgrep, CodeQL, Trivy, and OSV-Scanner.
- **Tab 4: Continuous Compliance (SOC 2 Type II)**:
  - 16 live Trust Services Criteria controls evaluated in real time against active repository findings.
  - Filter pills for CC6, CC7, CC8, CC3, CC4/CC5, and A1/C1/PI1.
  - Pass/Fail indicators with open deficiency counts and SLA breach tracking.

---

## 9. Current Service Architecture & Ports

- **Frontend Application**: Running on port `3000` (`http://localhost:3000`).
- **Core PF-7 Backend**: Running on port `8000` (`http://localhost:8000`).
- **Security & Vulnerability Engine Daemon**: Running on port `8001` (`http://localhost:8001`).
- **Database**: SQLite / PostgreSQL with SQLAlchemy ORM models (`ScanJob`, `CanonicalSecurityFinding`, `ScanEvidence`, `ComplianceEvaluation`, `AuditLog`).

---

## 10. Summary Checklist of Capabilities

- [x] Universal repository ingestion via GitHub PAT token or remote Git URL.
- [x] Dynamic branch and file discovery with pre-flight validation.
- [x] Local isolated workspace execution with automatic cleanup (`0700` permissions).
- [x] Multi-scanner execution fleet (Semgrep, CodeQL, Trivy, OSV-Scanner).
- [x] Deduplication and canonical finding normalization across all scanners.
- [x] Strict repository finding isolation (findings never mixed between repositories).
- [x] Deterministic CVSS v3 risk scoring and SLA deadline calculation.
- [x] Exclusively SOC 2 Type II compliance engine with complete Trust Services Criteria (CC1–CC9, A1, C1, PI1).
- [x] Dynamic finding-level compliance mapping with auditor verification evidence.
- [x] Global Continuous Compliance dashboard with 16 live controls.
- [x] Automated fix verification and immutable audit log lifecycle.
