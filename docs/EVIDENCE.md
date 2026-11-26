# DevSecOps Pipeline Evidence Documentation

This document records proof and validation of security controls implemented across the CI/CD pipeline targeting Azure Kubernetes Service (AKS).

---

## Phase 6 — DefectDojo Central Finding Management

### Implementation
- **Uploader Script**: [ci/defectdojo_upload.py](file:///e:/Main%20Programs/dell/Projects/devsecops-pipeline-k8s/ci/defectdojo_upload.py)
  - Interacts with DefectDojo v2 API (`/api/v2/reimport-scan/`).
  - Supports automatic engagement context resolution (`auto_create_context=true`, `product_name`, `engagement_name`).
  - Implements exponential backoff retry for network transient failures.
  - Automatically activates `close_old_findings=true` to track remediation trends over time.
- **Severity Gate**: [ci/severity_gate.py](file:///e:/Main%20Programs/dell/Projects/devsecops-pipeline-k8s/ci/severity_gate.py)
  - Normalized parser support for all integrated tools: `semgrep`, `trivy` (SCA, IaC, Image CVE, Image Secrets), `gitleaks`, and `hadolint`.
  - Single source of truth policy configuration in [ci/policy.yaml](file:///e:/Main%20Programs/dell/Projects/devsecops-pipeline-k8s/ci/policy.yaml).
- **Critical Failure Semantics**:
  - The workflow guarantees:
    $$\text{Scanner} \longrightarrow \text{Report Generated} \longrightarrow \text{DefectDojo Upload} \longrightarrow \text{Upload Verified} \longrightarrow \text{Severity Evaluation} \longrightarrow \text{PASS/FAIL Decision}$$
  - Scanners do **NOT** exit prematurely on finding detection; raw scanner exit codes are decoupled so DefectDojo upload is never skipped when vulnerabilities are detected.

---

### Scanners Imported

| Scanner | Tool | Report Format | DefectDojo Parser | Test Title |
|---|---|---|---|---|
| **SAST** | Semgrep | JSON | `Semgrep JSON Report` | `semgrep — local` |
| **SCA** | Trivy FS | JSON | `Trivy Scan` | `trivy-sca — local` |
| **Secret Detection** | Gitleaks | JSON | `Gitleaks Scan` | `gitleaks — local` |
| **IaC** | Trivy Config | JSON | `Trivy Scan` | `trivy-config — local` |
| **Dockerfile** | Hadolint | JSON | `Hadolint Dockerfile check` | `hadolint — local` |
| **Image CVE** | Trivy Image | JSON | `Trivy Scan` | `trivy-image — local` |
| **Image Secrets** | Trivy Secret | JSON | `Trivy Scan` | `trivy-image-secret — local` |

---

### Engagement

- **Product**: `devsecops-pipeline-k8s` (Product ID: `1`)
- **Engagement**: `CI/CD Security Gates` (Engagement ID: `1`)
- **Tests Managed**: 7 discrete test targets under one central engagement.
- **Total Unique Findings Tracked**: 28 baseline findings + auto-mitigated test findings.

---

### Blocking Behavior

The severity gate policy ([ci/policy.yaml](file:///e:/Main%20Programs/dell/Projects/devsecops-pipeline-k8s/ci/policy.yaml)) enforces:
- `CRITICAL`: **BLOCK** (tolerance = 0)
- `HIGH`: **BLOCK** (tolerance = 0)
- `MEDIUM`: Policy-dependent (configurable threshold, e.g., max 10–20 allowed with WARN)
- `LOW` / `UNKNOWN`: Report only (WARN)
- `Gitleaks` & `Image Secrets`: Zero-tolerance (all findings normalized to Critical -> BLOCK)

---

### RED Test (Controlled Vulnerability Injection)

- **Fixture**: [tests/red/sast-vulnerable.js.txt](file:///e:/Main%20Programs/dell/Projects/devsecops-pipeline-k8s/tests/red/sast-vulnerable.js.txt) containing command injection, eval, wildcard CORS, disabled Helmet headers, and exposed credentials.
- **Trigger**: Injected into `app/src/vulnerable.js` and scanned by Semgrep.
- **Detection**: Semgrep flagged 7 vulnerabilities (6 HIGH, 1 MEDIUM).
- **Upload to DefectDojo**: Uploaded via `ci/defectdojo_upload.py` to Test ID 1. DefectDojo created active findings (IDs 29–35).
- **Gating**: `ci/severity_gate.py` detected 6 HIGH findings exceeding tolerance 0.
- **Result**: Pipeline returned exit code `1` (**FAIL / BLOCK**).
- **Proof Log**: [evidence/defectdojo/import-logs/red-test.log](file:///e:/Main%20Programs/dell/Projects/devsecops-pipeline-k8s/evidence/defectdojo/import-logs/red-test.log).

---

### GREEN Test (Remediation & Auto-Mitigation)

- **Action**: Removed `app/src/vulnerable.js`.
- **Scan**: Semgrep scanned `app/` and reported 0 findings.
- **Reimport to DefectDojo**: Clean report reimported via `ci/defectdojo_upload.py` with `close_old_findings=true`.
- **DefectDojo Verification**: Findings 29–35 automatically marked `Inactive, Mitigated` with system note: `Mitigated by Semgrep JSON Report re-upload.`.
- **Gating**: `ci/severity_gate.py` evaluated clean report with 0 blocking findings.
- **Result**: Pipeline returned exit code `0` (**PASS**).
- **Proof Log**: [evidence/defectdojo/import-logs/green-test.log](file:///e:/Main%20Programs/dell/Projects/devsecops-pipeline-k8s/evidence/defectdojo/import-logs/green-test.log).

---

### Evidence Artifacts

1. **Import Logs**:
   - Sequential 7-scanner import: [evidence/defectdojo/import-logs/all-scanners-import.log](file:///e:/Main%20Programs/dell/Projects/devsecops-pipeline-k8s/evidence/defectdojo/import-logs/all-scanners-import.log)
   - RED Test execution log: [evidence/defectdojo/import-logs/red-test.log](file:///e:/Main%20Programs/dell/Projects/devsecops-pipeline-k8s/evidence/defectdojo/import-logs/red-test.log)
   - GREEN Test execution log: [evidence/defectdojo/import-logs/green-test.log](file:///e:/Main%20Programs/dell/Projects/devsecops-pipeline-k8s/evidence/defectdojo/import-logs/green-test.log)
2. **DefectDojo Documentation**:
   - [evidence/defectdojo/README.md](file:///e:/Main%20Programs/dell/Projects/devsecops-pipeline-k8s/evidence/defectdojo/README.md)
