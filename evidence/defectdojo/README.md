# DefectDojo Central Finding Management Evidence

This directory contains verified execution logs, reports, and evidence for **Phase 6: Central Finding Management — DefectDojo** of the DevSecOps Capstone Project.

---

## 1. Architecture Overview

Security findings from all CI/CD gates are centrally collected into a single DefectDojo Product and Engagement prior to gating decisions.

```text
GitHub Actions
      │
      ├── Semgrep (SAST)
      ├── Trivy SCA (SCA)
      ├── Gitleaks (Secrets)
      ├── Trivy Config (IaC)
      ├── Hadolint (Dockerfile)
      ├── Trivy Image (Image CVE)
      └── Trivy Image Secret (Image Secrets)
                │
                ▼
          Report Artifacts (reports/*.json)
                │
                ▼
           DefectDojo Reimport (/api/v2/reimport-scan/)
                │
                ▼
        Severity Gate Evaluation (ci/severity_gate.py)
                │
                ▼
       GitHub Actions PASS / FAIL
```

---

## 2. Environment & Engagement Configuration

- **DefectDojo Host**: `http://localhost:8080` (deployed via official Docker Compose stack)
- **Product ID**: `1`
  - **Product Name**: `devsecops-pipeline-k8s`
  - **Description**: `Secure CI/CD Pipeline to Azure Kubernetes Service (AKS)`
- **Engagement ID**: `1`
  - **Engagement Name**: `CI/CD Security Gates`
  - **Engagement Type**: `CI/CD`
  - **Status**: `In Progress`

---

## 3. Scanner Import Matrix

All 7 scanners from Phases 1–5 have been successfully integrated and verified under Engagement ID 1:

| Scanner | Category | Parser Name (`scan_type`) | DefectDojo Test ID | Findings in Baseline | Gate Status |
|---|---|---|:---:|:---:|:---:|
| **Semgrep** | SAST | `Semgrep JSON Report` | Test 1 | 0 | ✅ PASS |
| **Trivy SCA** | SCA | `Trivy Scan` | Test 2 | 2 (Medium) | ✅ PASS |
| **Gitleaks** | Secret Detection | `Gitleaks Scan` | Test 3 | 0 | ✅ PASS |
| **Trivy Config** | IaC / Manifests | `Trivy Scan` | Test 4 | 3 (2 Medium, 1 Low) | ✅ PASS |
| **Hadolint** | Dockerfile Linting | `Hadolint Dockerfile check` | Test 5 | 0 | ✅ PASS |
| **Trivy Image** | Container Image CVE | `Trivy Scan` | Test 6 | 23 (1 Crit, 5 High, 8 Med, 9 Low) | ❌ BLOCK (Strict Gate) |
| **Trivy Image Secret** | Container Image Secrets | `Trivy Scan` | Test 7 | 0 | ✅ PASS |

---

## 4. Controlled RED / GREEN Verification

Verified via `ci/test-red-green.sh`:

### RED Test (`import-logs/red-test.log`)
1. **Injection**: Injected intentional vulnerability fixture `tests/red/sast-vulnerable.js.txt` into `app/src/vulnerable.js`.
2. **Scan**: Semgrep identified 7 findings (6 High, 1 Medium).
3. **Upload**: Report uploaded to DefectDojo Test ID 1. API verified findings were set to **Active**.
4. **Gate Execution**: `ci/severity_gate.py` evaluated policy (`high: { action: block }`).
5. **Result**: Pipeline blocked with **exit code 1**.

### GREEN Test (`import-logs/green-test.log`)
1. **Remediation**: Removed vulnerable fixture `app/src/vulnerable.js`.
2. **Scan**: Semgrep identified 0 findings.
3. **Upload**: Clean report reimported to DefectDojo Test ID 1 with `close_old_findings=true`.
4. **Auto-Mitigation**: DefectDojo marked all 7 previous findings as **Inactive, Mitigated** (`Mitigated by Semgrep JSON Report re-upload.`).
5. **Gate Execution**: `ci/severity_gate.py` evaluated policy.
6. **Result**: Pipeline passed with **exit code 0**.

---

## 5. Log Files in this Directory

- `import-logs/all-scanners-import.log`: Full sequential reimport of all 7 scanners into DefectDojo Engagement 1.
- `import-logs/red-test.log`: Complete terminal log of intentional vulnerability detection, upload to DefectDojo, and pipeline failure.
- `import-logs/green-test.log`: Complete terminal log of remediation, clean reimport, finding auto-mitigation, and pipeline pass.
