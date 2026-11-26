# DefectDojo Setup & Architecture Guide

This document describes the deployment architecture, configuration, and CI/CD integration models for **DefectDojo** within the **Secure CI/CD Pipeline to Cloud Kubernetes** project.

---

## 1. Architecture Overview

DefectDojo operates as the centralized vulnerability and finding management platform:

```text
GitHub Actions / Local CLI
      │
      ├── Semgrep (SAST)
      ├── Trivy SCA (Dependencies)
      ├── Gitleaks (Secrets)
      ├── Trivy Config (IaC)
      ├── Hadolint (Dockerfile)
      ├── Trivy Image (Container CVE)
      └── Trivy Image Secret (Layer Secrets)
                │
                ▼
           JSON Reports (reports/*.json)
                │
                ▼
      Pre-Upload Report Validation (validate_report)
                │
                ▼
      DefectDojo Reimport API (/api/v2/reimport-scan/)
                │
                ▼
      Post-Upload Active Finding Verification (verify_test_import)
                │
                ▼
      Central Severity Gate (ci/severity_gate.py)
                │
                ▼
      Pipeline PASS / FAIL / BLOCK Decision
```

---

## 2. Environment Configuration

### Central Identity
- **Product Name**: `devsecops-pipeline-k8s` (Product ID: `1`)
- **Engagement Name**: `CI/CD Security Gates` (Engagement ID: `1`)
- **Engagement Type**: `CI/CD`
- **Reimport Behavior**: `close_old_findings=true` (automatically transitions remediated issues to `Mitigated` upon receipt of a complete, valid clean scan).

### Environment Variables
- `DD_URL`: The base URL of the DefectDojo instance (e.g., `http://localhost:8080` or `https://defectdojo.yourdomain.com`).
- `DD_API_KEY`: API v2 token for authentication (stored exclusively in GitHub Secrets / local environment).
- `DD_ENGAGEMENT_ID`: ID of the target engagement (`1`).
- `DD_UPLOAD_REQUIRED`: `true` on protected branches (`main`) to enforce fail-closed auditability; `false` on fork pull requests where secrets are inaccessible.

---

## 3. Network and CI/CD Limitations & Execution Models

> [!WARNING]
> **Network Boundary Limitation**: 
> A standard GitHub-hosted runner (`ubuntu-latest`) **cannot** reach `http://localhost:8080` running on a private developer workstation or isolated internal network. Local test execution (`http://localhost:8080`) proves API parser compatibility and gate logic, but **does not** prove public GitHub-hosted runner connectivity.

### Validated Execution Model
- **Model Validated**: **Local Development & Local DefectDojo Container Stack** (`http://localhost:8080`).

### Production Deployment Options for CI/CD

To connect GitHub Actions CI/CD to DefectDojo in an enterprise environment, choose one of the following two supported topologies:

### Option A: Dedicated Cloud VM behind HTTPS / Reverse Proxy (Recommended for GitHub-Hosted Runners)
1. Deploy DefectDojo on an Azure VM or cloud instance with a public FQDN (or restricted via IP allowlist).
2. Configure TLS via reverse proxy (e.g., Caddy, Traefik, or Nginx with Let's Encrypt certificates).
3. Set GitHub Repository Secrets:
   - `DD_URL=https://defectdojo.yourdomain.com`
   - `DD_API_KEY=<token>`
   - `DD_ENGAGEMENT_ID=1`
4. The GitHub-hosted runner sends scan reports securely over TLS port 443 directly to `/api/v2/reimport-scan/`.

### Option B: Self-Hosted GitHub Actions Runner (Recommended for Air-Gapped / Private Networks)
1. Keep DefectDojo deployed inside the private virtual network (VNet) without exposing port 8080 to the public internet.
2. Deploy a GitHub Self-Hosted Runner on an Azure VM within the same VNet or private subnet.
3. Configure workflows with `runs-on: [self-hosted, linux]`.
4. The runner communicates with DefectDojo over private internal DNS / IP (`http://defectdojo.internal:8080`).
