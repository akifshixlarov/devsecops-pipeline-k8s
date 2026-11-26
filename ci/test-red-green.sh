#!/usr/bin/env bash
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

mkdir -p evidence/defectdojo/import-logs

MODE="${1:-red}"

export DD_URL="${DD_URL:-http://localhost:8080}"
export DD_ENGAGEMENT_ID="${DD_ENGAGEMENT_ID:-1}"

if [ -z "${DD_API_KEY:-}" ]; then
  echo "ERROR: DD_API_KEY environment variable must be set." >&2
  exit 2
fi

SEMGREP_BIN="${SEMGREP_BIN:-$(command -v semgrep || echo /home/akif/.local/bin/semgrep)}"

if [ "${MODE}" = "red" ]; then
  echo "============================================================"
  echo "PHASE 6 RED TEST: INTENTIONAL VULNERABILITY INJECTION"
  echo "============================================================"
  echo "[1/4] Injecting intentional vulnerability fixture..."
  cp tests/red/sast-vulnerable.js.txt app/src/vulnerable.js

  echo "[2/4] Running Semgrep SAST scan..."
  set +e
  "${SEMGREP_BIN}" scan --config=security/semgrep/rules --json --output=reports/semgrep.json app/
  SCAN_RC=$?
  set -e
  echo "Semgrep raw exit code: ${SCAN_RC}"
  test -s reports/semgrep.json || { echo "ERROR: reports/semgrep.json missing or empty" >&2; exit 2; }

  echo "[3/4] Uploading scan report to DefectDojo (MUST SUCCEED BEFORE BLOCK)..."
  python3 ci/defectdojo_upload.py --scanner semgrep --report reports/semgrep.json --required true

  echo "[4/4] Evaluating severity gate policy (MUST BLOCK with exit code 1)..."
  set +e
  python3 ci/severity_gate.py --report reports/semgrep.json --format semgrep --scanner semgrep
  GATE_RC=$?
  set -e

  echo "Severity gate exit code: ${GATE_RC}"
  if [ "${GATE_RC}" -ne 0 ]; then
    echo ">>> RED TEST VERIFIED: Upload succeeded AND pipeline blocked (exit code ${GATE_RC}) <<<"
    exit "${GATE_RC}"
  else
    echo ">>> RED TEST FAILED: Pipeline did not block! <<<"
    exit 1
  fi

elif [ "${MODE}" = "green" ]; then
  echo "============================================================"
  echo "PHASE 6 GREEN TEST: REMEDIATION & AUTO-MITIGATION"
  echo "============================================================"
  echo "[1/4] Removing vulnerable fixture (remediation)..."
  rm -f app/src/vulnerable.js

  echo "[2/4] Running Semgrep SAST scan on remediated code..."
  set +e
  "${SEMGREP_BIN}" scan --config=security/semgrep/rules --json --output=reports/semgrep.json app/
  SCAN_RC=$?
  set -e
  echo "Semgrep raw exit code: ${SCAN_RC}"
  test -s reports/semgrep.json || { echo "ERROR: reports/semgrep.json missing or empty" >&2; exit 2; }

  echo "[3/4] Reimporting clean report to DefectDojo (auto-mitigating previous findings)..."
  python3 ci/defectdojo_upload.py --scanner semgrep --report reports/semgrep.json --required true

  echo "[4/4] Evaluating severity gate policy (MUST PASS with exit code 0)..."
  python3 ci/severity_gate.py --report reports/semgrep.json --format semgrep --scanner semgrep
  GATE_RC=$?

  echo "Severity gate exit code: ${GATE_RC}"
  if [ "${GATE_RC}" -eq 0 ]; then
    echo ">>> GREEN TEST VERIFIED: Reimport auto-mitigated AND pipeline passed (exit code 0) <<<"
    exit 0
  else
    echo ">>> GREEN TEST FAILED: Pipeline blocked! <<<"
    exit "${GATE_RC}"
  fi
fi
