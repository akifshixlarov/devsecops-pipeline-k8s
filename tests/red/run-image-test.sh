#!/usr/bin/env bash
# Phase 3 gate-lerinin RED/GREEN testi (image build etmeden).
#   hadolint : Dockerfile lint gate-i
#   secret   : layer secret gate-i (fixture ile)
set -Eeuo pipefail
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${REPO_ROOT}"

GRN=$'\033[32m'; RED=$'\033[31m'; BLD=$'\033[1m'; RST=$'\033[0m'
PASS=0; FAIL=0
TMP="$(mktemp -d)"; trap 'rm -rf "${TMP}"' EXIT

record() {
  if [ "$1" = "PASS" ]; then echo "  ${GRN}${BLD}✓ $2${RST}"; PASS=$((PASS+1))
  else echo "  ${RED}${BLD}✗ $2${RST}  $3"; FAIL=$((FAIL+1)); fi
}

command -v hadolint >/dev/null || { echo "hadolint yoxdur: bash ci/install-scanners.sh hadolint"; exit 1; }

echo ""
echo "${BLD}═══ Phase 3 — Image Security RED/GREEN Test ═══${RST}"
echo ""

# ── Gate 6A GREEN ───────────────────────────────────────────────────────────
echo "${BLD}[1] Gate 6A GREEN — hardened Dockerfile${RST}"
hadolint --config security/hadolint/hadolint.yaml --format json app/Dockerfile > "${TMP}/g.json" 2>/dev/null || true
set +e
python3 ci/severity_gate.py --report "${TMP}/g.json" --format hadolint --scanner hadolint >/dev/null 2>&1
rc=$?; set -e
[ "$rc" -eq 0 ] && record PASS "hardened Dockerfile PASS (exit 0)" \
                || record FAIL "hardened Dockerfile PASS" "exit ${rc}"

# ── Gate 6A RED ─────────────────────────────────────────────────────────────
echo ""
echo "${BLD}[2] Gate 6A RED — zeif Dockerfile (USER root, :latest, ADD URL)${RST}"
cp tests/red/Dockerfile.red.txt "${TMP}/Dockerfile"
hadolint --config security/hadolint/hadolint.yaml --format json "${TMP}/Dockerfile" > "${TMP}/r.json" 2>/dev/null || true
python3 -c "
import json;d=json.load(open('${TMP}/r.json'))
errs=[f for f in d if f['level']=='error']
print(f'  {len(d)} finding, bunlardan {len(errs)} error:')
[print(f'    {f[\"code\"]:8} {f[\"level\"]:8} {f[\"message\"][:55]}') for f in errs]
"
set +e
python3 ci/severity_gate.py --report "${TMP}/r.json" --format hadolint --scanner hadolint >/dev/null 2>&1
rc=$?; set -e
[ "$rc" -eq 1 ] && record PASS "zeif Dockerfile BLOKLANDI (exit 1)" \
                || record FAIL "zeif Dockerfile BLOKLANDI" "exit ${rc} — gate islemir!"

# ── Gate 6C RED ─────────────────────────────────────────────────────────────
echo ""
echo "${BLD}[3] Gate 6C RED — layer secret (fixture)${RST}"
cat > "${TMP}/sec.json" <<'JSON'
{"Results":[{"Target":"app/.npmrc","Class":"secret","Secrets":[
 {"RuleID":"npm-token","Category":"NPM","Severity":"CRITICAL","Title":"npm token",
  "StartLine":1,"Match":"_authToken=npm_LABDUMMYVALUE1234567890"}]}]}
JSON
python3 ci/redact_trivy_secrets.py --input "${TMP}/sec.json" --output "${TMP}/sec-red.json" >/dev/null
if grep -q "LABDUMMYVALUE" "${TMP}/sec-red.json"; then
  record FAIL "secret redaction" "artifact-a secret sizir!"
else
  record PASS "secret redaction — deyer tam silindi"
fi
set +e
python3 ci/severity_gate.py --report "${TMP}/sec-red.json" --format trivy --scanner trivy-image-secret >/dev/null 2>&1
rc=$?; set -e
[ "$rc" -eq 1 ] && record PASS "layer secret BLOKLANDI (exit 1)" \
                || record FAIL "layer secret BLOKLANDI" "exit ${rc}"

# ── Gate 6C GREEN ───────────────────────────────────────────────────────────
echo ""
echo "${BLD}[4] Gate 6C GREEN — secret yoxdur${RST}"
echo '{"Results":[{"Target":"app","Class":"secret","Secrets":[]}]}' > "${TMP}/clean.json"
set +e
python3 ci/severity_gate.py --report "${TMP}/clean.json" --format trivy --scanner trivy-image-secret >/dev/null 2>&1
rc=$?; set -e
[ "$rc" -eq 0 ] && record PASS "temiz image PASS (exit 0)" \
                || record FAIL "temiz image PASS" "exit ${rc}"

echo ""
echo "${BLD}═══════════════════════════════════════════════${RST}"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo ""
[ "${FAIL}" -eq 0 ] && { echo "  ${GRN}${BLD}Phase 3 image gates: PASS${RST}"; echo ""; exit 0; }
echo "  ${RED}${BLD}Phase 3 image gates: FAIL${RST}"; echo ""; exit 1
