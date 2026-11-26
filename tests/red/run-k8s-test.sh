#!/usr/bin/env bash
# Phase 5 — Kubernetes hardening RED/GREEN testi.
# Cluster OLMADAN işleyen hisseleri yoxlayir: manifest validliyi, Gate 4
# (IaC) neticesi, digest mecburiyyeti, trust policy render-i.
set -Eeuo pipefail
export PATH="${HOME}/.local/bin:/home/akif/.local/bin:${PATH}"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${REPO_ROOT}"

GRN=$'\033[32m'; RED=$'\033[31m'; BLD=$'\033[1m'; RST=$'\033[0m'
PASS=0; FAIL=0
TMP="$(mktemp -d)"; trap 'rm -rf "${TMP}"' EXIT

record() {
  if [ "$1" = "PASS" ]; then echo "  ${GRN}${BLD}✓ $2${RST}"; PASS=$((PASS+1))
  else echo "  ${RED}${BLD}✗ $2${RST}  ${3:-}"; FAIL=$((FAIL+1)); fi
}

render() {
  local dst="$1"; shift
  cp "$@" "${dst}/"
  sed -i \
    -e 's|__IMAGE_REF__|acr.azurecr.io/capstone/app@sha256:1111111111111111111111111111111111111111111111111111111111111111|' \
    -e 's|__GIT_COMMIT__|abc123|' \
    -e 's|__PIPELINE_RUN_URL__|https://example.com/run/1|' \
    -e 's|__CI_PRINCIPAL_OBJECT_ID__|00000000-0000-0000-0000-000000000000|' \
    "${dst}"/*.yaml
}

echo ""
echo "${BLD}═══ Phase 5 — Kubernetes Hardening RED/GREEN Test ═══${RST}"
echo ""

# ── [1] GREEN: manifestler sxem baximindan validdir ─────────────────────────
echo "${BLD}[1] GREEN — manifest sxem validasiyasi${RST}"
mkdir -p "${TMP}/green" && render "${TMP}/green" k8s/bootstrap/*.yaml k8s/app/*.yaml
if command -v kubeconform >/dev/null 2>&1; then
  if kubeconform -strict -summary "${TMP}/green"/*.yaml >/dev/null 2>&1; then
    record PASS "butun manifestler kubeconform-dan kecdi"
  else
    record FAIL "kubeconform validasiyasi" "$(kubeconform -strict "${TMP}/green"/*.yaml 2>&1 | tail -2)"
  fi
else
  echo "  (kubeconform yoxdur — atlanir)"
fi

# ── [2] GREEN: oz Gate 4-umuzden kecir ──────────────────────────────────────
echo ""
echo "${BLD}[2] GREEN — hardened manifestler Gate 4 (IaC) testinden kecir${RST}"
if command -v trivy >/dev/null 2>&1; then
  trivy config --format json --output "${TMP}/g.json" --exit-code 0 "${TMP}/green" >/dev/null 2>&1 || true
  set +e
  python3 ci/severity_gate.py --report "${TMP}/g.json" --format trivy --scanner trivy-config >/dev/null 2>&1
  rc=$?; set -e
  [ "$rc" -eq 0 ] && record PASS "hardened manifestler PASS (exit 0)" \
                  || record FAIL "hardened manifestler PASS" "exit ${rc} — HIGH/CRITICAL tapinti var"
else
  echo "  (trivy yoxdur — atlanir: bash ci/install-scanners.sh trivy)"
fi

# ── [3] RED: zeif manifest bloklanmalidir ───────────────────────────────────
echo ""
echo "${BLD}[3] RED — privileged/hostPath manifest Gate 4-u bloklamalidir${RST}"
mkdir -p "${TMP}/red" && cp tests/red/Deployment.red.txt "${TMP}/red/deployment.yaml"
if command -v trivy >/dev/null 2>&1; then
  trivy config --format json --output "${TMP}/r.json" --exit-code 0 "${TMP}/red" >/dev/null 2>&1 || true
  python3 -c "
import json,collections
d=json.load(open('${TMP}/r.json')); c=collections.Counter()
for r in d.get('Results',[]):
    for m in r.get('Misconfigurations',[]) or []: c[m['Severity']]+=1
print('    tapintilar:', dict(c))"
  set +e
  python3 ci/severity_gate.py --report "${TMP}/r.json" --format trivy --scanner trivy-config >/dev/null 2>&1
  rc=$?; set -e
  [ "$rc" -eq 1 ] && record PASS "zeif manifest BLOKLANDI (exit 1)" \
                  || record FAIL "zeif manifest BLOKLANDI" "exit ${rc} — gate islemir!"
else
  echo "  (trivy yoxdur — atlanir)"
fi

# ── [4] RED: tag ile deploy redd edilmelidir ────────────────────────────────
echo ""
echo "${BLD}[4] RED — tag ile deploy cehdi${RST}"
set +e
IMAGE_REF="acr.azurecr.io/capstone/app:v1" SKIP_VERIFY=true bash ci/k8s-deploy.sh >/dev/null 2>&1
rc=$?; set -e
[ "$rc" -ne 0 ] && record PASS "tag ile deploy BLOKLANDI (exit ${rc})" \
                || record FAIL "tag ile deploy BLOKLANDI" "mutable tag qebul edildi!"

# ── [5] Hardening control-larinin manifestde movcudlugu ─────────────────────
echo ""
echo "${BLD}[5] Hardening control-lari manifestde${RST}"
D="k8s/app/deployment.yaml"
declare -A CONTROLS=(
  ["runAsNonRoot: true"]="runAsNonRoot"
  ["readOnlyRootFilesystem: true"]="readOnlyRootFilesystem"
  ["allowPrivilegeEscalation: false"]="allowPrivilegeEscalation"
  ["type: RuntimeDefault"]="seccompProfile"
  ["automountServiceAccountToken: false"]="automountServiceAccountToken"
  ["runAsUser: 65532"]="reqemsal UID"
)
missing=0
for pattern in "${!CONTROLS[@]}"; do
  grep -q "${pattern}" "${D}" || { echo "    catişmir: ${CONTROLS[$pattern]}"; missing=$((missing+1)); }
done
grep -q "drop:" "${D}" && grep -q "\- ALL" "${D}" || { echo "    catişmir: capabilities.drop ALL"; missing=$((missing+1)); }
[ "$missing" -eq 0 ] && record PASS "7 hardening control-u movcuddur" \
                     || record FAIL "hardening control-lari" "${missing} catişmir"

# ── [6] NetworkPolicy default-deny ──────────────────────────────────────────
echo ""
echo "${BLD}[6] NetworkPolicy default-deny${RST}"
NP="k8s/bootstrap/networkpolicy.yaml"
if grep -q "podSelector: {}" "${NP}" && grep -q "Ingress" "${NP}" && grep -q "Egress" "${NP}"; then
  record PASS "default-deny hem Ingress, hem Egress uçun var"
else
  record FAIL "default-deny" "podSelector: {} + Ingress/Egress gozlenilir"
fi
grep -q "k8s-app: kube-dns" "${NP}" \
  && record PASS "DNS egress acilib (default-deny-den sonra mecburidir)" \
  || record FAIL "DNS egress" "DNS acilmayib — pod ad helli ede bilmeyecek"

# ── [7] CI Role-da tehlukeli icazeler yoxdur ────────────────────────────────
echo ""
echo "${BLD}[7] CI Role — least privilege${RST}"
R="k8s/bootstrap/rbac.yaml"
bad=0
for res in secrets networkpolicies rolebindings; do
  if python3 -c "
import yaml,sys
docs=[d for d in yaml.safe_load_all(open('${R}')) if d and d.get('kind')=='Role']
for d in docs:
    for rule in d.get('rules',[]):
        if '${res}' in rule.get('resources',[]):
            w=set(rule.get('verbs',[]))
            if w & {'create','update','patch','delete','*'}: sys.exit(1)
sys.exit(0)"; then :; else echo "    ${res} uzerinde yazma icazesi var!"; bad=$((bad+1)); fi
done
[ "$bad" -eq 0 ] && record PASS "secrets/networkpolicies/rolebindings yazma icazesi YOXDUR" \
                 || record FAIL "least privilege" "${bad} tehlukeli icaze"

echo ""
echo "${BLD}═══════════════════════════════════════════════${RST}"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo ""
[ "${FAIL}" -eq 0 ] && { echo "  ${GRN}${BLD}Phase 5 Kubernetes hardening: PASS${RST}"; echo ""; exit 0; }
echo "  ${RED}${BLD}Phase 5 Kubernetes hardening: FAIL${RST}"; echo ""; exit 1
