#!/usr/bin/env bash
# Phase 4 — Supply chain RED/GREEN testi.
# Registry olmadan yoxlanila bilen hisseler: trust policy dexilliyi,
# digest-only tetbiqi, cosign flag uygunlugu.
set -Eeuo pipefail
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${REPO_ROOT}"

GRN=$'\033[32m'; RED=$'\033[31m'; BLD=$'\033[1m'; RST=$'\033[0m'
PASS=0; FAIL=0
record() {
  if [ "$1" = "PASS" ]; then echo "  ${GRN}${BLD}✓ $2${RST}"; PASS=$((PASS+1))
  else echo "  ${RED}${BLD}✗ $2${RST}  ${3:-}"; FAIL=$((FAIL+1)); fi
}

echo ""
echo "${BLD}═══ Phase 4 — Supply Chain RED/GREEN Test ═══${RST}"
echo ""

# ── [1] Tag ile imzalama REDD EDILMELIDIR ───────────────────────────────────
echo "${BLD}[1] RED — tag ile imzalama cehdi (digest teleb olunur)${RST}"
set +e
IMAGE_REF="myacr.azurecr.io/capstone/app:v1" bash ci/cosign-sign.sh >/dev/null 2>&1
rc=$?; set -e
[ "$rc" -ne 0 ] && record PASS "tag ile imzalama BLOKLANDI (exit ${rc})" \
                || record FAIL "tag ile imzalama BLOKLANDI" "mutable tag qebul edildi!"

echo ""
echo "${BLD}[2] RED — tag ile dogrulama cehdi${RST}"
set +e
IMAGE_REF="myacr.azurecr.io/capstone/app:v1" bash ci/cosign-verify.sh >/dev/null 2>&1
rc=$?; set -e
[ "$rc" -ne 0 ] && record PASS "tag ile dogrulama BLOKLANDI (exit ${rc})" \
                || record FAIL "tag ile dogrulama BLOKLANDI"

# ── [3] Trust policy kimlik mehdudiyyetleri ─────────────────────────────────
echo ""
echo "${BLD}[3] Trust policy — kimlik mehdudiyyeti matrisi${RST}"
# shellcheck source=/dev/null
. security/cosign/trust-policy.env
export CERT_IDENTITY_REGEXP EXPECTED_REPOSITORY
set +e
python3 - <<'PY'
import os, re, sys

rx   = os.environ["CERT_IDENTITY_REGEXP"]
slug = os.environ["EXPECTED_REPOSITORY"]

# Test SAN-lari policy-nin OZUNDEN qurulur, hardcoded deyil.
# Bele ki, `ci/init-trust-policy.sh --write` ile owner/repo deyisdikde
# test avtomatik uygunlasir ve yalanci FAIL vermir.
if "/" not in slug:
    print("    EXPECTED_REPOSITORY 'owner/repo' formatinda deyil:", slug)
    sys.exit(1)
owner, repo = slug.split("/", 1)

if owner == "OWNER":
    print("    Placeholder hele doldurulmayib.")
    print("    Islet: bash ci/init-trust-policy.sh --write")
    sys.exit(1)

# Workflow fayli ve branch adi regexp-den cixarilir.
m_wf = re.search(r"workflows/([A-Za-z0-9_\\.-]+?)@", rx)
wf   = m_wf.group(1).replace("\\", "") if m_wf else "build.yml"
m_br = re.search(r"refs/heads/([A-Za-z0-9_./-]+?)\$?$", rx)
br   = m_br.group(1).replace("\\", "") if m_br else "main"

base = "https://github.com"
cases = [
 (f"{base}/{owner}/{repo}/.github/workflows/{wf}@refs/heads/{br}",   True,  "legitim CI imzasi"),
 (f"{base}/{owner}/{repo}/.github/workflows/{wf}@refs/heads/evil-x", False, "basqa branch-den imza"),
 (f"{base}/attacker/{repo}/.github/workflows/{wf}@refs/heads/{br}",  False, "fork / basqa owner"),
 (f"{base}/{owner}/{repo}/.github/workflows/pwn.yml@refs/heads/{br}", False, "basqa workflow fayli"),
 (f"{base}/{owner}/{repo}/.github/workflows/{wf}@refs/tags/v1",       False, "tag ref-den imza"),
]
bad = 0
for san, expect, desc in cases:
    got = bool(re.match(rx, san))
    if got != expect:
        print(f"    MISMATCH ({desc}): gozlenilen={expect} alinan={got}")
        print(f"      SAN: {san}")
        bad += 1
sys.exit(1 if bad else 0)
PY
rc=$?
set -e
[ "$rc" -eq 0 ] && record PASS "5 kimlik ssenarisi duzgun (1 qebul, 4 redd)" \
                || record FAIL "kimlik mehdudiyyetleri" "yuxaridaki detallara bax"

# ── [4] Wildcard trust policy askarlanmalidir ───────────────────────────────
echo ""
echo "${BLD}[4] RED — hedden artiq genis trust policy${RST}"
if echo "${CERT_IDENTITY_REGEXP}" | grep -qE '^\^?\.\*|^\.\*$|^"?\*"?$'; then
  record FAIL "trust policy dardir" "wildcard askarlandi — her kes imzalaya biler!"
else
  record PASS "trust policy dardir (wildcard yoxdur)"
fi
if [ "${CERT_OIDC_ISSUER}" = "https://token.actions.githubusercontent.com" ]; then
  record PASS "OIDC issuer GitHub Actions-a baglidir"
else
  record FAIL "OIDC issuer" "gozlenilmeyen issuer: ${CERT_OIDC_ISSUER}"
fi

# ── [5] Cosign mövcudlugu ve flag uygunlugu ─────────────────────────────────
echo ""
echo "${BLD}[5] Cosign binary ve flag uygunlugu${RST}"
if command -v cosign >/dev/null 2>&1; then
  record PASS "cosign quraşdirilib"
  if cosign sign --help 2>&1 | grep -q "registry-referrers-mode"; then
    record PASS "--registry-referrers-mode desteklenir"
  else
    record FAIL "--registry-referrers-mode" "cosign versiyasi kohnedir?"
  fi
  if cosign attest --help 2>&1 | grep -q "cyclonedx"; then
    record PASS "--type cyclonedx desteklenir"
  else
    record FAIL "--type cyclonedx"
  fi
else
  echo "  (cosign yoxdur — atlanir: bash ci/install-scanners.sh cosign)"
fi

# ── [6] Kilid siralamasi ────────────────────────────────────────────────────
echo ""
echo "${BLD}[6] Sira dogrulugu — kilid imzalamadan SONRA${RST}"
if grep -q "write-enabled false" ci/acr-promote.sh 2>/dev/null; then
  record FAIL "kilid siralanmasi" "acr-promote.sh hele de kilidleyir — imzalama bloklana biler"
else
  record PASS "acr-promote.sh kilidlemir (kilid ci/acr-lock.sh-dedir)"
fi
if grep -q "write-enabled false" ci/acr-lock.sh 2>/dev/null; then
  record PASS "ci/acr-lock.sh kilidleyir"
else
  record FAIL "ci/acr-lock.sh kilidleyir"
fi

echo ""
echo "${BLD}═══════════════════════════════════════════════${RST}"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo ""
[ "${FAIL}" -eq 0 ] && { echo "  ${GRN}${BLD}Phase 4 supply chain: PASS${RST}"; echo ""; exit 0; }
echo "  ${RED}${BLD}Phase 4 supply chain: FAIL${RST}"; echo ""; exit 1
