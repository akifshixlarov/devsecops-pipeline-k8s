#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
# render-kyverno-policy.sh — admission policy şablonunu trust-policy.env
# dəyərləri ilə doldurur.
#
# NİYƏ ŞABLON + RENDER (hazır YAML əvəzinə):
#   İmzalayan kimlik ÜÇ yerdə istifadə olunur:
#     1. ci/cosign-verify.sh      (CI doğrulaması, Gate 7B)
#     2. lokal audit              (auditor əl ilə yoxlayır)
#     3. Kyverno admission policy (cluster)
#
#   Əgər kimlik hər yerdə ayrıca yazılsaydı, biri yenilənəndə digərləri
#   unudula bilərdi. Ən təhlükəli hal: CI-də dar, admission-da geniş —
#   nəticədə cluster hər imzanı qəbul edir, amma dashboard yaşıl görünür.
#
#   Ona görə YEGANƏ mənbə: security/cosign/trust-policy.env
# ═════════════════════════════════════════════════════════════════════════════
set -Eeuo pipefail

fail() { printf '::error::%s\n' "$*" >&2; exit 1; }

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${REPO_ROOT}"

TEMPLATE="k8s/policy/kyverno-verify-images.yaml"
OUTPUT="${1:-/tmp/kyverno-verify-images.rendered.yaml}"
POLICY_FILE="security/cosign/trust-policy.env"

[ -f "${TEMPLATE}" ]    || fail "şablon tapılmadı: ${TEMPLATE}"
[ -f "${POLICY_FILE}" ] || fail "trust policy tapılmadı: ${POLICY_FILE}"

# shellcheck source=/dev/null
. "${POLICY_FILE}"

: "${CERT_OIDC_ISSUER:?trust-policy.env-də CERT_OIDC_ISSUER yoxdur}"
: "${CERT_IDENTITY_REGEXP:?trust-policy.env-də CERT_IDENTITY_REGEXP yoxdur}"
: "${ACR_NAME:?ACR_NAME environment dəyişəni təyin edilməyib}"

# ── Fail-closed yoxlamalar ──────────────────────────────────────────────────
# Doldurulmamış placeholder cluster-ə getməməlidir.
case "${CERT_IDENTITY_REGEXP}" in
  *OWNER*)
    fail "trust-policy.env hələ doldurulmayıb (OWNER placeholder qalıb).
     İşlədin: bash ci/init-trust-policy.sh --write" ;;
esac

# Həddindən artıq geniş regexp doğrulamanı mənasızlaşdırır — render mərhələsində dayandırırıq.
case "${CERT_IDENTITY_REGEXP}" in
  ".*"|"^.*$"|"*"|"")
    fail "CERT_IDENTITY_REGEXP həddindən artıq genişdir: '${CERT_IDENTITY_REGEXP}'
     Belə policy İSTƏNİLƏN imzanı qəbul edər — Sigstore public instance-dır.
     Bu, doğrulamanı tamamilə mənasızlaşdırır." ;;
esac

if [ "${CERT_OIDC_ISSUER}" != "https://token.actions.githubusercontent.com" ]; then
  fail "Gözlənilməyən OIDC issuer: ${CERT_OIDC_ISSUER}
     GitHub Actions üçün dəyər dəqiq olmalıdır."
fi

LOGIN_SERVER="${ACR_NAME}.azurecr.io"

# ── Render ──────────────────────────────────────────────────────────────────
# Python istifadə olunur: regexp-də `/`, `&`, `\` simvolları var və sed
# bunları xüsusi məna kimi oxuyur (səssiz korlanma riski).
CERT_IDENTITY_REGEXP="${CERT_IDENTITY_REGEXP}" \
CERT_OIDC_ISSUER="${CERT_OIDC_ISSUER}" \
LOGIN_SERVER="${LOGIN_SERVER}" \
TEMPLATE="${TEMPLATE}" \
OUTPUT="${OUTPUT}" \
python3 <<'PY'
import os, pathlib
t = pathlib.Path(os.environ["TEMPLATE"]).read_text(encoding="utf-8")
# Sablonda bu deyerler TEK dirnaq icindedir (regexp backslash saxlayir,
# YAML cut dirnaqda `\.` etibarsiz escape verir).
# Tek dirnaqli YAML skalyarinda yeganə xususi simvol `'` -dir ve o,
# ikiqat yazilmaqla escape olunur.
def yaml_sq(value: str) -> str:
    return value.replace("'", "''")

subs = {
    "__CERT_IDENTITY_REGEXP__": yaml_sq(os.environ["CERT_IDENTITY_REGEXP"]),
    "__CERT_OIDC_ISSUER__":     yaml_sq(os.environ["CERT_OIDC_ISSUER"]),
    "__ACR_LOGIN_SERVER__":     yaml_sq(os.environ["LOGIN_SERVER"]),
}
for k, v in subs.items():
    t = t.replace(k, v)

# Doldurulmamiş placeholder qalibsa dayandir.
leftover = [ln for ln in t.splitlines() if "__CERT_" in ln or "__ACR_LOGIN_SERVER__" in ln]
if leftover:
    raise SystemExit("RENDER XETASI — doldurulmamiş placeholder:\n" + "\n".join(leftover[:5]))

pathlib.Path(os.environ["OUTPUT"]).write_text(t, encoding="utf-8")
print(f"Render tamamlandi -> {os.environ['OUTPUT']}")
PY

echo ""
echo "Tetbiq olunan deyerler:"
echo "  issuer   : ${CERT_OIDC_ISSUER}"
echo "  subject  : ${CERT_IDENTITY_REGEXP}"
echo "  registry : ${LOGIN_SERVER}/capstone/app*"
echo ""
echo "Tetbiq etmek ucun:  kubectl apply -f ${OUTPUT}"
echo ""
