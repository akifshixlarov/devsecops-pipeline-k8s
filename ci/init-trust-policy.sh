#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
# init-trust-policy.sh — security/cosign/trust-policy.env faylındakı
# OWNER/REPO placeholder-lərini git remote-dan avtomatik doldurur.
#
# NİYƏ SKRİPT (əl ilə redaktə əvəzinə):
#   Trust policy-də bir simvol səhvi = doğrulama HƏMİŞƏ uğursuz.
#   Daha pisi: regexp həddindən artıq geniş yazılarsa (məs. `.*` əlavə etmək),
#   doğrulama SÜKUTLA mənasızlaşır — hər kəsin imzası qəbul olunur və
#   pipeline yaşıl qalır. Bu, ən təhlükəli nasazlıq növüdür.
#
#   Ona görə dəyərlər git remote-dan çıxarılır və regexp şablonu
#   skriptdə sabit saxlanılır.
#
# İstifadə:
#   bash ci/init-trust-policy.sh              # nəticəni göstərir
#   bash ci/init-trust-policy.sh --write      # faylı yeniləyir
#   bash ci/init-trust-policy.sh --write --owner myorg --repo myrepo
# ═════════════════════════════════════════════════════════════════════════════
set -Eeuo pipefail

GRN=$'\033[32m'; RED=$'\033[31m'; YLW=$'\033[33m'; BLD=$'\033[1m'; RST=$'\033[0m'

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${REPO_ROOT}"

POLICY_FILE="security/cosign/trust-policy.env"
WORKFLOW_FILE="build.yml"
BRANCH="main"
WRITE=0
OWNER="akifshixlarov"
REPO="devsecops-pipeline-k8s"

while [ $# -gt 0 ]; do
  case "$1" in
    --write)     WRITE=1; shift ;;
    --owner)     OWNER="$2"; shift 2 ;;
    --repo)      REPO="$2"; shift 2 ;;
    --workflow)  WORKFLOW_FILE="$2"; shift 2 ;;
    --branch)    BRANCH="$2"; shift 2 ;;
    *) echo "Naməlum arqument: $1" >&2; exit 2 ;;
  esac
done

# ── git remote-dan owner/repo çıxarmaq ──────────────────────────────────────
if [ -z "${OWNER}" ] || [ -z "${REPO}" ]; then
  REMOTE="$(git remote get-url origin 2>/dev/null || echo '')"
  if [ -z "${REMOTE}" ]; then
    echo "${RED}✗ git remote 'origin' tapılmadı.${RST}" >&2
    echo "  --owner və --repo arqumentlərini əl ilə verin, məsələn:" >&2
    echo "    bash ci/init-trust-policy.sh --write --owner myorg --repo myrepo" >&2
    exit 1
  fi
  # Həm SSH (git@github.com:owner/repo.git), həm HTTPS formatını dəstəkləyir.
  SLUG="$(printf '%s' "${REMOTE}" \
    | sed -E 's#^git@github\.com:##; s#^https://github\.com/##; s#\.git$##')"
  OWNER="${OWNER:-${SLUG%%/*}}"
  REPO="${REPO:-${SLUG##*/}}"
fi

if [ -z "${OWNER}" ] || [ -z "${REPO}" ] || [ "${OWNER}" = "${REPO}" ]; then
  echo "${RED}✗ owner/repo müəyyən edilmədi (alınan: '${OWNER}/${REPO}')${RST}" >&2
  exit 1
fi

# ── Regexp qurulması ────────────────────────────────────────────────────────
# Nöqtələr escape edilir: `.` regexp-də istənilən simvoldur, biz LİTERAL
# nöqtə istəyirik. Bunsuz `github.com` həm də `githubXcom`-a uyğunlaşardı.
# Python istifade olunur: sed-in BRE/ERE escape qaydalari platformadan asili
# olaraq ferqlenir ve `{}` kimi simvollarda sinir. re.escape deterministikdir.
esc() { PY_IN="$1" python3 -c 'import os,re; print(re.escape(os.environ["PY_IN"]))'; }

E_OWNER="$(esc "${OWNER}")"
E_REPO="$(esc "${REPO}")"
E_WF="$(esc "${WORKFLOW_FILE}")"
E_BRANCH="$(esc "${BRANCH}")"

IDENTITY_REGEXP="^https://github\\.com/${E_OWNER}/${E_REPO}/\\.github/workflows/${E_WF}@refs/heads/${E_BRANCH}\$"
SAN_EXAMPLE="https://github.com/${OWNER}/${REPO}/.github/workflows/${WORKFLOW_FILE}@refs/heads/${BRANCH}"

echo ""
echo "${BLD}Cosign trust policy${RST}"
echo ""
echo "  owner    : ${OWNER}"
echo "  repo     : ${REPO}"
echo "  workflow : ${WORKFLOW_FILE}"
echo "  branch   : ${BRANCH}"
echo ""
echo "  Gözlənilən Fulcio SAN:"
echo "    ${SAN_EXAMPLE}"
echo ""

# ── Öz-özünü yoxlama ────────────────────────────────────────────────────────
# Yaradılan regexp həqiqətən gözlənilən SAN-a uyğunlaşırmı və saxta
# variantları rədd edirmi? Bu, "yazdım, deməli işləyir" fərziyyəsini aradan qaldırır.
export IDENTITY_REGEXP SAN_EXAMPLE OWNER REPO WORKFLOW_FILE BRANCH
if ! python3 - <<'PY'
import os, re, sys
rx  = os.environ["IDENTITY_REGEXP"]
san = os.environ["SAN_EXAMPLE"]
owner, repo = os.environ["OWNER"], os.environ["REPO"]
wf, br = os.environ["WORKFLOW_FILE"], os.environ["BRANCH"]

cases = [
    (san, True, "legitim CI imzasi"),
    (f"https://github.com/{owner}/{repo}/.github/workflows/{wf}@refs/heads/evil", False, "basqa branch"),
    (f"https://github.com/attacker/{repo}/.github/workflows/{wf}@refs/heads/{br}", False, "basqa owner / fork"),
    (f"https://github.com/{owner}/{repo}/.github/workflows/pwn.yml@refs/heads/{br}", False, "basqa workflow"),
    (f"https://github.com/{owner}/{repo}/.github/workflows/{wf}@refs/tags/v1", False, "tag ref"),
]
bad = 0
print("  Oz-ozunu yoxlama:")
for s, expect, desc in cases:
    got = bool(re.match(rx, s))
    ok = got == expect
    bad += not ok
    print(f"    {'PASS' if ok else 'FAIL'}  {'MATCH ' if got else 'REJECT'}  {desc}")
if re.fullmatch(r'\^?\.\*\$?', rx) or rx.strip() in ("*", ".*"):
    print("    FAIL  regexp hedden artiq genisdir!"); bad += 1
sys.exit(1 if bad else 0)
PY
then
  echo ""
  echo "${RED}✗ Yaradılan regexp yoxlamadan keçmədi — fayl DƏYİŞDİRİLMƏDİ.${RST}" >&2
  exit 1
fi

echo ""

# ── Yazma ───────────────────────────────────────────────────────────────────
if [ "${WRITE}" -ne 1 ]; then
  echo "  ${YLW}Tətbiq etmək üçün:${RST}  bash ci/init-trust-policy.sh --write"
  echo ""
  exit 0
fi

[ -f "${POLICY_FILE}" ] || { echo "${RED}✗ ${POLICY_FILE} tapılmadı${RST}" >&2; exit 1; }

cp "${POLICY_FILE}" "${POLICY_FILE}.bak"

python3 - <<'PY'
import os, re, pathlib
path = pathlib.Path("security/cosign/trust-policy.env")
t = path.read_text(encoding="utf-8")
rx = os.environ["IDENTITY_REGEXP"]
owner, repo = os.environ["OWNER"], os.environ["REPO"]

t = re.sub(r'^CERT_IDENTITY_REGEXP=.*$',
           f'CERT_IDENTITY_REGEXP="{rx}"', t, count=1, flags=re.M)
t = re.sub(r'^EXPECTED_REPOSITORY=.*$',
           f'EXPECTED_REPOSITORY="{owner}/{repo}"', t, count=1, flags=re.M)
path.write_text(t, encoding="utf-8")
PY

echo "  ${GRN}${BLD}✓ ${POLICY_FILE} yeniləndi${RST}  (ehtiyat nüsxə: ${POLICY_FILE}.bak)"
echo ""
grep -E '^(CERT_OIDC_ISSUER|CERT_IDENTITY_REGEXP|EXPECTED_REPOSITORY|COSIGN_REFERRERS_MODE)=' "${POLICY_FILE}" \
  | sed 's/^/    /'
echo ""
echo "  Növbəti addım:  bash tests/red/run-supply-chain-test.sh"
echo ""
