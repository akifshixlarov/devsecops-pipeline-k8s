#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
# run-precommit-test.sh — Secret Lifecycle Gate 1 (pre-commit) üçün RED/GREEN test.
#
#   RED   : dummy secret stage edilir → commit BLOKLANMALIDIR (exit != 0)
#   GREEN : secret təmizlənir → commit KEÇMƏLİDİR (exit 0)
#
# ⚠ TƏHLÜKƏSİZLİK DİZAYNI:
#   Test secret-i BU FAYLDA SAXLANMIR — runtime-da generasiya olunur.
#   Səbəb: repo-da saxlanılan hər hansı realistik secret CI-dakı Gate 2
#   (gitleaks git — bütün tarixçə) tərəfindən tutulacaq və pipeline-ı
#   əbədi qırmızı saxlayacaq. Test bitdikdən sonra fayl silinir və
#   index bərpa olunur — repository-də heç bir iz qalmır.
#
# ⚠ Bu test heç vaxt `--no-verify` istifadə etmir — məqsəd məhz hook-un
#   həqiqətən bloklayıb-bloklamadığını yoxlamaqdır.
# ═════════════════════════════════════════════════════════════════════════════
set -Eeuo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "${REPO_ROOT}"

GRN=$'\033[32m'; RED=$'\033[31m'; BLD=$'\033[1m'; RST=$'\033[0m'

TEST_FILE="app/src/__precommit_red_test__.js"
PASS=0
FAIL=0

cleanup() {
  git reset -q -- "${TEST_FILE}" 2>/dev/null || true
  rm -f "${TEST_FILE}"
  echo ""
  echo "  (təmizləndi: ${TEST_FILE} silindi, index bərpa olundu)"
}
trap cleanup EXIT

record() {
  if [ "$1" = "PASS" ]; then
    echo "  ${GRN}${BLD}✓ $2 — PASS${RST}"; PASS=$((PASS+1))
  else
    echo "  ${RED}${BLD}✗ $2 — FAIL${RST}  $3"; FAIL=$((FAIL+1))
  fi
}

echo ""
echo "${BLD}═══ Secret Lifecycle Gate 1 — Pre-commit RED/GREEN Test ═══${RST}"
echo ""

# ── Ön şərtlər ──────────────────────────────────────────────────────────────
echo "${BLD}[0] Ön şərtlər${RST}"

HOOKS_PATH="$(git config --get core.hooksPath || echo '')"
if [ "${HOOKS_PATH}" = ".githooks" ]; then
  record PASS "core.hooksPath = .githooks"
else
  record FAIL "core.hooksPath" "cari dəyər: '${HOOKS_PATH:-<təyin edilməyib>}' — işlədin: bash ci/setup-hooks.sh"
  echo ""; echo "${RED}Ön şərt ödənmədi, test dayandırıldı.${RST}"; exit 1
fi

if [ -x .githooks/pre-commit ]; then
  record PASS "hook icra edilə bilir"
else
  record FAIL "hook icra edilə bilir" "chmod +x .githooks/pre-commit"
  exit 1
fi

if command -v gitleaks >/dev/null 2>&1; then
  record PASS "gitleaks mövcuddur ($(gitleaks version 2>/dev/null))"
else
  record FAIL "gitleaks mövcuddur" "bash ci/install-scanners.sh gitleaks"
  exit 1
fi

# İşçi ağac təmiz olmalıdır ki, test digər dəyişikliklərə qarışmasın.
if [ -n "$(git status --porcelain -- "${TEST_FILE}" 2>/dev/null)" ]; then
  echo "  ${RED}Test faylı artıq mövcuddur — əvvəlki test təmizlənməyib.${RST}"
  exit 1
fi

# ═══ RED TEST ═══════════════════════════════════════════════════════════════
echo ""
echo "${BLD}[1] RED TEST — dummy secret ilə commit cəhdi${RST}"

# Secret runtime-da qurulur ki, bu skriptin özündə saxlanmasın.
# Yüksək entropiyalı, LAB-ONLY dəyər — heç bir real sistemə aid deyil.
LAB_VALUE="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"

{
  echo "'use strict';"
  echo "// LAB-ONLY — pre-commit gate testi. Real credential DEYİL."
  echo "const DATABASE_PASSWORD = \"${LAB_VALUE}\";"
  echo "module.exports = { DATABASE_PASSWORD };"
} > "${TEST_FILE}"

git add "${TEST_FILE}"
echo "  stage edildi: ${TEST_FILE}"
echo ""

set +e
git commit -m "test: pre-commit red test (bloklanmalıdır)" >/dev/null 2>&1
COMMIT_RC=$?
set -e

echo ""
if [ "${COMMIT_RC}" -ne 0 ]; then
  record PASS "secret olan commit BLOKLANDI (git exit ${COMMIT_RC})"
else
  record FAIL "secret olan commit BLOKLANDI" "commit keçdi! Hook işləmir — geri alınır."
  git reset -q --soft HEAD~1
fi

# ═══ GREEN TEST ═════════════════════════════════════════════════════════════
echo ""
echo "${BLD}[2] GREEN TEST — secret çıxarıldıqdan sonra commit${RST}"

{
  echo "'use strict';"
  echo "// Düzəliş: secret environment variable-dan oxunur."
  echo "const DATABASE_PASSWORD = process.env.DATABASE_PASSWORD;"
  echo "module.exports = { DATABASE_PASSWORD };"
} > "${TEST_FILE}"

git add "${TEST_FILE}"
echo "  stage edildi (secret çıxarılıb): ${TEST_FILE}"
echo ""

set +e
git commit -m "test: pre-commit green test (keçməlidir)" >/dev/null 2>&1
GREEN_RC=$?
set -e

echo ""
if [ "${GREEN_RC}" -eq 0 ]; then
  record PASS "təmiz commit İCAZƏ VERİLDİ"
  # Test commit-ini geri al — repository tarixçəsi təmiz qalsın.
  git reset -q --hard HEAD~1
  echo "  (test commit-i geri alındı)"
else
  record FAIL "təmiz commit İCAZƏ VERİLDİ" "təmiz kod bloklandı — false positive!"
fi

# ═══ .gitleaksignore hörmət testi ═══════════════════════════════════════════
echo ""
echo "${BLD}[3] Allowlist testi — dummy dəyər susdurulmalıdır${RST}"

{
  echo "'use strict';"
  echo "// gitleaks.toml allowlist-ində qeydə alınmış dummy pattern."
  echo "const TEST_TOKEN = \"DUMMY-NOT-A-REAL-SECRET-0000000000\";"
  echo "module.exports = { TEST_TOKEN };"
} > "${TEST_FILE}"

git add "${TEST_FILE}"
set +e
git commit -m "test: allowlist testi" >/dev/null 2>&1
ALLOW_RC=$?
set -e

echo ""
if [ "${ALLOW_RC}" -eq 0 ]; then
  record PASS "allowlist-dəki dummy dəyər commit-ə icazə verdi"
  git reset -q --hard HEAD~1
else
  record FAIL "allowlist hörmət edilir" "allowlist işləmir — dummy dəyər bloklandı"
fi

# ═══ Nəticə ═════════════════════════════════════════════════════════════════
echo ""
echo "${BLD}═══════════════════════════════════════════════════════════${RST}"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo ""
if [ "${FAIL}" -eq 0 ]; then
  echo "  ${GRN}${BLD}Secret Lifecycle Gate 1 — PRE-COMMIT: PASS${RST}"
  echo ""
  exit 0
fi
echo "  ${RED}${BLD}Secret Lifecycle Gate 1 — PRE-COMMIT: FAIL${RST}"
echo ""
exit 1
