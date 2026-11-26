#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
# setup-hooks.sh — repository clone edildikdən sonra pre-commit müdafiəsini
# aktivləşdirir.
#
# NİYƏ `core.hooksPath` (və `.git/hooks/` DEYİL):
#   `.git/` qovluğu versiya nəzarətində DEYİL — ora fayl commit etmək mümkün
#   deyil. `git config core.hooksPath .githooks` isə Git-ə hook-ları repo
#   daxilindəki (yəni versiya nəzarətindəki, review olunan) qovluqdan
#   oxumağı bildirir. Nəticədə hook:
#     - repo ilə birlikdə paylanır,
#     - code review-dən keçir,
#     - hər developer-də eyni olur.
#
#   Təhlükəsizlik qeydi: `core.hooksPath` LOKAL konfiqurasiyadır və hər
#   developer bir dəfə işə salmalıdır. Bu, dizayn məhdudiyyətidir — məhz
#   ona görə pre-commit gate TƏK müdafiə xətti sayılmır və CI-dakı Gate 2
#   (server tərəfi, bypass edilə bilməyən) mütləq qalır.
# ═════════════════════════════════════════════════════════════════════════════
set -Eeuo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "${REPO_ROOT}"

GRN=$'\033[32m'; RED=$'\033[31m'; YLW=$'\033[33m'; BLD=$'\033[1m'; RST=$'\033[0m'

echo ""
echo "${BLD}Secret Lifecycle Gate 1 — pre-commit hook quraşdırılması${RST}"
echo ""

# ── 1. hooksPath ────────────────────────────────────────────────────────────
git config core.hooksPath .githooks
echo "  ${GRN}✓${RST} core.hooksPath → .githooks"

# ── 2. İcra icazəsi ─────────────────────────────────────────────────────────
# Git hook-u yalnız icra edilə bilən olduqda işlədir. İcazə bit-i repo-da
# saxlanılır, lakin bəzi Windows/arxiv ssenarilərində itə bilər.
chmod +x .githooks/* 2>/dev/null || true
if [ -x .githooks/pre-commit ]; then
  echo "  ${GRN}✓${RST} .githooks/pre-commit icra edilə bilir"
else
  echo "  ${RED}✗${RST} .githooks/pre-commit icra edilə bilmir"
  echo "     Düzəliş: chmod +x .githooks/pre-commit"
  exit 1
fi

# ── 3. Gitleaks mövcudluğu ──────────────────────────────────────────────────
if command -v gitleaks >/dev/null 2>&1; then
  echo "  ${GRN}✓${RST} gitleaks $(gitleaks version 2>/dev/null) tapıldı"
else
  echo "  ${YLW}!${RST} gitleaks tapılmadı — hook commit-ləri bloklayacaq."
  echo ""
  echo "     Quraşdırmaq üçün:"
  echo "       bash ci/install-scanners.sh gitleaks"
  echo "       export PATH=\"\$HOME/.local/bin:\$PATH\""
  echo ""
  echo "     (Bu, qəsdən belədir: alət yoxdursa skan da yoxdur —"
  echo "      hook sükutla keçmək əvəzinə açıq şəkildə fail edir.)"
fi

# ── 4. Konfiqurasiya yoxlaması ──────────────────────────────────────────────
if [ -f security/gitleaks/gitleaks.toml ]; then
  echo "  ${GRN}✓${RST} security/gitleaks/gitleaks.toml (Gate 2 ilə paylaşılır)"
else
  echo "  ${RED}✗${RST} security/gitleaks/gitleaks.toml tapılmadı"
  exit 1
fi

echo ""
echo "${GRN}${BLD}Hazırdır.${RST} Artıq hər \`git commit\` əvvəlcə secret skanından keçəcək."
echo ""
echo "Yoxlamaq üçün:  bash tests/red/run-precommit-test.sh"
echo ""
