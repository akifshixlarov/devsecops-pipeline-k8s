#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
# make-red-branch.sh — capstone evidence üçün qəsdən RED pipeline yaradır.
#
# Hər çağırış:
#   1. main-dən təmiz branch açır
#   2. YALNIZ bir gate-i pozan minimal dəyişiklik edir
#   3. commit + push edir (pre-commit hook bypass problemi həll olunur)
#   4. PR açır və Actions linkini verir
#
# NİYƏ AYRICA BRANCH (main-də deyil):
#   RED pipeline-lar GitHub Actions tarixçəsində ƏBƏDİ qalır. Bu, bizim
#   üçün SÜBUTDUR — amma `main`-in tarixçəsi yaşıl qalmalıdır ki, portfolio
#   "işləyən pipeline" təəssüratı versin. Branch/PR üzərində RED göstərmək
#   həm sübut verir, həm main-i təmiz saxlayır.
#
# NİYƏ HƏR GATE ÜÇÜN AYRICA BRANCH:
#   Bir branch-də bütün zəiflikləri inject etsək, pipeline ilk uğursuz
#   gate-də dayanmır (job-lar paraleldir), lakin screenshot-da hansı
#   dəyişikliyin hansı gate-i pozduğu görünmür. Ayrı-ayrı branch-lər
#   "səbəb → nəticə" əlaqəsini birmənalı edir.
#
# İSTİFADƏ:
#   bash tests/red/make-red-branch.sh sast
#   bash tests/red/make-red-branch.sh --list
#   bash tests/red/make-red-branch.sh --cleanup
# ═════════════════════════════════════════════════════════════════════════════
set -Eeuo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "${REPO_ROOT}"

GRN=$'\033[32m'; RED=$'\033[31m'; YLW=$'\033[33m'; BLD=$'\033[1m'; RST=$'\033[0m'
PREFIX="evidence/red"

usage() {
  cat <<'EOF'

RED evidence branch generator

  bash tests/red/make-red-branch.sh <gate>
  bash tests/red/make-red-branch.sh --list
  bash tests/red/make-red-branch.sh --cleanup

Mövcud gate-lər:
  sast        Gate 1  — Semgrep: hardcoded secret + eval
  sca         Gate 2  — Trivy SCA: köhnə, zəif dependency
  secret      Gate 3  — Gitleaks: repo-ya secret commit
  iac         Gate 4  — Trivy config: privileged K8s manifest
  ci          Gate 4B — zizmor: təhlükəli workflow dəyişikliyi
  dockerfile  Gate 6A — Hadolint: USER root + :latest
  all         hamısını ardıcıl yaradır

EOF
}

[ $# -eq 0 ] && { usage; exit 0; }

# ── Ön şərtlər ──────────────────────────────────────────────────────────────
require_clean() {
  if [ -n "$(git status --porcelain)" ]; then
    echo "${RED}✗ İşçi ağac təmiz deyil.${RST} Əvvəlcə commit və ya stash edin:" >&2
    git status --short >&2
    exit 1
  fi
}

DEFAULT_BRANCH="$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's|.*/||' || echo main)"

new_branch() {
  local name="${PREFIX}/$1"
  git checkout "${DEFAULT_BRANCH}" --quiet
  git pull --quiet origin "${DEFAULT_BRANCH}" 2>/dev/null || true
  git branch -D "${name}" --quiet 2>/dev/null || true
  git checkout -b "${name}" --quiet
  echo "${name}"
}

# ⚠ pre-commit hook (Secret Lifecycle Gate 1) bu commit-ləri BLOKLAYACAQ —
# çünki o, məhz bunun üçün qurulub. Evidence yaratmaq üçün açıq şəkildə
# `--no-verify` istifadə edirik və bunu log-a yazırıq.
#
# Bu, "hook-u aldatmaq" deyil: hook-un işlədiyini ARTIQ Phase 2 remediation-da
# sübut etmişik (tests/red/run-precommit-test.sh). Burada məqsəd SERVER
# tərəfindəki Gate 2-nin işlədiyini göstərməkdir — yəni lokal bypass olsa da
# CI-nin tutduğunu.
commit_push() {
  local branch="$1" msg="$2"
  git add -A
  echo "  ${YLW}qeyd:${RST} pre-commit hook --no-verify ilə bypass edilir"
  echo "        (məqsəd: SERVER tərəfindəki gate-in tutduğunu göstərmək)"
  git commit --no-verify -q -m "${msg}"
  git push -u origin "${branch}" --force-with-lease --quiet
  echo "  ${GRN}✓${RST} push edildi: ${branch}"
}

open_pr() {
  local branch="$1" title="$2" body="$3"
  if command -v gh >/dev/null 2>&1; then
    gh pr create --base "${DEFAULT_BRANCH}" --head "${branch}" \
      --title "${title}" --body "${body}" --draft 2>/dev/null \
      && echo "  ${GRN}✓${RST} draft PR açıldı" \
      || echo "  ${YLW}!${RST} PR açılmadı (artıq mövcud ola bilər)"
    gh pr view "${branch}" --json url -q .url 2>/dev/null | sed 's/^/  PR: /' || true
  else
    local slug
    slug="$(git remote get-url origin | sed -E 's#^git@github\.com:##; s#^https://github\.com/##; s#\.git$##')"
    echo "  PR açmaq üçün: https://github.com/${slug}/compare/${branch}?expand=1"
  fi
  echo ""
  echo "  ${BLD}Actions:${RST} repo → Actions → 'Security Gates' → son run"
  echo ""
}

# ═══ Gate ssenariləri ═══════════════════════════════════════════════════════

red_sast() {
  local b; b="$(new_branch sast)"
  echo "${BLD}Gate 1 — SAST (Semgrep)${RST}"
  cat > app/src/config.js <<'EOF'
'use strict';
// LAB-ONLY — Gate 1 (SAST) evidence ucun qesden zeif kod.
// Bu fayl heç vaxt main-e merge edilmemelidir.

// capstone-hardcoded-secret-assignment qaydasini tetikleyir
const JWT_SECRET = "DUMMY-NOT-A-REAL-SECRET-evidence-0001";

// capstone-eval-like-construct qaydasini tetikleyir
function calc(expr) {
  return eval(expr);
}

module.exports = { JWT_SECRET, calc };
EOF
  commit_push "${b}" "test(evidence): SAST gate RED — hardcoded secret + eval"
  open_pr "${b}" "[RED EVIDENCE] Gate 1 — SAST" \
    "Qesden zeif kod: hardcoded secret + eval. Gate 1 (Semgrep) bloklamalidir. **Merge EDILMEMELIDIR.**"
  echo "  ${BLD}Gözlənilən:${RST} Gate 1 ❌ · digərləri ✅ · Security Gate (required) ❌"
}

red_sca() {
  local b; b="$(new_branch sca)"
  echo "${BLD}Gate 2 — SCA (Trivy)${RST}"
  # Zeif versiya: lodash 4.17.15 (CVE-2020-8203, CVE-2021-23337 — HIGH/CRITICAL)
  python3 - <<'PY'
import json, pathlib
p = pathlib.Path("app/package.json")
d = json.loads(p.read_text(encoding="utf-8"))
d["dependencies"]["lodash"] = "4.17.15"
p.write_text(json.dumps(d, indent=2) + "\n", encoding="utf-8")
print("  lodash@4.17.15 elave edildi (bilinen CVE-ler)")
PY
  ( cd app && npm install --package-lock-only --no-audit --no-fund --silent )
  commit_push "${b}" "test(evidence): SCA gate RED — vulnerable lodash 4.17.15"
  open_pr "${b}" "[RED EVIDENCE] Gate 2 — SCA" \
    "lodash@4.17.15 (CVE-2020-8203, CVE-2021-23337). Gate 2 bloklamalidir. **Merge EDILMEMELIDIR.**"
  echo "  ${BLD}Gözlənilən:${RST} Gate 2 ❌ (HIGH/CRITICAL CVE)"
}

red_secret() {
  local b; b="$(new_branch secret)"
  echo "${BLD}Gate 3 — Secret Detection (Gitleaks)${RST}"
  # Yuksek entropiyali, LAB-ONLY deyer — runtime-da generasiya olunur ki,
  # bu skriptin ozunde saxlanmasin.
  local lab_value
  lab_value="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"
  cat > app/src/db-config.js <<EOF
'use strict';
// LAB-ONLY — Gate 3 (Secret Detection) evidence.
// Bu deyer generasiya olunmuş saxta dəyərdir, real credential DEYIL.
const DATABASE_PASSWORD = "${lab_value}";
module.exports = { DATABASE_PASSWORD };
EOF
  commit_push "${b}" "test(evidence): secret gate RED — hardcoded credential"
  open_pr "${b}" "[RED EVIDENCE] Gate 3 — Secret Detection" \
    "Hardcoded credential (LAB-ONLY, generasiya olunmuş deyer). Gate 3 bloklamalidir. **Merge EDILMEMELIDIR.**"
  echo "  ${BLD}Gözlənilən:${RST} Gate 3 ❌ (sıfır tolerantlıq)"
}

red_iac() {
  local b; b="$(new_branch iac)"
  echo "${BLD}Gate 4 — IaC (Trivy config)${RST}"
  cp tests/red/Deployment.red.txt k8s/app/insecure-deployment.yaml
  commit_push "${b}" "test(evidence): IaC gate RED — privileged + hostPath"
  open_pr "${b}" "[RED EVIDENCE] Gate 4 — IaC" \
    "privileged: true, hostPath: /, hostNetwork, runAsUser: 0. Gate 4 bloklamalidir. **Merge EDILMEMELIDIR.**"
  echo "  ${BLD}Gözlənilən:${RST} Gate 4 ❌ (7+ HIGH misconfiguration)"
}

red_ci() {
  local b; b="$(new_branch ci)"
  echo "${BLD}Gate 4B — CI/CD Security (zizmor)${RST}"
  cat > .github/workflows/insecure-example.yml <<'EOF'
# LAB-ONLY — Gate 4B (zizmor) evidence ucun qesden tehlukeli workflow.
name: Insecure Example

on:
  pull_request_target:      # zizmor: dangerous-triggers
    types: [opened]

permissions: write-all      # zizmor: excessive-permissions

jobs:
  demo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4   # zizmor: unpinned-uses (SHA yoxdur)
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Echo untrusted input
        # zizmor: template-injection — PR başlığı birbaşa shell-e otururulur
        run: echo "PR title: ${{ github.event.pull_request.title }}"
EOF
  commit_push "${b}" "test(evidence): CI security gate RED — template injection"
  open_pr "${b}" "[RED EVIDENCE] Gate 4B — CI/CD Security" \
    "pull_request_target + write-all + template injection. Gate 4B bloklamalidir. **Merge EDILMEMELIDIR.**"
  echo "  ${BLD}Gözlənilən:${RST} Gate 4B ❌ (template-injection, excessive-permissions)"
}

red_dockerfile() {
  local b; b="$(new_branch dockerfile)"
  echo "${BLD}Gate 6A — Dockerfile (Hadolint)${RST}"
  cp app/Dockerfile /tmp/Dockerfile.backup
  cp tests/red/Dockerfile.red.txt app/Dockerfile
  commit_push "${b}" "test(evidence): Dockerfile gate RED — USER root + :latest"
  open_pr "${b}" "[RED EVIDENCE] Gate 6A — Dockerfile" \
    "USER root, FROM node:latest, ADD https://. Gate 6A bloklamalidir. **Merge EDILMEMELIDIR.**"
  echo "  ${BLD}Gözlənilən:${RST} Gate 6A ❌ (DL3002, DL3007, DL3066)"
}

cleanup() {
  echo ""
  echo "${BLD}Evidence branch-ləri silinir…${RST}"
  git checkout "${DEFAULT_BRANCH}" --quiet 2>/dev/null || true
  local n=0
  while read -r b; do
    [ -z "${b}" ] && continue
    git branch -D "${b}" --quiet 2>/dev/null && n=$((n+1)) || true
    git push origin --delete "${b}" --quiet 2>/dev/null || true
  done < <(git branch --list "${PREFIX}/*" | tr -d ' *')
  echo "  ${GRN}✓${RST} ${n} lokal branch silindi (remote-dan da silinməyə çalışıldı)"
  echo ""
  echo "  ${YLW}Qeyd:${RST} Actions run tarixçəsi QALIR — screenshot-larınız etibarlıdır."
  echo ""
}

# ═══ Main ═══════════════════════════════════════════════════════════════════
case "${1}" in
  --list|-l)    usage; exit 0 ;;
  --cleanup|-c) cleanup; exit 0 ;;
esac

require_clean
ORIGINAL="$(git rev-parse --abbrev-ref HEAD)"
trap 'git checkout "${ORIGINAL}" --quiet 2>/dev/null || true' EXIT

echo ""
case "${1}" in
  sast)        red_sast ;;
  sca)         red_sca ;;
  secret)      red_secret ;;
  iac)         red_iac ;;
  ci)          red_ci ;;
  dockerfile)  red_dockerfile ;;
  all)
    for g in sast sca secret iac ci dockerfile; do
      "red_${g}"; echo ""
    done
    ;;
  *) echo "${RED}Naməlum gate: ${1}${RST}"; usage; exit 2 ;;
esac

echo ""
echo "${YLW}${BLD}⚠ Bu branch-lər HEÇ VAXT merge edilməməlidir.${RST}"
echo "  Screenshot-lar alındıqdan sonra:  bash tests/red/make-red-branch.sh --cleanup"
echo ""
