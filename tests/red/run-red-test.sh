#!/usr/bin/env bash
# RED test icraçısı — gate-in FAIL etdiyini yoxlayır.
# Uğur meyarı TƏRSİNƏDİR: gate exit 1 verməlidir.
set -Eeuo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

export PATH="${HOME}/.local/bin:/home/akif/.local/bin:${PATH}"

GATE="${1:-sast}"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

SEMGREP_BIN="$(command -v semgrep || echo /home/akif/.local/bin/semgrep)"

case "${GATE}" in
  sast)
    mkdir -p "${TMP}/src"
    cp tests/red/sast-vulnerable.js.txt "${TMP}/src/vulnerable.js"
    "${SEMGREP_BIN}" scan --config=security/semgrep/rules --metrics=off \
      --json --output="${TMP}/report.json" "${TMP}" >/dev/null 2>&1 || true
    set +e
    python3 ci/severity_gate.py --report "${TMP}/report.json" \
      --format semgrep --scanner semgrep
    rc=$?
    set -e
    ;;
  *)
    echo "Naməlum gate: ${GATE}. Mövcud: sast" >&2
    exit 2
    ;;
esac

echo
if [ "${rc}" -eq 1 ]; then
  echo "✅ RED TEST PASS — gate düzgün şəkildə FAIL etdi (exit ${rc})"
  exit 0
fi
echo "❌ RED TEST FAIL — gate bloklamalı idi, lakin exit ${rc} verdi"
echo "   Bu, security gate-in işləmədiyi deməkdir!"
exit 1
