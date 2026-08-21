#!/usr/bin/env bash
# Phase 4 fayllarinin yerli repo-da yenilenib-yenilenmediyini yoxlayir.
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
echo ""
echo "=== Phase 4 fayl vəziyyəti ==="
chk() {
  if [ ! -e "$1" ]; then printf '  ❌ YOXDUR      %s\n' "$1"; return; fi
  if [ -n "$2" ] && ! grep -q "$2" "$1" 2>/dev/null; then
    printf '  ⚠️  KÖHNƏDİR   %s   (gözlənilir: %s)\n' "$1" "$2"; return
  fi
  printf '  ✅ OK          %s\n' "$1"
}
chk ci/install-scanners.sh   'install_cosign'
chk ci/scanner-versions.env  'COSIGN_VERSION'
chk ci/cosign-sign.sh        ''
chk ci/cosign-verify.sh      ''
chk ci/acr-lock.sh           ''
chk ci/init-trust-policy.sh  ''
chk ci/acr-promote.sh        'ARXİTEKTURA DÜZƏLİŞİ'
chk security/cosign/trust-policy.env ''
chk docs/supply-chain.md     ''
chk tests/red/run-supply-chain-test.sh ''
chk .github/workflows/build.yml 'gate-7-sign'
echo ""
