#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
# cosign-verify.sh — imzanı VƏ imzalayanın kimliyini yoxlayır.
#
# ⚠ ƏN ÇOX RAST GƏLİNƏN SƏHV: "image imzalanıbmı?" sualını yoxlamaq.
#   Bu sual MƏNASIZDIR. Sigstore public instance-dır — istənilən şəxs
#   istənilən image-i imzalaya bilər. `cosign verify` kimlik məhdudiyyəti
#   olmadan yalnız "kimsə bunu imzalayıb" deyir, "BİZ imzalamışıq" demir.
#
#   Doğru sual: "bu image MƏHZ bizim repository-mizin MƏHZ bizim
#   workflow-umuz tərəfindən imzalanıbmı?"
#
#   Ona görə `--certificate-identity-regexp` və `--certificate-oidc-issuer`
#   MƏCBURİDİR (cosign v2+ onsuz keyless verify-a icazə vermir) və biz
#   əlavə olaraq `--certificate-github-workflow-repository` ilə repository-ni
#   də bağlayırıq.
#
# Bu skript üç yerdə təkrar istifadə olunur:
#   1. Phase 4 — CI-də imzalamadan dərhal sonra (müstəqil doğrulama)
#   2. Phase 5 — deploy-dan əvvəl son yoxlama
#   3. Lokal — developer/auditor əl ilə yoxlaya bilsin
# ═════════════════════════════════════════════════════════════════════════════
set -Eeuo pipefail

fail() { printf '::error::%s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

: "${IMAGE_REF:?IMAGE_REF təyin edilməyib (repo@sha256:... formatında)}"

# ── Trust policy ────────────────────────────────────────────────────────────
# Dəyərlər security/cosign/trust-policy.env-dən gəlir (versiya nəzarətində,
# review olunan fayl). Workflow-da hardcoded kimlik YOXDUR.
POLICY_FILE="${TRUST_POLICY_FILE:-security/cosign/trust-policy.env}"
if [ -f "${POLICY_FILE}" ]; then
  # shellcheck source=/dev/null
  source "${POLICY_FILE}"
  note "Trust policy yükləndi: ${POLICY_FILE}"
else
  note "⚠ Trust policy faylı tapılmadı (${POLICY_FILE}) — environment dəyərləri istifadə olunur"
fi

: "${CERT_OIDC_ISSUER:?CERT_OIDC_ISSUER təyin edilməyib}"
: "${CERT_IDENTITY_REGEXP:?CERT_IDENTITY_REGEXP təyin edilməyib}"
: "${EXPECTED_REPOSITORY:?EXPECTED_REPOSITORY təyin edilməyib}"

REFERRERS_MODE="${COSIGN_REFERRERS_MODE:-oci-1-1}"

case "${IMAGE_REF}" in
  *@sha256:*) ;;
  *) fail "IMAGE_REF digest ilə göstərilməlidir (repo@sha256:...), tag ilə YOX." ;;
esac

command -v cosign >/dev/null || fail "cosign tapılmadı"

note ""
note "═══ Cosign verification ═══"
note "  artefakt   : ${IMAGE_REF}"
note "  issuer     : ${CERT_OIDC_ISSUER}"
note "  identity   : ${CERT_IDENTITY_REGEXP}"
note "  repository : ${EXPECTED_REPOSITORY}"
note ""

FAILED=0

# ── 1. İMZA + KİMLİK ────────────────────────────────────────────────────────
note "[1/3] İmza və imzalayan kimliyi yoxlanılır…"
if cosign verify \
     --certificate-oidc-issuer "${CERT_OIDC_ISSUER}" \
     --certificate-identity-regexp "${CERT_IDENTITY_REGEXP}" \
     --certificate-github-workflow-repository "${EXPECTED_REPOSITORY}" \
     --registry-referrers-mode "${REFERRERS_MODE}" \
     --output json \
     "${IMAGE_REF}" > /tmp/verify-sig.json 2>/tmp/verify-sig.err; then
  note "  ✓ İmza etibarlıdır və kimlik uyğundur"
  python3 - <<'PY'
import json
try:
    data = json.load(open("/tmp/verify-sig.json"))
except Exception:
    raise SystemExit(0)
for entry in (data if isinstance(data, list) else [data]):
    opt = (entry.get("optional") or {})
    print(f"    imzalayan  : {opt.get('Subject', '?')}")
    print(f"    issuer     : {opt.get('Issuer', '?')}")
    if opt.get("org.capstone.commit"):
        print(f"    commit     : {opt['org.capstone.commit']}")
    if opt.get("Bundle"):
        payload = (opt["Bundle"].get("Payload") or {})
        if payload.get("logIndex"):
            print(f"    Rekor index: {payload['logIndex']}")
PY
else
  note "  ✗ İMZA DOĞRULANMADI"
  sed 's/^/    /' /tmp/verify-sig.err | head -10
  FAILED=$((FAILED + 1))
fi

# ── 2. SBOM ATTESTATION ─────────────────────────────────────────────────────
note ""
note "[2/3] SBOM attestation yoxlanılır…"
if cosign verify-attestation \
     --type cyclonedx \
     --certificate-oidc-issuer "${CERT_OIDC_ISSUER}" \
     --certificate-identity-regexp "${CERT_IDENTITY_REGEXP}" \
     --certificate-github-workflow-repository "${EXPECTED_REPOSITORY}" \
     --registry-referrers-mode "${REFERRERS_MODE}" \
     "${IMAGE_REF}" > /tmp/verify-sbom.json 2>/tmp/verify-sbom.err; then
  note "  ✓ SBOM attestation etibarlıdır"
else
  note "  ✗ SBOM ATTESTATION DOĞRULANMADI"
  sed 's/^/    /' /tmp/verify-sbom.err | head -5
  FAILED=$((FAILED + 1))
fi

# ── 3. VULN ATTESTATION ─────────────────────────────────────────────────────
note ""
note "[3/3] Vulnerability attestation yoxlanılır…"
if cosign verify-attestation \
     --type vuln \
     --certificate-oidc-issuer "${CERT_OIDC_ISSUER}" \
     --certificate-identity-regexp "${CERT_IDENTITY_REGEXP}" \
     --certificate-github-workflow-repository "${EXPECTED_REPOSITORY}" \
     --registry-referrers-mode "${REFERRERS_MODE}" \
     "${IMAGE_REF}" > /tmp/verify-vuln.json 2>/tmp/verify-vuln.err; then
  note "  ✓ Vulnerability attestation etibarlıdır"
else
  note "  ✗ VULN ATTESTATION DOĞRULANMADI"
  sed 's/^/    /' /tmp/verify-vuln.err | head -5
  FAILED=$((FAILED + 1))
fi

# ── Nəticə ──────────────────────────────────────────────────────────────────
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo ""
    echo "## Gate 7B — Signature verification"
    echo ""
    echo "| Yoxlama | Nəticə |"
    echo "|---|---|"
    echo "| İmza + kimlik | $([ "${FAILED}" -eq 0 ] && echo '✅' || echo '❌') |"
    echo "| SBOM attestation | $([ "${FAILED}" -eq 0 ] && echo '✅' || echo '❌') |"
    echo "| Vuln attestation | $([ "${FAILED}" -eq 0 ] && echo '✅' || echo '❌') |"
    echo ""
    echo "Doğrulama kimlik məhdudiyyəti ilə aparıldı — sadəcə \"imzalanıb\" deyil,"
    echo "**\`${EXPECTED_REPOSITORY}\` repository-sinin workflow-u tərəfindən imzalanıb**."
    echo ""
  } >> "${GITHUB_STEP_SUMMARY}"
fi

note ""
if [ "${FAILED}" -eq 0 ]; then
  note "═══ ✅ Bütün doğrulamalar PASS ═══"
  note ""
  exit 0
fi
note "═══ ❌ ${FAILED} doğrulama UĞURSUZ — artefakt ETİBARSIZ ═══"
note ""
exit 1
