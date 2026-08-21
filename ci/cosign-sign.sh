#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
# cosign-sign.sh — promote edilmiş image-i keyless (OIDC) imzalayır və
# ona SBOM + vulnerability attestation-ları bağlayır.
#
#   GitHub Actions OIDC → Fulcio (qısaömürlü sertifikat) → imza
#                                      ↓
#                          Rekor transparency log (public, immutable)
#
# NİYƏ KEYLESS (statik açar DEYİL):
#   Statik cosign açarı ilə imzalamaq problemi HƏLL ETMİR, sadəcə köçürür:
#   indi qorunmalı olan uzunömürlü private key var. O sızarsa, hücumçu
#   istənilən image-i "etibarlı" kimi imzalaya bilər və bunu aşkarlamaq
#   mümkün olmur.
#
#   Keyless modeldə:
#     - private key EPHEMERAL-dir (~10 dəqiqə yaşayır, diskə yazılmır);
#     - kimlik GitHub-un OIDC token-idir (repo + workflow + branch);
#     - hər imza Rekor-a yazılır → kim, nə vaxt, hansı workflow-dan
#       imzaladı sualı SONRADAN da cavablandırıla bilir (non-repudiation,
#       threat model § 3.5 STRIDE-R).
#   Oğurlanacaq açar yoxdur.
#
# İMZALAMA HƏMİŞƏ DIGEST İLƏ APARILIR, TAG İLƏ YOX:
#   Tag mutable-dır. `cosign sign registry/app:v1` yazsanız, cosign tag-ı
#   digest-ə həll edir və HƏMİN ANDAKI manifest-i imzalayır. Tag sonra başqa
#   manifest-ə keçirilərsə, imza "sanki" hələ də mövcuddur, lakin tamam
#   başqa məzmuna aiddir. Ona görə bu skript yalnız `repo@sha256:...` qəbul edir.
# ═════════════════════════════════════════════════════════════════════════════
set -Eeuo pipefail

fail() { printf '::error::%s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

: "${IMAGE_REF:?IMAGE_REF təyin edilməyib (repo@sha256:... formatında)}"

# Referrers rejimi. ACR OCI 1.1 Referrers API-ni dəstəkləyir, LAKİN
# customer-managed key (CMK) ilə şifrələnmiş registry-lərdə dəstəklənmir.
# Belə halda `legacy` (sha256-<digest>.sig tag sxemi) istifadə edilməlidir.
# Default `oci-1-1`-dir; CMK registry üçün COSIGN_REFERRERS_MODE=legacy verin.
REFERRERS_MODE="${COSIGN_REFERRERS_MODE:-oci-1-1}"

# ── Giriş validasiyası: yalnız digest ────────────────────────────────────────
case "${IMAGE_REF}" in
  *@sha256:*) ;;
  *) fail "IMAGE_REF digest ilə göstərilməlidir (repo@sha256:...), tag ilə YOX.
     Alınan: ${IMAGE_REF}
     Səbəb: tag mutable-dır — imza ilə məzmun arasındakı bağ qırıla bilər." ;;
esac

command -v cosign >/dev/null || fail "cosign tapılmadı (bash ci/install-scanners.sh cosign)"

note ""
note "═══ Cosign keyless signing ═══"
note "  artefakt : ${IMAGE_REF}"
note "  rejim    : keyless (Fulcio + Rekor)"
note "  referrers: ${REFERRERS_MODE}"
note "  cosign   : $(cosign version --json 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("gitVersion","?"))' 2>/dev/null || echo '?')"
note ""

# ── 1. İMZA ─────────────────────────────────────────────────────────────────
# `--yes`  : interaktiv təsdiqi atlayır (CI-də terminal yoxdur).
# Ambient OIDC: cosign GitHub Actions mühitini avtomatik aşkarlayır və
#   ACTIONS_ID_TOKEN_REQUEST_* dəyişənlərindən token alır. Bunun üçün
#   workflow-da `permissions: id-token: write` OLMALIDIR.
# `--tlog-upload` İSTİFADƏ EDİLMİR: cosign v3-də deprecated-dir və
#   `--use-signing-config` ilə birlikdə xəta verir. Rekor-a yazılma
#   default davranışdır və bizim üçün MƏQSƏDDİR (auditability), söndürülmür.
note "[1/4] Image imzalanır…"
cosign sign \
  --yes \
  --registry-referrers-mode "${REFERRERS_MODE}" \
  --annotations "org.capstone.commit=${GITHUB_SHA:-local}" \
  --annotations "org.capstone.workflow=${GITHUB_WORKFLOW:-local}" \
  --annotations "org.capstone.run-id=${GITHUB_RUN_ID:-local}" \
  "${IMAGE_REF}" \
  || fail "cosign sign uğursuz — 'permissions: id-token: write' varmı? ACR-də AcrPush icazəsi varmı?"

note "✓ İmza yükləndi"

# ── 2. SBOM ATTESTATION ─────────────────────────────────────────────────────
# NİYƏ BURADA YENİDƏN SBOM YARADIRIQ (Gate 2-dəki SBOM-u istifadə etmək əvəzinə):
#   Gate 2-dəki SBOM MƏNBƏ KODUNUN SBOM-udur (package-lock.json əsasında).
#   Bu isə IMAGE-in SBOM-udur: base image-in OS paketləri (glibc, openssl,
#   ca-certificates…) da daxildir. İkisi FƏRQLİ artefaktdır və hər ikisi
#   lazımdır. Deploy edilən şey image olduğuna görə, imzalanan SBOM da
#   image-in SBOM-u olmalıdır.
note ""
note "[2/4] Image SBOM yaradılır (CycloneDX)…"
trivy image \
  --format cyclonedx \
  --output /tmp/image-sbom.cdx.json \
  --quiet \
  "${IMAGE_REF}" \
  || fail "SBOM yaradılmadı"

COMPONENTS="$(python3 -c "
import json
d = json.load(open('/tmp/image-sbom.cdx.json'))
print(len(d.get('components', [])))
")"
note "  komponent sayı: ${COMPONENTS}"

note "  SBOM attestation imzalanır…"
cosign attest \
  --yes \
  --type cyclonedx \
  --predicate /tmp/image-sbom.cdx.json \
  --registry-referrers-mode "${REFERRERS_MODE}" \
  "${IMAGE_REF}" \
  || fail "SBOM attestation uğursuz"

note "✓ SBOM attestation bağlandı"

# ── 3. VULNERABILITY ATTESTATION ────────────────────────────────────────────
# Bu, "bu image imzalandığı anda skan edilmişdi və nəticə budur" faktını
# kriptoqrafik olaraq təsbit edir. Sonradan "biz bunu skan etmişdik" iddiası
# yoxlanıla bilən sübuta çevrilir (threat model § 3.3 STRIDE-R:
# "hansı image-in hansı scan nəticəsinə uyğun olduğuna dair immutable link yoxdur").
note ""
note "[3/4] Vulnerability scan nəticəsi attestation kimi bağlanır…"
trivy image \
  --format cosign-vuln \
  --output /tmp/image-vuln.json \
  --quiet \
  "${IMAGE_REF}" \
  || fail "vuln predicate yaradılmadı"

cosign attest \
  --yes \
  --type vuln \
  --predicate /tmp/image-vuln.json \
  --registry-referrers-mode "${REFERRERS_MODE}" \
  "${IMAGE_REF}" \
  || fail "vuln attestation uğursuz"

note "✓ Vulnerability attestation bağlandı"

# ── 4. NƏTİCƏLƏR ────────────────────────────────────────────────────────────
note ""
note "[4/4] Artefaktlar saxlanılır…"
cp /tmp/image-sbom.cdx.json ./image-sbom.cdx.json 2>/dev/null || true

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo ""
    echo "## Gate 7 — Cosign keyless signing"
    echo ""
    echo "| Element | Dəyər |"
    echo "|---|---|"
    echo "| İmzalanmış artefakt | \`${IMAGE_REF}\` |"
    echo "| İmzalama rejimi | keyless (Fulcio + Rekor) |"
    echo "| Referrers rejimi | \`${REFERRERS_MODE}\` |"
    echo "| SBOM komponentləri | ${COMPONENTS} |"
    echo "| Attestation-lar | \`cyclonedx\` (SBOM), \`vuln\` (scan nəticəsi) |"
    echo "| Kimlik | \`${GITHUB_WORKFLOW_REF:-local}\` |"
    echo ""
    echo "> Uzunömürlü private key istifadə **edilmədi**. İmzalama açarı"
    echo "> ephemeral idi və diskə yazılmadı; kimlik Rekor transparency"
    echo "> log-una yazıldı və sonradan audit edilə bilər."
    echo ""
  } >> "${GITHUB_STEP_SUMMARY}"
fi

note ""
note "═══ İmzalama tamamlandı ═══"
note ""
