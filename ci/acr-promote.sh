#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
# acr-promote.sh — image-i quarantine repository-dən release repository-yə
# server-side köçürür, digest-in dəyişmədiyini SÜBUT edir və manifest-i kilidləyir.
#
# NİYƏ QUARANTINE NAXIŞI:
#   Klassik pipeline: build → push → scan. Problem: scan uğursuz olsa belə,
#   zəif image ARTIQ registry-dədir və istənilən nəfər onu pull edə bilər.
#   `:latest` və ya paylaşılan tag varsa, hətta təsadüfən deploy oluna bilər.
#
#   Bizim naxış:
#       build → push to  <repo>-quarantine:<sha>   (yalnız CI oxuya bilər)
#             → Hadolint / Trivy CVE / Trivy secret gate-ləri
#             → PASS olduqda:  promote to <repo>:<sha>   (deploy mənbəyi)
#             → manifest-i kilidlə (write/delete disabled)
#
#   Yəni release repository-də YALNIZ bütün gate-lərdən keçmiş image olur.
#   Bu, Phase 4-də Cosign imzalama üçün də doğru sıranı təmin edir:
#   imzalanan artefakt artıq skan edilmiş artefaktdır.
#
# NİYƏ `az acr import` (docker pull+push DEYİL):
#   - server-side işləyir: baytlar runner-dən keçmir (sürətli, ucuz);
#   - manifest OLDUĞU KİMİ köçürülür → digest DƏYİŞMİR.
#   Digest-in eyni qalması kritikdir: skan etdiyimiz artefakt ilə deploy
#   etdiyimiz artefakt eyni olmalıdır. Aşağıda bunu iddia etmirik — YOXLAYIRIQ.
# ═════════════════════════════════════════════════════════════════════════════
set -Eeuo pipefail

fail() { printf '::error::%s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

: "${ACR_NAME:?ACR_NAME təyin edilməyib}"
: "${IMAGE_REPO:?IMAGE_REPO təyin edilməyib (məs. capstone/app)}"
: "${IMAGE_TAG:?IMAGE_TAG təyin edilməyib (commit SHA)}"
: "${QUARANTINE_DIGEST:?QUARANTINE_DIGEST təyin edilməyib (build mərhələsindən)}"

QUARANTINE_REPO="${IMAGE_REPO}-quarantine"
LOGIN_SERVER="${ACR_NAME}.azurecr.io"

note ""
note "═══ ACR Promotion ═══"
note "  mənbə : ${QUARANTINE_REPO}@${QUARANTINE_DIGEST}"
note "  hədəf : ${IMAGE_REPO}:${IMAGE_TAG}"
note ""

# ── 1. Promotion (server-side kopyalama) ────────────────────────────────────
# Mənbə DIGEST ilə göstərilir, tag ilə deyil — TOCTOU (time-of-check to
# time-of-use) hücumunun qarşısını alır: tag skan ilə promote arasında
# başqa manifest-ə keçirilə bilər, digest isə keçirilə bilməz.
note "Image promote edilir (az acr import, server-side)…"
az acr import \
  --name "${ACR_NAME}" \
  --source "${LOGIN_SERVER}/${QUARANTINE_REPO}@${QUARANTINE_DIGEST}" \
  --image "${IMAGE_REPO}:${IMAGE_TAG}" \
  --output none \
  || fail "az acr import uğursuz — CI identity-də AcrPush rolu varmı?"

note "✓ Import tamamlandı"

# ── 2. DIGEST DOĞRULAMASI (iddia deyil, yoxlama) ────────────────────────────
# Bu addım bütün supply chain-in dayaq nöqtəsidir. Əgər promote edilmiş
# manifest-in digest-i skan etdiyimizdən fərqlidirsə, deməli deploy edəcəyimiz
# artefakt SKAN EDİLMƏMİŞ artefaktdır → dərhal dayan.
PROMOTED_DIGEST="$(
  az acr repository show \
    --name "${ACR_NAME}" \
    --image "${IMAGE_REPO}:${IMAGE_TAG}" \
    --query digest -o tsv 2>/dev/null
)" || fail "promote edilmiş image-in digest-i alınmadı"

note ""
note "Digest doğrulaması:"
note "  quarantine : ${QUARANTINE_DIGEST}"
note "  promoted   : ${PROMOTED_DIGEST}"

if [ "${PROMOTED_DIGEST}" != "${QUARANTINE_DIGEST}" ]; then
  fail "DIGEST UYĞUNSUZLUĞU! Skan edilən artefakt ilə promote edilən artefakt
        eyni deyil. Bu, supply-chain pozuntusudur — promotion ləğv edilir."
fi
note "  ✓ EYNİDİR — skan edilən artefakt = deploy ediləcək artefakt"

# ── 3. Immutability HARADADIR? ──────────────────────────────────────────────
#
# ⚠ ARXİTEKTURA DÜZƏLİŞİ (Phase 4-də aşkarlandı):
#   Əvvəlcə manifest kilidi (write/delete disabled) MƏHZ BURADA idi.
#   Bu, SƏHV SIRA idi.
#
#   Səbəb: Cosign imzanı və attestation-ları OCI 1.1 Referrers API ilə
#   subject manifest-ə bağlayır. Kilidlənmiş manifest-ə referrer əlavə etmək
#   ACR-in referrers indeksini yeniləməyi tələb edir — bu, konfiqurasiyadan
#   asılı olaraq kiliddən sonra uğursuz ola bilər.
#
#   Düzgün sıra:
#       promote → digest doğrula → SIGN + ATTEST → verify → LOCK
#
#   Yəni artefakt yalnız imzalandıqdan SONRA "final" sayılır və kilidlənir.
#   Kilid indi ayrıca skriptdədir: ci/acr-lock.sh (Phase 4-də çağırılır).
#
# Bu mərhələdə image promote edilib və digest doğrulanıb, lakin HƏLƏ
# İMZALANMAYIB — ona görə deploy edilə bilməz (Phase 5-də imza tələb olunur).

# ── 5. Nəticələrin ötürülməsi ───────────────────────────────────────────────
IMMUTABLE_REF="${LOGIN_SERVER}/${IMAGE_REPO}@${PROMOTED_DIGEST}"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "image_digest=${PROMOTED_DIGEST}"
    echo "image_ref=${IMMUTABLE_REF}"
    echo "image_tag_ref=${LOGIN_SERVER}/${IMAGE_REPO}:${IMAGE_TAG}"
  } >> "${GITHUB_OUTPUT}"
fi

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo ""
    echo "## Image promoted to ACR"
    echo ""
    echo "| Sahə | Dəyər |"
    echo "|---|---|"
    echo "| Registry | \`${LOGIN_SERVER}\` |"
    echo "| Repository | \`${IMAGE_REPO}\` |"
    echo "| Tag | \`${IMAGE_TAG}\` |"
    echo "| Digest | \`${PROMOTED_DIGEST}\` |"
    echo "| Immutable reference | \`${IMMUTABLE_REF}\` |"
    echo "| Status | ⚠️ İMZALANMAYIB — hələ deploy edilə bilməz |"
    echo ""
    echo "> Növbəti addım: Gate 7 (Cosign imzalama), sonra kilid (ci/acr-lock.sh)."
    echo "> Deploy (Phase 5) bu **digest** ilə aparılacaq, tag ilə deyil."
    echo ""
  } >> "${GITHUB_STEP_SUMMARY}"
fi

note ""
note "═══ Promotion tamamlandı ═══"
note "  Immutable reference: ${IMMUTABLE_REF}"
note ""
