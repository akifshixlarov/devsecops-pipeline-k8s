#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
# acr-lock.sh — imzalanmış və doğrulanmış manifest-i immutable edir.
#
# BU SKRİPT SUPPLY CHAIN-in SON ADDIMIDIR:
#     build → scan → promote → SIGN → verify → [BU SKRİPT] → deploy
#
# NİYƏ SIRA MƏHZ BELƏDİR (Phase 4-də düzəldilmiş səhv):
#   Kilid əvvəlcə promote mərhələsində idi. Lakin Cosign imzanı OCI 1.1
#   Referrers API ilə subject manifest-ə bağlayır — kilidlənmiş manifest-ə
#   referrer əlavə etmək ACR konfiqurasiyasından asılı olaraq uğursuz ola
#   bilər. Ona görə kilid imzalamadan SONRA tətbiq olunur.
#
#   Konseptual olaraq da doğrudur: artefakt yalnız imzalandıqdan sonra
#   "buraxılmış" sayılır. İmzasız image kilidləmək mənasızdır — onsuz da
#   deploy edilə bilməz.
#
# NƏ EDİR:
#   ACR tag-ları DEFAULT OLARAQ MUTABLE-dır: eyni tag-a yenidən push etmək
#   manifest-i əvəz edir. Yəni `app:abc123` bu gün skan+imzalanmış image,
#   sabah tamamilə başqa məzmun ola bilər — imza isə köhnə digest-ə aid
#   qaldığı üçün "sanki" hər şey qaydasındadır.
#   (threat model § 3.4 — Registry, STRIDE-T: "scan+sign-dan sonra mövcud
#   tag-ın üzərinə yazılması")
#
#   Kilid HƏM manifest (digest), HƏM tag səviyyəsində tətbiq olunur:
#     - manifest kilidi → məzmun silinə/dəyişdirilə bilməz
#     - tag kilidi      → tag adı başqa manifest-ə keçirilə bilməz
# ═════════════════════════════════════════════════════════════════════════════
set -Eeuo pipefail

fail() { printf '::error::%s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

: "${ACR_NAME:?ACR_NAME təyin edilməyib}"
: "${IMAGE_REPO:?IMAGE_REPO təyin edilməyib}"
: "${IMAGE_TAG:?IMAGE_TAG təyin edilməyib}"
: "${IMAGE_DIGEST:?IMAGE_DIGEST təyin edilməyib}"

LOGIN_SERVER="${ACR_NAME}.azurecr.io"

note ""
note "═══ ACR Immutability ═══"
note "  manifest : ${IMAGE_REPO}@${IMAGE_DIGEST}"
note "  tag      : ${IMAGE_REPO}:${IMAGE_TAG}"
note ""

# ── 1. Manifest kilidi ──────────────────────────────────────────────────────
note "[1/3] Manifest kilidlənir (write + delete disabled)…"
az acr repository update \
  --name "${ACR_NAME}" \
  --image "${IMAGE_REPO}@${IMAGE_DIGEST}" \
  --write-enabled false \
  --delete-enabled false \
  --output none \
  || fail "manifest kilidlənmədi — CI identity-də 'ACR Image Lock Manager' rolu varmı?
     (bax docs/azure-setup.md § 3 — AcrPush bu icazəni ƏHATƏ ETMİR)"

note "  ✓ manifest kilidləndi"

# ── 2. Tag kilidi ───────────────────────────────────────────────────────────
# Tag-a `--delete-enabled false` VERİLMİR: tag-ın silinməsi manifest-i
# silmir və bəzən lazım olur (məs. səhv tag adı). Kritik olan tag-ın BAŞQA
# manifest-ə KEÇİRİLMƏMƏSİDİR, bunu isə `--write-enabled false` təmin edir.
note "[2/3] Tag kilidlənir (write disabled)…"
az acr repository update \
  --name "${ACR_NAME}" \
  --image "${IMAGE_REPO}:${IMAGE_TAG}" \
  --write-enabled false \
  --output none \
  || fail "tag kilidlənmədi"

note "  ✓ tag kilidləndi"

# ── 3. DOĞRULAMA (iddia deyil, yoxlama) ─────────────────────────────────────
# "Kilidlədik" demək kifayət deyil — ACR-dən geri oxuyub təsdiqləyirik.
# Bu addım olmasa, icazə çatışmazlığı halında `az` bəzən səssizcə
# uğurlu görünür və biz yanlış təhlükəsizlik hissi ilə qalarıq.
note "[3/3] Kilid ACR-dən geri oxunub doğrulanır…"

ATTRS="$(
  az acr repository show \
    --name "${ACR_NAME}" \
    --image "${IMAGE_REPO}@${IMAGE_DIGEST}" \
    --query changeableAttributes -o json 2>/dev/null
)" || fail "manifest atributları oxunmadı"

WRITE_ENABLED="$(echo "${ATTRS}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("writeEnabled"))')"
DELETE_ENABLED="$(echo "${ATTRS}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("deleteEnabled"))')"

note "  writeEnabled  : ${WRITE_ENABLED}   (False gözlənilir)"
note "  deleteEnabled : ${DELETE_ENABLED}   (False gözlənilir)"

if [ "${WRITE_ENABLED}" != "False" ] || [ "${DELETE_ENABLED}" != "False" ]; then
  fail "IMMUTABILITY TƏTBİQ OLUNMADI — manifest hələ də dəyişdirilə bilər.
     Rol təyinatlarını yoxlayın (docs/azure-setup.md § 3)."
fi

note "  ✓ Immutability təsdiqləndi"

IMMUTABLE_REF="${LOGIN_SERVER}/${IMAGE_REPO}@${IMAGE_DIGEST}"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo ""
    echo "## Immutability — release artefaktı kilidləndi"
    echo ""
    echo "| Sahə | Dəyər |"
    echo "|---|---|"
    echo "| Immutable reference | \`${IMMUTABLE_REF}\` |"
    echo "| writeEnabled | \`${WRITE_ENABLED}\` |"
    echo "| deleteEnabled | \`${DELETE_ENABLED}\` |"
    echo "| İmza | ✅ Cosign keyless (Fulcio + Rekor) |"
    echo "| Attestation-lar | \`cyclonedx\` + \`vuln\` |"
    echo ""
    echo "**Supply chain tamamlandı:**"
    echo ""
    echo "\`\`\`"
    echo "Source → Scan → Build → Scan → Promote → Sign → Verify → Lock"
    echo "\`\`\`"
    echo ""
    echo "Phase 5 (Kubernetes deploy) bu digest ilə davam edə bilər."
    echo ""
  } >> "${GITHUB_STEP_SUMMARY}"
fi

note ""
note "═══ Artefakt immutable və imzalanmış ═══"
note "  ${IMMUTABLE_REF}"
note ""
