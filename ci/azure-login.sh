#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
# azure-login.sh — GitHub Actions OIDC ilə Azure-a keyless authentication.
#
#   GitHub Actions → OIDC token → Entra ID (federated credential) → short-lived
#   access token (≈1 saat) → ACR / AKS
#
# NİYƏ `azure/login` ACTION-U İSTİFADƏ ETMİRİK:
#   Phase 2-də üçüncü tərəf action-lardan imtina etdik (19 mart 2026 —
#   `aquasecurity/trivy-action` kompromisi: bütün tag-lar yenidən işarələndi,
#   runner yaddaşından secret oğurlandı). Eyni prinsip burada da tətbiq olunur.
#   `az` CLI GitHub-hosted runner-də ƏVVƏLCƏDƏN quraşdırılıb, ona görə
#   üçüncü tərəf JS kodu icra etməyə ehtiyac yoxdur — 15 sətirlik curl+az
#   kifayətdir və tam auditə açıqdır.
#
#   (Əgər komanda `azure/login@<sha>` istifadə etməyi üstün tutursa, bu
#   qəbuledilən alternativdir — ŞƏRT: commit SHA ilə pinlənməlidir.)
#
# NİYƏ CLIENT SECRET YOXDUR:
#   Federated credential modelində Azure-da saxlanılan şey GitHub-un OIDC
#   issuer-i + subject filtridir (məs. `repo:owner/repo:ref:refs/heads/main`).
#   Yəni:
#     - repository-də uzunömürlü credential SAXLANMIR;
#     - oğurlanacaq secret yoxdur;
#     - token ≈1 saat yaşayır;
#     - fork PR bu token-i ALA BİLMİR (subject uyğunlaşmır).
#   AZURE_CLIENT_ID / TENANT_ID / SUBSCRIPTION_ID secret deyil (identifikatordur),
#   lakin biz onları yenə də GitHub Secrets-də saxlayırıq — icazəsiz şəxsə
#   hədəf abunəliyin strukturunu açmamaq üçün.
#
# Tələb olunan workflow icazəsi:
#     permissions:
#       id-token: write      # OIDC token tələb etmək üçün
#       contents: read
# ═════════════════════════════════════════════════════════════════════════════
set -Eeuo pipefail

fail() { printf '::error::%s\n' "$*" >&2; exit 1; }

: "${AZURE_CLIENT_ID:?AZURE_CLIENT_ID təyin edilməyib}"
: "${AZURE_TENANT_ID:?AZURE_TENANT_ID təyin edilməyib}"
: "${AZURE_SUBSCRIPTION_ID:?AZURE_SUBSCRIPTION_ID təyin edilməyib}"

# Bu iki dəyişən GitHub tərəfindən YALNIZ `id-token: write` icazəsi olduqda
# job-a inject edilir. Yoxdursa — konfiqurasiya səhvidir.
: "${ACTIONS_ID_TOKEN_REQUEST_URL:?id-token icazəsi yoxdur — workflow-a 'permissions: id-token: write' əlavə edin}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?id-token icazəsi yoxdur — workflow-a 'permissions: id-token: write' əlavə edin}"

# audience: Azure-un federated credential-da gözlədiyi standart dəyər.
AUDIENCE="api://AzureADTokenExchange"

echo "OIDC token tələb olunur (audience: ${AUDIENCE})…"

OIDC_TOKEN="$(
  curl -fsSL \
    -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
    -H "Accept: application/json; api-version=2.0" \
    "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${AUDIENCE}" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["value"])'
)" || fail "OIDC token alınmadı"

[ -n "${OIDC_TOKEN}" ] || fail "OIDC token boşdur"

# Token-i log-a YAZMIRIQ. GitHub avtomatik maskalama etmir, çünki bu dəyər
# secrets-dən gəlmir — ona görə açıq şəkildə maskalayırıq.
echo "::add-mask::${OIDC_TOKEN}"

echo "Azure-a login edilir (federated credential)…"
az login \
  --service-principal \
  --username "${AZURE_CLIENT_ID}" \
  --tenant "${AZURE_TENANT_ID}" \
  --federated-token "${OIDC_TOKEN}" \
  --output none \
  || fail "az login uğursuz — federated credential subject-i yoxlayın (repo/branch uyğunluğu)"

az account set --subscription "${AZURE_SUBSCRIPTION_ID}" --output none \
  || fail "abunəliyə keçid uğursuz: ${AZURE_SUBSCRIPTION_ID}"

# Kimlik təsdiqi — log-da hansı identity ilə işlədiyimiz görünsün (auditability).
PRINCIPAL="$(az account show --query user.name -o tsv 2>/dev/null || echo '?')"
SUB_NAME="$(az account show --query name -o tsv 2>/dev/null || echo '?')"
echo "✓ Azure login uğurlu"
echo "  identity     : ${PRINCIPAL}"
echo "  subscription : ${SUB_NAME}"
echo "  token ömrü   : ≈1 saat (uzunömürlü credential yoxdur)"
