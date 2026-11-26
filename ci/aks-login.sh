#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
# aks-login.sh — AKS-ə keyless authentication (uzunömürlü kubeconfig YOXDUR).
#
#   GitHub OIDC → Entra ID → qısaömürlü token → AKS (Azure RBAC)
#
# NİYƏ `KUBE_CONFIG` SECRET-İ İSTİFADƏ ETMİRİK:
#   Ən çox yayılmış naxış base64 kubeconfig-i GitHub Secret kimi saxlamaqdır.
#   Bu, bir neçə səbəbdən pisdir:
#     - kubeconfig cluster-admin sertifikatı saxlaya bilər (aylarla etibarlı);
#     - rotasiya praktiki olaraq heç vaxt edilmir;
#     - secret sızarsa, hücumçu birbaşa cluster-ə tam çıxış əldə edir;
#     - hansı identity-nin nə etdiyi audit log-da görünmür (hamı eyni sertifikatdır).
#
#   Bizim yanaşmada:
#     - repository-də cluster credential-ı SAXLANMIR;
#     - token ≈1 saat yaşayır;
#     - AKS audit log-unda konkret service principal görünür;
#     - icazələr Azure RBAC + K8s RBAC ilə namespace-ə məhdudlaşdırılıb.
#
# ⚠ AKS TƏLƏBİ: cluster Entra ID inteqrasiyası ilə yaradılmalıdır
#   (--enable-aad --enable-azure-rbac). Lokal hesablar (--disable-local-accounts)
#   söndürülməlidir, əks halda `--admin` kubeconfig hələ də mövcud olur və
#   bütün bu müdafiə bypass edilə bilər.
# ═════════════════════════════════════════════════════════════════════════════
set -Eeuo pipefail

fail() { printf '::error::%s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

: "${AKS_RESOURCE_GROUP:?AKS_RESOURCE_GROUP təyin edilməyib}"
: "${AKS_CLUSTER_NAME:?AKS_CLUSTER_NAME təyin edilməyib}"

# Azure sessiyası ci/azure-login.sh tərəfindən qurulur (Phase 3).
az account show --output none 2>/dev/null \
  || fail "Azure sessiyası yoxdur — əvvəlcə ci/azure-login.sh işlədin."

note ""
note "═══ AKS Login ═══"
note "  resource group : ${AKS_RESOURCE_GROUP}"
note "  cluster        : ${AKS_CLUSTER_NAME}"
note ""

# ── kubeconfig alınması ─────────────────────────────────────────────────────
# `--admin` İSTİFADƏ EDİLMİR: o, cluster-admin sertifikatı verir və
# Azure RBAC-ı tamamilə bypass edir. Bizə lazım olan Entra ID kontekstidir.
note "[1/3] kubeconfig alınır (Entra ID konteksti)…"
az aks get-credentials \
  --resource-group "${AKS_RESOURCE_GROUP}" \
  --name "${AKS_CLUSTER_NAME}" \
  --overwrite-existing \
  --output none \
  || fail "az aks get-credentials uğursuz — service principal-da
     'Azure Kubernetes Service Cluster User Role' varmı?"

# ── kubelogin ilə non-interaktiv rejimə çevrilmə ────────────────────────────
# Default kubeconfig `kubelogin` üçün devicecode (interaktiv) rejimini
# göstərir — CI-də bu, sonsuz gözləmə deməkdir.
# `-l azurecli` mövcud `az` sessiyasının token-ini istifadə edir.
note "[2/3] kubelogin non-interaktiv rejimə çevrilir…"
if ! command -v kubelogin >/dev/null 2>&1; then
  note "  kubelogin tapılmadı, quraşdırılır…"
  az aks install-cli --only-show-errors 2>/dev/null \
    || fail "kubelogin quraşdırılmadı"
fi

kubelogin convert-kubeconfig -l azurecli \
  || fail "kubelogin convert-kubeconfig uğursuz"

# ── Doğrulama ───────────────────────────────────────────────────────────────
note "[3/3] Bağlantı və icazələr yoxlanılır…"
kubectl version --output=json 2>/dev/null | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    print('  server:', d.get('serverVersion',{}).get('gitVersion','?'))
except Exception:
    pass" || true

NAMESPACE="${NAMESPACE:-capstone}"

# İcazələri açıq şəkildə yoxlayırıq — həm işləyəcəyini təsdiqləyir,
# həm də least-privilege-in sübutunu log-a yazır (evidence).
note ""
note "  İcazə yoxlaması (namespace: ${NAMESPACE}):"
check_perm() {
  local verb="$1" res="$2" expect="$3"
  local got
  got="$(kubectl auth can-i "${verb}" "${res}" -n "${NAMESPACE}" 2>/dev/null || echo no)"
  local mark="✓"
  [ "${got}" != "${expect}" ] && mark="✗"
  printf '    %s %-28s %-4s (gözlənilən: %s)\n' "${mark}" "${verb} ${res}" "${got}" "${expect}"
}

# Olmalı olanlar
check_perm patch  deployments               yes
check_perm get    pods                      yes
# OLMAMALI olanlar — least privilege sübutu (threat model T4)
check_perm delete deployments               no
check_perm get    secrets                   no
check_perm patch  networkpolicies           no
check_perm create rolebindings              no

note ""
note "✓ AKS login tamamlandı (uzunömürlü credential istifadə edilmədi)"
note ""
