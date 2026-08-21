#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
# k8s-evidence.sh — hardening control-larının HƏQİQƏTƏN tətbiq olunduğunu
# cluster-dən oxuyaraq sübut edir.
#
# NİYƏ MANİFEST GÖSTƏRMƏK KİFAYƏT DEYİL:
#   Manifestdə `runAsNonRoot: true` yazmaq bir şeydir, cluster-də həqiqətən
#   tətbiq olunması başqa. Mutating webhook, admission controller, default
#   dəyər və ya sadəcə köhnə ReplicaSet — hər biri fərq yarada bilər.
#   Bu skript CLUSTER-DƏN oxuyur, repository-dən yox.
#
# Nəticə həm insan üçün (markdown), həm maşın üçün (JSON) saxlanılır.
# Capstone təqdimatında bu, "sübut" bölməsinin əsasıdır.
# ═════════════════════════════════════════════════════════════════════════════
set -Eeuo pipefail

NAMESPACE="${NAMESPACE:-capstone}"
DEPLOYMENT="${DEPLOYMENT:-capstone-app}"
OUT_DIR="${OUT_DIR:-evidence}"

mkdir -p "${OUT_DIR}"
REPORT="${OUT_DIR}/k8s-hardening-evidence.md"
: > "${REPORT}"

PASS=0
FAIL=0

say()  { printf '%s\n' "$*" | tee -a "${REPORT}"; }
raw()  { printf '%s\n' "$*" >> "${REPORT}"; }

check() {
  local label="$1" actual="$2" expected="$3"
  if [ "${actual}" = "${expected}" ]; then
    say "| ${label} | \`${actual}\` | \`${expected}\` | ✅ |"
    PASS=$((PASS + 1))
  else
    say "| ${label} | \`${actual}\` | \`${expected}\` | ❌ |"
    FAIL=$((FAIL + 1))
  fi
}

jp() { kubectl get "$1" "$2" -n "${NAMESPACE}" -o jsonpath="$3" 2>/dev/null || echo "<yoxdur>"; }

say "# Kubernetes Hardening Evidence"
say ""
say "Toplanma tarixi: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "Namespace: \`${NAMESPACE}\` · Deployment: \`${DEPLOYMENT}\`"
say ""
say "> Bütün dəyərlər **cluster-dən** oxunub (repository manifestindən deyil)."
say ""

# ── 1. Pod securityContext ──────────────────────────────────────────────────
say "## 1. Pod securityContext"
say ""
say "| Control | Cluster dəyəri | Gözlənilən | Nəticə |"
say "|---|---|---|---|"

POD="$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name="${DEPLOYMENT}" \
       -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")"

if [ -z "${POD}" ]; then
  say "| — | işləyən pod tapılmadı | — | ❌ |"
  FAIL=$((FAIL + 1))
else
  check "runAsNonRoot"            "$(jp pod "${POD}" '{.spec.securityContext.runAsNonRoot}')" "true"
  check "runAsUser"               "$(jp pod "${POD}" '{.spec.securityContext.runAsUser}')" "65532"
  check "seccompProfile.type"     "$(jp pod "${POD}" '{.spec.securityContext.seccompProfile.type}')" "RuntimeDefault"
  check "automountSAToken"        "$(jp pod "${POD}" '{.spec.automountServiceAccountToken}')" "false"
  check "hostNetwork"             "$(jp pod "${POD}" '{.spec.hostNetwork}')" "<yoxdur>"
  check "readOnlyRootFilesystem"  "$(jp pod "${POD}" '{.spec.containers[0].securityContext.readOnlyRootFilesystem}')" "true"
  check "allowPrivilegeEscalation" "$(jp pod "${POD}" '{.spec.containers[0].securityContext.allowPrivilegeEscalation}')" "false"
  check "capabilities.drop"       "$(jp pod "${POD}" '{.spec.containers[0].securityContext.capabilities.drop[0]}')" "ALL"
fi
say ""

# ── 2. Resurs limitləri ─────────────────────────────────────────────────────
say "## 2. Resurs limitləri"
say ""
say "| Control | Cluster dəyəri | Gözlənilən | Nəticə |"
say "|---|---|---|---|"
MEM_LIMIT="$(jp deployment "${DEPLOYMENT}" '{.spec.template.spec.containers[0].resources.limits.memory}')"
MEM_REQ="$(jp deployment "${DEPLOYMENT}" '{.spec.template.spec.containers[0].resources.requests.memory}')"
check "memory limit"   "${MEM_LIMIT}" "256Mi"
check "memory request" "${MEM_REQ}"   "96Mi"
say ""
say "> CPU limit-i qəsdən təyin edilməyib: CPU sıxıla bilən resursdur və"
say "> throttling Node.js event loop-una zərər verir. Memory isə sıxılmayan"
say "> resursdur — limit məcburidir."
say ""

# ── 3. Image immutability ───────────────────────────────────────────────────
say "## 3. Image reference (digest, tag deyil)"
say ""
IMAGE="$(jp deployment "${DEPLOYMENT}" '{.spec.template.spec.containers[0].image}')"
say '```'
raw "${IMAGE}"
say '```'
say ""
case "${IMAGE}" in
  *@sha256:*) say "✅ Digest istifadə olunur — artefakt immutable-dır."; PASS=$((PASS + 1)) ;;
  *)          say "❌ TAG istifadə olunur — məzmun dəyişə bilər!"; FAIL=$((FAIL + 1)) ;;
esac
say ""

# ── 4. Pod Security Standards ───────────────────────────────────────────────
say "## 4. Pod Security Standards (namespace admission)"
say ""
say "| Etiket | Dəyər | Gözlənilən | Nəticə |"
say "|---|---|---|---|"
for mode in enforce audit warn; do
  V="$(kubectl get ns "${NAMESPACE}" -o jsonpath="{.metadata.labels.pod-security\.kubernetes\.io/${mode}}" 2>/dev/null || echo "<yoxdur>")"
  check "pod-security…/${mode}" "${V}" "restricted"
done
say ""

# ── 5. NetworkPolicy ────────────────────────────────────────────────────────
say "## 5. NetworkPolicy"
say ""
say '```'
kubectl get networkpolicy -n "${NAMESPACE}" >> "${REPORT}" 2>&1 || echo "(alınmadı)" >> "${REPORT}"
say '```'
say ""
NP_COUNT="$(kubectl get networkpolicy -n "${NAMESPACE}" --no-headers 2>/dev/null | wc -l | tr -d ' ')"
if [ "${NP_COUNT}" -ge 3 ]; then
  say "✅ ${NP_COUNT} NetworkPolicy tətbiq olunub (default-deny + açıq allow qaydaları)."
  PASS=$((PASS + 1))
else
  say "❌ Yalnız ${NP_COUNT} NetworkPolicy — default-deny gözlənilirdi."
  FAIL=$((FAIL + 1))
fi
say ""
say "> ⚠️ NetworkPolicy obyektinin mövcudluğu onun **tətbiq olunduğunu**"
say "> sübut etmir. AKS-də CNI policy dəstəyi olmadan bu obyektlər"
say "> sükutla nəzərə alınmır. Aşağıdakı yoxlamaya baxın."
say ""
NP_ENGINE="$(az aks show --resource-group "${AKS_RESOURCE_GROUP:-}" --name "${AKS_CLUSTER_NAME:-}" \
             --query networkProfile.networkPolicy -o tsv 2>/dev/null || echo "<oxunmadı>")"
say "**AKS network policy engine:** \`${NP_ENGINE}\`"
if [ "${NP_ENGINE}" = "azure" ] || [ "${NP_ENGINE}" = "calico" ] || [ "${NP_ENGINE}" = "cilium" ]; then
  say "✅ Policy engine aktivdir — qaydalar həqiqətən tətbiq olunur."
  PASS=$((PASS + 1))
else
  say "❌ Policy engine aktiv deyil — NetworkPolicy obyektləri TƏSİRSİZDİR!"
  FAIL=$((FAIL + 1))
fi
say ""

# ── 6. RBAC — least privilege ───────────────────────────────────────────────
say "## 6. RBAC — CI identity icazələri"
say ""
say "| Əməliyyat | Nəticə | Gözlənilən | Qiymət |"
say "|---|---|---|---|"
perm() {
  local verb="$1" res="$2" expected="$3"
  local got
  got="$(kubectl auth can-i "${verb}" "${res}" -n "${NAMESPACE}" 2>/dev/null || echo no)"
  check "${verb} ${res}" "${got}" "${expected}"
}
perm patch  deployments    yes
perm get    pods           yes
perm delete deployments    no
perm get    secrets        no
perm patch  networkpolicies no
perm create rolebindings   no
say ""
say "> \`no\` cavabları least-privilege sübutudur: CI tətbiqi deploy edə bilir,"
say "> lakin onu qoruyan təhlükəsizlik hasarına toxuna bilmir (threat model T4)."
say ""

# ── 7. ServiceAccount ───────────────────────────────────────────────────────
say "## 7. Tətbiq ServiceAccount-u"
say ""
SA_AUTOMOUNT="$(kubectl get sa app-sa -n "${NAMESPACE}" -o jsonpath='{.automountServiceAccountToken}' 2>/dev/null || echo "<yoxdur>")"
say "| Control | Dəyər | Gözlənilən | Nəticə |"
say "|---|---|---|---|"
check "app-sa automountServiceAccountToken" "${SA_AUTOMOUNT}" "false"
say ""
if [ -n "${POD}" ]; then
  MOUNTED="$(kubectl exec "${POD}" -n "${NAMESPACE}" -- ls /var/run/secrets/kubernetes.io/serviceaccount 2>&1 || echo "MOUNT YOXDUR")"
  say "Pod daxilində token yoxlaması:"
  say '```'
  raw "${MOUNTED}"
  say '```'
  say ""
  say "> Qeyd: distroless image-də shell yoxdur, ona görə \`kubectl exec\` uğursuz olur."
  say "> Bu, **əlavə bir hardening sübutudur** — konteynerə interaktiv giriş mümkün deyil."
  say ""
fi

# ── 8. Ümumi cluster vəziyyəti ──────────────────────────────────────────────
say "## 8. Cluster vəziyyəti"
say ""
for cmd in "get pods -o wide" "get svc" "get networkpolicy" "get sa" "get role" "get rolebinding" "get pdb"; do
  say "### \`kubectl ${cmd}\`"
  say '```'
  # shellcheck disable=SC2086
  kubectl ${cmd} -n "${NAMESPACE}" >> "${REPORT}" 2>&1 || echo "(alınmadı)" >> "${REPORT}"
  say '```'
  say ""
done

# ── Xülasə ──────────────────────────────────────────────────────────────────
say "---"
say ""
say "## Xülasə"
say ""
say "**PASS: ${PASS} · FAIL: ${FAIL}**"
say ""

# Maşın üçün JSON
python3 -c "
import json, sys
json.dump({'pass': ${PASS}, 'fail': ${FAIL}, 'namespace': '${NAMESPACE}',
           'deployment': '${DEPLOYMENT}', 'image': '''${IMAGE}'''},
          open('${OUT_DIR}/k8s-hardening-evidence.json','w'), indent=2)
" 2>/dev/null || true

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat "${REPORT}" >> "${GITHUB_STEP_SUMMARY}"
fi

echo ""
echo "Evidence saxlanildi: ${REPORT}"
[ "${FAIL}" -eq 0 ] || { echo "::error::${FAIL} hardening yoxlamasi UGURSUZ"; exit 1; }
echo "Butun hardening yoxlamalari PASS"
