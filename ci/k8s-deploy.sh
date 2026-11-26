#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
# k8s-deploy.sh — imzalanmış image-i AKS-ə deploy edir.
#
#   verify signature → digest tetbiq et → apply → rollout gozle → dogrula
#
# NİYƏ İMZA BURADA DA YOXLANILIR (Gate 7B-də artıq yoxlanılıb):
#   Gate 7B build workflow-undadır. Bu skript isə deploy workflow-undadır və
#   ayrıca da işlədilə bilər. Deploy-dan dərhal əvvəl yoxlama "artefakt
#   imzalandıqdan sonra dəyişdirilməyib" zəmanətini deploy anına gətirir.
#   Bu, ucuz bir yoxlamadır və müstəqil bir qat əlavə edir.
#
#   Üçüncü qat isə Kyverno-dur (admission) — o, bu skripti tamamilə bypass
#   edən `kubectl apply` hallarını da tutur.
# ═════════════════════════════════════════════════════════════════════════════
set -Eeuo pipefail

fail() { printf '::error::%s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${REPO_ROOT}"

: "${IMAGE_REF:?IMAGE_REF təyin edilməyib (repo@sha256:... formatında)}"
NAMESPACE="${NAMESPACE:-capstone}"
DEPLOYMENT="${DEPLOYMENT:-capstone-app}"
ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT:-180s}"
SKIP_VERIFY="${SKIP_VERIFY:-false}"

# ── 1. Digest məcburiyyəti ──────────────────────────────────────────────────
# Tag ilə deploy QADAĞANDIR. Tag mutable-dır: imzaladığımız manifest ilə
# deploy olunan manifest fərqli ola bilər.
case "${IMAGE_REF}" in
  *@sha256:*) ;;
  *) fail "IMAGE_REF digest ilə göstərilməlidir (repo@sha256:...), tag ilə YOX.
     Alınan: ${IMAGE_REF}" ;;
esac

note ""
note "═══ Kubernetes Deploy ═══"
note "  image     : ${IMAGE_REF}"
note "  namespace : ${NAMESPACE}"
note ""

# ── 2. İmza doğrulaması (deploy-dan əvvəl) ──────────────────────────────────
if [ "${SKIP_VERIFY}" = "true" ]; then
  # Bu bayraq YALNIZ lokal debug üçündür və CI-də İSTİFADƏ EDİLMİR.
  # Xəbərdarlıq açıq şəkildə çap olunur ki, log-da görünsün.
  note "⚠️  SKIP_VERIFY=true — imza yoxlaması ATLANDI (yalnız lokal debug)."
  note "    Kyverno admission policy hər halda tətbiq olunacaq."
else
  note "[1/5] İmza doğrulanır…"
  IMAGE_REF="${IMAGE_REF}" bash ci/cosign-verify.sh \
    || fail "İmza doğrulanmadı — deploy DAYANDIRILDI.
     Bu artefakt bizim pipeline tərəfindən imzalanmayıb və ya dəyişdirilib."
fi

# ── 3. Manifestləri render et ───────────────────────────────────────────────
note ""
note "[2/5] Manifestlər render edilir…"

RENDER_DIR="$(mktemp -d)"
trap 'rm -rf "${RENDER_DIR}"' EXIT
cp k8s/app/*.yaml "${RENDER_DIR}/"

GIT_COMMIT="${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"
RUN_URL="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-local}/actions/runs/${GITHUB_RUN_ID:-0}"

# Python istifadə olunur: image reference `/` və `@` saxlayır və sed-də
# ayırıcı seçimi səhvə açıqdır.
IMAGE_REF="${IMAGE_REF}" GIT_COMMIT="${GIT_COMMIT}" RUN_URL="${RUN_URL}" \
RENDER_DIR="${RENDER_DIR}" python3 <<'PY'
import os, pathlib
d = pathlib.Path(os.environ["RENDER_DIR"])
subs = {
    "__IMAGE_REF__":        os.environ["IMAGE_REF"],
    "__GIT_COMMIT__":       os.environ["GIT_COMMIT"],
    "__PIPELINE_RUN_URL__": os.environ["RUN_URL"],
}
for f in d.glob("*.yaml"):
    t = f.read_text(encoding="utf-8")
    for k, v in subs.items():
        t = t.replace(k, v)
    if "__" in t and any(p in t for p in subs):
        raise SystemExit(f"RENDER XETASI — doldurulmamiş placeholder: {f.name}")
    f.write_text(t, encoding="utf-8")
print("  ✓ render tamamlandi")
PY

# ── 4. Server-side dry-run ──────────────────────────────────────────────────
# Bu, HƏQİQİ admission yoxlamasıdır: Pod Security Standards və Kyverno
# policy-ləri burada işə düşür. `--dry-run=client` bunu ETMİR — o, yalnız
# YAML sintaksisini yoxlayır.
note ""
note "[3/5] Server-side dry-run (PSS + Kyverno admission)…"
kubectl apply -f "${RENDER_DIR}" -n "${NAMESPACE}" --dry-run=server \
  || fail "Admission yoxlaması UĞURSUZ.
     Ehtimal səbəblər:
       - Pod Security Standards 'restricted' pozuntusu
       - Kyverno imza doğrulaması uğursuz (imzasız və ya yad kimlik)
     Yuxarıdakı xəta mesajına baxın."
note "  ✓ admission yoxlamasi kecdi"

# ── 5. Tətbiq ───────────────────────────────────────────────────────────────
note ""
note "[4/5] Tətbiq edilir…"
kubectl apply -f "${RENDER_DIR}" -n "${NAMESPACE}"

note ""
note "[5/5] Rollout gözlənilir (timeout: ${ROLLOUT_TIMEOUT})…"
if ! kubectl rollout status "deployment/${DEPLOYMENT}" -n "${NAMESPACE}" --timeout="${ROLLOUT_TIMEOUT}"; then
  note ""
  note "═══ ROLLOUT UĞURSUZ — diaqnostika ═══"
  kubectl get pods -n "${NAMESPACE}" -o wide || true
  note ""
  note "--- Son hadisələr ---"
  kubectl get events -n "${NAMESPACE}" --sort-by=.lastTimestamp 2>/dev/null | tail -15 || true
  note ""
  note "--- Pod təsviri (ilk pod) ---"
  POD="$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name="${DEPLOYMENT}" \
         -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [ -n "${POD}" ] && kubectl describe pod "${POD}" -n "${NAMESPACE}" | tail -30 || true

  # Avtomatik geri qaytarma: uğursuz deploy-u asılı vəziyyətdə saxlamırıq.
  note ""
  note "Əvvəlki işlək versiyaya qaytarılır…"
  kubectl rollout undo "deployment/${DEPLOYMENT}" -n "${NAMESPACE}" || true
  fail "Rollout uğursuz oldu — geri qaytarma icra edildi."
fi

# ── Deploy sonrası doğrulama ────────────────────────────────────────────────
note ""
note "═══ Deploy sonrası doğrulama ═══"

RUNNING_IMAGE="$(kubectl get deployment "${DEPLOYMENT}" -n "${NAMESPACE}" \
  -o jsonpath='{.spec.template.spec.containers[0].image}')"

note "  gözlənilən : ${IMAGE_REF}"
note "  işləyən    : ${RUNNING_IMAGE}"

# İşləyən image-in deploy etmək istədiyimizlə EYNİ olduğunu yoxlayırıq.
# Bu, "apply etdim, deməli işləyir" fərziyyəsini aradan qaldırır.
[ "${RUNNING_IMAGE}" = "${IMAGE_REF}" ] \
  || fail "IMAGE UYĞUNSUZLUĞU — deploy olunan artefakt gözləniləndən fərqlidir!"
note "  ✓ image uygun"

READY="$(kubectl get deployment "${DEPLOYMENT}" -n "${NAMESPACE}" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo 0)"
note "  hazır replica: ${READY:-0}"
[ "${READY:-0}" -ge 1 ] || fail "Heç bir replica hazır deyil"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo ""
    echo "## Gate 8 — Kubernetes Deploy"
    echo ""
    echo "| Sahə | Dəyər |"
    echo "|---|---|"
    echo "| Namespace | \`${NAMESPACE}\` |"
    echo "| Deployment | \`${DEPLOYMENT}\` |"
    echo "| Image (digest) | \`${IMAGE_REF}\` |"
    echo "| Hazır replica | ${READY} |"
    echo "| İmza doğrulaması | ✅ deploy-dan əvvəl |"
    echo "| Admission | ✅ PSS restricted + Kyverno |"
    echo ""
  } >> "${GITHUB_STEP_SUMMARY}"
fi

note ""
note "═══ Deploy tamamlandı ═══"
note ""
