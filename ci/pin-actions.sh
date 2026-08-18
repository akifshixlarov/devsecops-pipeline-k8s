#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# pin-actions.sh — workflow-lardakı `uses: owner/repo@tag` sətirlərini
# həmin tag-ın REAL commit SHA-sına çevirir.
#
# ⚠ NİYƏ BU SKRİPT VAR (və niyə SHA-lar sənəddə hazır verilmir):
#   Commit SHA-nı əldən uydurmaq mümkün deyil — yanlış SHA workflow-u
#   qıracaq. Ona görə SHA-ları GitHub API-dən CANLI alırıq.
#
# ⚠ NİYƏ TAG PİNLƏMƏSİ KİFAYƏT DEYİL:
#   Tag mutable-dır. 19 mart 2026-da `aquasecurity/trivy-action`
#   kompromis ediləndə attacker mövcud tag-ları (0.0.1–0.34.2) zərərli
#   commit-ə YENİDƏN İŞARƏLƏDİ. `@v0.28.0` yazan hər kəs zərərli kod icra etdi.
#   Commit SHA isə immutable-dır — bu hücumu tam bloklayır.
#
# İSTİFADƏ (repo-nu ilk dəfə push etməzdən ƏVVƏL bir dəfə işlədin):
#   export GH_TOKEN=<personal access token>   # public repo üçün read kifayətdir
#   bash ci/pin-actions.sh                    # nəticəni göstərir
#   bash ci/pin-actions.sh --write            # faylları yeniləyir
#
# Sonradan Dependabot (.github/dependabot.yml) SHA-ları avtomatik yeniləyəcək
# və hər yeniləmə review tələb edən PR kimi gələcək.
# ─────────────────────────────────────────────────────────────────────────────
set -Eeuo pipefail

WRITE=0
[[ "${1:-}" == "--write" ]] && WRITE=1

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW_DIR="${REPO_ROOT}/.github/workflows"

command -v jq >/dev/null || { echo "jq tələb olunur: sudo apt-get install -y jq" >&2; exit 1; }

api() {
  local url="$1"
  if [[ -n "${GH_TOKEN:-}" ]]; then
    curl -fsSL -H "Authorization: Bearer ${GH_TOKEN}" -H "Accept: application/vnd.github+json" "$url"
  else
    curl -fsSL -H "Accept: application/vnd.github+json" "$url"
  fi
}

resolve_sha() {
  local repo="$1" ref="$2"
  # Əvvəlcə annotated tag-ı açırıq (tag object → commit), sonra birbaşa ref.
  api "https://api.github.com/repos/${repo}/git/ref/tags/${ref}" 2>/dev/null \
    | jq -r 'if .object.type == "tag" then .object.url else .object.sha end' \
    | { read -r out; if [[ "$out" == http* ]]; then api "$out" | jq -r '.object.sha'; else echo "$out"; fi; }
}

echo "Workflow-lardakı action istinadları pinlənir…"
echo

found=0
while IFS= read -r line; do
  file="${line%%:*}"
  rest="${line#*:}"
  ref="$(echo "$rest" | sed -E 's#.*uses:[[:space:]]*([^[:space:]]+).*#\1#')"
  repo="${ref%@*}"
  tag="${ref##*@}"

  # Artıq SHA ilə pinlənibsə (40 hex simvol) atla.
  [[ "$tag" =~ ^[0-9a-f]{40}$ ]] && continue
  # Local action-lar (./ ilə başlayan) atlanır.
  [[ "$repo" == ./* ]] && continue

  found=$((found + 1))
  sha="$(resolve_sha "$repo" "$tag" || true)"

  if [[ -z "$sha" || ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
    echo "  ✗ ${repo}@${tag} → SHA alınmadı (rate limit? GH_TOKEN təyin edin)"
    continue
  fi

  echo "  ✓ ${repo}@${tag}"
  echo "      → ${repo}@${sha} # ${tag}"

  if [[ "$WRITE" -eq 1 ]]; then
    # Şərh olaraq orijinal tag saxlanılır ki, Dependabot onu izləyə bilsin.
    sed -i "s|uses: ${repo}@${tag}\$|uses: ${repo}@${sha} # ${tag}|g" "$file"
  fi
done < <(grep -rn 'uses:' "${WORKFLOW_DIR}" | grep -v '@[0-9a-f]\{40\}')

echo
if [[ "$found" -eq 0 ]]; then
  echo "Bütün action-lar artıq commit SHA ilə pinlənib. ✓"
elif [[ "$WRITE" -eq 1 ]]; then
  echo "${found} istinad yeniləndi. Dəyişikliyi `git diff` ilə yoxlayıb commit edin."
else
  echo "${found} istinad pinlənməyib. Tətbiq etmək üçün: bash ci/pin-actions.sh --write"
fi
