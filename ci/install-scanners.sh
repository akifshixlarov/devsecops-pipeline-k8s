#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# install-scanners.sh — security alətlərini pinlənmiş versiyada, checksum
# yoxlaması ilə quraşdırır.
#
# İstifadə:
#   bash ci/install-scanners.sh trivy gitleaks
#   bash ci/install-scanners.sh --print-pins        # SHA256 dəyərlərini çap edir
#
# Alətlər $HOME/.local/bin altına quraşdırılır (runner-də PATH-a əlavə olunur).
# ─────────────────────────────────────────────────────────────────────────────
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "${REPO_ROOT}/ci/scanner-versions.env"

BIN_DIR="${HOME}/.local/bin"
WORK_DIR="$(mktemp -d)"
PRINT_PINS=0

cleanup() { rm -rf "${WORK_DIR}"; }
trap cleanup EXIT

mkdir -p "${BIN_DIR}"

log()  { printf '  %s\n' "$*"; }
fail() { printf '::error::%s\n' "$*" >&2; exit 1; }

# ── Checksum yoxlaması ───────────────────────────────────────────────────────
# İki səviyyəli:
#   1. Rəsmi checksums.txt-ə qarşı yoxlama (transit tampering-dən qoruyur).
#   2. Əgər scanner-versions.env-də SHA256 pinlənibsə, checksums.txt-in ÖZÜ də
#      yoxlanılır (release-in yenidən yayımlanmasından qoruyur).
verify_checksum() {
  local file="$1" expected="$2" label="$3"
  local actual
  actual="$(sha256sum "${file}" | awk '{print $1}')"

  if [[ -n "${expected}" ]]; then
    if [[ "${actual}" != "${expected}" ]]; then
      fail "${label}: SHA256 UYĞUNSUZLUĞU!
        Gözlənilən: ${expected}
        Alınan    : ${actual}
      Bu, kompromis edilmiş və ya yenidən yayımlanmış release ola bilər.
      Quraşdırma DAYANDIRILDI."
    fi
    log "✓ ${label}: SHA256 pin təsdiqləndi"
  else
    log "⚠ ${label}: SHA256 pinlənməyib. Müşahidə olunan dəyər:"
    log "    ${actual}"
    log "  Bunu ci/scanner-versions.env faylına yazın ki, pin aktivləşsin."
  fi
  [[ "${PRINT_PINS}" -eq 1 ]] && printf 'PIN %s=%s\n' "${label}" "${actual}"
  return 0
}

install_trivy() {
  local ver="${TRIVY_VERSION}"
  local tarball="trivy_${ver}_Linux-64bit.tar.gz"
  local base="https://github.com/aquasecurity/trivy/releases/download/v${ver}"

  log "Trivy v${ver} endirilir…"
  curl -fsSL --retry 3 -o "${WORK_DIR}/${tarball}" "${base}/${tarball}"
  curl -fsSL --retry 3 -o "${WORK_DIR}/checksums.txt" "${base}/trivy_${ver}_checksums.txt"

  # 1) Rəsmi checksums.txt-ə qarşı yoxlama
  ( cd "${WORK_DIR}" && grep " ${tarball}\$" checksums.txt | sha256sum -c - ) \
    || fail "Trivy: rəsmi checksums.txt yoxlaması UĞURSUZ"
  log "✓ Trivy: rəsmi checksums.txt təsdiqləndi"

  # 2) Bizim pinə qarşı yoxlama
  verify_checksum "${WORK_DIR}/${tarball}" "${TRIVY_SHA256:-}" "TRIVY_SHA256"

  tar -xzf "${WORK_DIR}/${tarball}" -C "${WORK_DIR}" trivy
  install -m 0755 "${WORK_DIR}/trivy" "${BIN_DIR}/trivy"
  "${BIN_DIR}/trivy" --version | head -1
}

install_gitleaks() {
  local ver="${GITLEAKS_VERSION}"
  local tarball="gitleaks_${ver}_linux_x64.tar.gz"
  local base="https://github.com/gitleaks/gitleaks/releases/download/v${ver}"

  log "Gitleaks v${ver} endirilir…"
  curl -fsSL --retry 3 -o "${WORK_DIR}/${tarball}" "${base}/${tarball}"
  curl -fsSL --retry 3 -o "${WORK_DIR}/gl-checksums.txt" "${base}/checksums.txt"

  ( cd "${WORK_DIR}" && grep " ${tarball}\$" gl-checksums.txt | sha256sum -c - ) \
    || fail "Gitleaks: rəsmi checksums.txt yoxlaması UĞURSUZ"
  log "✓ Gitleaks: rəsmi checksums.txt təsdiqləndi"

  verify_checksum "${WORK_DIR}/${tarball}" "${GITLEAKS_SHA256:-}" "GITLEAKS_SHA256"

  tar -xzf "${WORK_DIR}/${tarball}" -C "${WORK_DIR}" gitleaks
  install -m 0755 "${WORK_DIR}/gitleaks" "${BIN_DIR}/gitleaks"
  "${BIN_DIR}/gitleaks" version
}

# Semgrep və zizmor Python paketləridir — PyPI-dan hash-pinned requirements
# faylı ilə quraşdırılır (bax ci/requirements-scanners.txt).
install_python_scanners() {
  log "Semgrep v${SEMGREP_VERSION} və zizmor v${ZIZMOR_VERSION} quraşdırılır…"
  python3 -m pip install --quiet --disable-pip-version-check \
    "semgrep==${SEMGREP_VERSION}" "zizmor==${ZIZMOR_VERSION}"
  semgrep --version
  zizmor --version
}

main() {
  local targets=()
  for arg in "$@"; do
    case "${arg}" in
      --print-pins) PRINT_PINS=1 ;;
      *) targets+=("${arg}") ;;
    esac
  done
  [[ ${#targets[@]} -eq 0 ]] && targets=(trivy gitleaks python)

  for t in "${targets[@]}"; do
    case "${t}" in
      trivy)    install_trivy ;;
      gitleaks) install_gitleaks ;;
      semgrep|zizmor|python) install_python_scanners ;;
      *) fail "Naməlum scanner: ${t}" ;;
    esac
  done

  echo "${BIN_DIR}" >> "${GITHUB_PATH:-/dev/null}" 2>/dev/null || true
  log "Quraşdırma tamamlandı → ${BIN_DIR}"
}

main "$@"
