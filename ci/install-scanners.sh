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

# ── Versiya pinlerinin movcudlugu ───────────────────────────────────────────
# `set -u` altinda catismayan deyisen "unbound variable" verir — bu mesaj
# ise problemi izah etmir. Asagidaki yoxlama scanner-versions.env faylinin
# kohne oldugunu ACIQ sekilde bildirir.
# (Bu, real istifadede rast gelinmis problemdir: install-scanners.sh
#  yenilenib, lakin scanner-versions.env kohne qalib.)
require_pin() {
  local var="$1" scanner="$2"
  if [[ -z "${!var:-}" ]]; then
    printf '::error::%s\n' "${var} tapilmadi — ci/scanner-versions.env faylı köhnədir.

  '${scanner}' quraşdırmaq üçün ci/scanner-versions.env faylında
  ${var} sətri olmalıdır.

  Cari fayldakı pinlər:
$(grep -E '^[A-Z0-9_]+_VERSION=' "${REPO_ROOT}/ci/scanner-versions.env" 2>/dev/null | sed 's/^/    /' || echo '    (fayl oxunmadı)')

  Həll: ci/scanner-versions.env faylını ən son versiya ilə əvəz edin." >&2
    exit 1
  fi
}

BIN_DIR="${HOME}/.local/bin"
WORK_DIR="$(mktemp -d)"
# Resmi checksums yoxlamasi kecdiyi halda 1 olur (diaqnostika ucun).
OFFICIAL_CHECKSUM_OK=0
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
      # Diaqnostika: resmi checksums.txt kecdisə, binary mənbədə düzgündür,
      # yəni problem böyük ehtimalla YANLIŞ PİN-dir (kompromis deyil).
      # Bu fərqi göstərmək vacibdir — əks halda istifadəçi "hücum var" deyə
      # panikaya düşür və ya (daha pisi) yoxlamanı tamamilə söndürür.
      local hint=""
      if [[ "${OFFICIAL_CHECKSUM_OK:-0}" == "1" ]]; then
        hint="
      DİAQNOSTİKA: rəsmi checksums faylı bu binary-ni TƏSDİQLƏDİ.
      Yəni endirilən fayl mənbədə elan olunanla eynidir və kompromis
      əlaməti YOXDUR. Ən ehtimallı səbəb: ${label} sətrinə YANLIŞ dəyər
      yazılıb (məsələn başqa alətin hash-i səhv slota köçürülüb).

      HƏLL:
        1) ci/scanner-versions.env faylında ${label} sətrini boşaldın:
             ${label}=
        2) Yenidən işlədin — skript düzgün dəyəri çap edəcək.
        3) Çap olunan dəyəri MƏHZ ${label} sətrinə yazın.

      DİQQƏT: hər alətin öz hash-i var. Onları qarışdırmayın."
      else
        hint="
      DİQQƏT: rəsmi checksums yoxlaması da KEÇMƏDİ və ya mövcud deyil.
      Bu, real kompromis əlaməti ola bilər — pini KÖRLƏMƏYİN,
      əvvəlcə release-i müstəqil mənbədən yoxlayın."
      fi

      fail "${label}: SHA256 UYĞUNSUZLUĞU!
        Gözlənilən (pin): ${expected}
        Alınan (fayl)   : ${actual}
${hint}

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
  require_pin TRIVY_VERSION trivy
  local ver="${TRIVY_VERSION}"
  local tarball="trivy_${ver}_Linux-64bit.tar.gz"
  local base="https://github.com/aquasecurity/trivy/releases/download/v${ver}"

  log "Trivy v${ver} endirilir…"
  curl -fsSL --retry 3 -o "${WORK_DIR}/${tarball}" "${base}/${tarball}"
  curl -fsSL --retry 3 -o "${WORK_DIR}/checksums.txt" "${base}/trivy_${ver}_checksums.txt"

  # 1) Rəsmi checksums.txt-ə qarşı yoxlama
  ( cd "${WORK_DIR}" && grep " ${tarball}\$" checksums.txt | sha256sum -c - ) \
    || fail "Trivy: rəsmi checksums.txt yoxlaması UĞURSUZ"
  OFFICIAL_CHECKSUM_OK=1
  log "✓ Trivy: rəsmi checksums.txt təsdiqləndi"

  # 2) Bizim pinə qarşı yoxlama
  verify_checksum "${WORK_DIR}/${tarball}" "${TRIVY_SHA256:-}" "TRIVY_SHA256"

  tar -xzf "${WORK_DIR}/${tarball}" -C "${WORK_DIR}" trivy
  install -m 0755 "${WORK_DIR}/trivy" "${BIN_DIR}/trivy"
  "${BIN_DIR}/trivy" --version | head -1
}

install_gitleaks() {
  require_pin GITLEAKS_VERSION gitleaks
  local ver="${GITLEAKS_VERSION}"
  local tarball="gitleaks_${ver}_linux_x64.tar.gz"
  local base="https://github.com/gitleaks/gitleaks/releases/download/v${ver}"

  log "Gitleaks v${ver} endirilir…"
  curl -fsSL --retry 3 -o "${WORK_DIR}/${tarball}" "${base}/${tarball}"
  # ⚠ Asset adı: Gitleaks checksums faylı `checksums.txt` DEYİL,
  # `gitleaks_<versiya>_checksums.txt`-dir (Trivy ilə eyni sxem).
  # Əvvəlki versiyada bu səhv idi və 404 verirdi.
  curl -fsSL --retry 3 -o "${WORK_DIR}/gl-checksums.txt" "${base}/gitleaks_${ver}_checksums.txt"

  ( cd "${WORK_DIR}" && grep " ${tarball}\$" gl-checksums.txt | sha256sum -c - ) \
    || fail "Gitleaks: rəsmi checksums.txt yoxlaması UĞURSUZ"
  OFFICIAL_CHECKSUM_OK=1
  log "✓ Gitleaks: rəsmi checksums.txt təsdiqləndi"

  verify_checksum "${WORK_DIR}/${tarball}" "${GITLEAKS_SHA256:-}" "GITLEAKS_SHA256"

  tar -xzf "${WORK_DIR}/${tarball}" -C "${WORK_DIR}" gitleaks
  install -m 0755 "${WORK_DIR}/gitleaks" "${BIN_DIR}/gitleaks"
  "${BIN_DIR}/gitleaks" version
}

# Semgrep və zizmor Python paketləridir — PyPI-dan hash-pinned requirements
# faylı ilə quraşdırılır (bax ci/requirements-scanners.txt).
install_hadolint() {
  require_pin HADOLINT_VERSION hadolint
  local ver="${HADOLINT_VERSION}"
  local bin="hadolint-Linux-x86_64"
  local base="https://github.com/hadolint/hadolint/releases/download/v${ver}"

  log "Hadolint v${ver} endirilir…"
  curl -fsSL --retry 3 -o "${WORK_DIR}/${bin}" "${base}/${bin}"
  # ⚠ Hadolint checksum yayimlanmasi RELEASE-DEN RELEASE-E DEYISIR:
  # bezi versiyalarda `<asset>.sha256` fayli var, bezilerinde (o cumleden
  # v2.15.1) YALNIZ binary yayimlanir. Ona gore 404 NORMAL haldir ve
  # quraşdirmani dayandirmir — sadece bir mudafie qati az olur.
  # Bu halda lokal SHA256 pin XUSUSILE vacibdir (yegane qat odur).
  # stderr susdurulur ki, gozlenilen 404 real xeta kimi gorunmesin.
  if curl -fsSL --retry 2 -o "${WORK_DIR}/${bin}.sha256" "${base}/${bin}.sha256" 2>/dev/null; then
    :
  else
    rm -f "${WORK_DIR}/${bin}.sha256"
    log "  (bu release ucun resmi .sha256 fayli yayimlanmayib — normaldir)"
  fi

  if [[ -s "${WORK_DIR}/${bin}.sha256" ]]; then
    local expected_official
    expected_official="$(awk '{print $1}' "${WORK_DIR}/${bin}.sha256")"
    local actual
    actual="$(sha256sum "${WORK_DIR}/${bin}" | awk '{print $1}')"
    if [[ "${expected_official}" != "${actual}" ]]; then
      fail "Hadolint: resmi .sha256 yoxlamasi UGURSUZ"
    fi
    OFFICIAL_CHECKSUM_OK=1
    log "✓ Hadolint: resmi .sha256 tesdiqlendi"
  else
    log "⚠ Hadolint: resmi .sha256 alinmadi — yalniz lokal pin yoxlanilir"
  fi

  verify_checksum "${WORK_DIR}/${bin}" "${HADOLINT_SHA256:-}" "HADOLINT_SHA256"

  install -m 0755 "${WORK_DIR}/${bin}" "${BIN_DIR}/hadolint"
  "${BIN_DIR}/hadolint" --version
}

install_cosign() {
  require_pin COSIGN_VERSION cosign
  local ver="${COSIGN_VERSION}"
  local bin="cosign-linux-amd64"
  local base="https://github.com/sigstore/cosign/releases/download/v${ver}"

  log "Cosign v${ver} endirilir…"
  curl -fsSL --retry 3 -o "${WORK_DIR}/${bin}" "${base}/${bin}"
  curl -fsSL --retry 3 -o "${WORK_DIR}/cosign_checksums.txt" "${base}/cosign_checksums.txt" || true

  if [[ -s "${WORK_DIR}/cosign_checksums.txt" ]]; then
    ( cd "${WORK_DIR}" && grep " ${bin}\$" cosign_checksums.txt | sha256sum -c - ) \
      || fail "Cosign: resmi checksums yoxlamasi UGURSUZ"
    OFFICIAL_CHECKSUM_OK=1
    log "✓ Cosign: resmi checksums tesdiqlendi"
  else
    log "⚠ Cosign: resmi checksums alinmadi"
  fi

  verify_checksum "${WORK_DIR}/${bin}" "${COSIGN_SHA256:-}" "COSIGN_SHA256"

  install -m 0755 "${WORK_DIR}/${bin}" "${BIN_DIR}/cosign"
  "${BIN_DIR}/cosign" version --json 2>/dev/null | head -3 || "${BIN_DIR}/cosign" version 2>&1 | tail -2
}

install_python_scanners() {
  require_pin SEMGREP_VERSION semgrep
  require_pin ZIZMOR_VERSION zizmor
  log "Semgrep v${SEMGREP_VERSION} və zizmor v${ZIZMOR_VERSION} quraşdırılır…"
  # PEP 668: Debian/Kali/Ubuntu kimi distro-larda sistem Python "externally
  # managed"-dir ve birbasa `pip install` REDD OLUNUR. GitHub runner-de bu
  # problem yoxdur (actions/setup-python virtual muhit qurur), lakin lokal
  # maşinda qacilmazdir. Ona gore avtomatik olaraq venv-e kecirik —
  # bu, sistem Python-una toxunmadan deterministik quraşdirma verir.
  local pip_args=(--quiet --disable-pip-version-check)
  local venv_dir="${HOME}/.local/share/capstone-scanners-venv"

  if python3 -m pip install "${pip_args[@]}" \
       "semgrep==${SEMGREP_VERSION}" "zizmor==${ZIZMOR_VERSION}" 2>/dev/null; then
    log "  (sistem Python-una quraşdirildi)"
  else
    log "  Sistem Python 'externally managed'-dir (PEP 668) — venv istifade olunur:"
    log "    ${venv_dir}"
    python3 -m venv "${venv_dir}" 2>/dev/null || fail "venv yaradilmadi (python3-venv paketi quraşdirilib?)"
    "${venv_dir}/bin/pip" install "${pip_args[@]}" \
      "semgrep==${SEMGREP_VERSION}" "zizmor==${ZIZMOR_VERSION}" \
      || fail "semgrep/zizmor quraşdirilmadi"
    ln -sf "${venv_dir}/bin/semgrep" "${BIN_DIR}/semgrep"
    ln -sf "${venv_dir}/bin/zizmor"  "${BIN_DIR}/zizmor"
  fi
  "${BIN_DIR}/semgrep" --version 2>/dev/null || semgrep --version
  "${BIN_DIR}/zizmor" --version 2>/dev/null || zizmor --version
}

main() {
  local targets=()
  for arg in "$@"; do
    case "${arg}" in
      --print-pins) PRINT_PINS=1 ;;
      *) targets+=("${arg}") ;;
    esac
  done
  [[ ${#targets[@]} -eq 0 ]] && targets=(trivy gitleaks hadolint cosign python)

  for t in "${targets[@]}"; do
    case "${t}" in
      trivy)    install_trivy ;;
      gitleaks) install_gitleaks ;;
      hadolint) install_hadolint ;;
      cosign)   install_cosign ;;
      semgrep|zizmor|python) install_python_scanners ;;
      *) fail "Naməlum scanner: ${t}" ;;
    esac
  done

  echo "${BIN_DIR}" >> "${GITHUB_PATH:-/dev/null}" 2>/dev/null || true
  log "Quraşdırma tamamlandı → ${BIN_DIR}"
}

main "$@"
