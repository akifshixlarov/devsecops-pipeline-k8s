# Supply Chain Security (Phase 4)

## Etibar zənciri

```
Source → Scan → Build → Scan → Promote → Sign → Verify → Lock → Deploy
  │       │       │       │       │        │       │       │       │
  │       │       │       │       │        │       │       │       └─ Phase 5
  │       │       │       │       │        │       │       └─ ACR immutability
  │       │       │       │       │        │       └─ Gate 7B (müstəqil job)
  │       │       │       │       │        └─ Gate 7 (Cosign keyless)
  │       │       │       │       └─ az acr import + digest doğrulaması
  │       │       │       └─ Gate 6A/6B/6C (Hadolint, CVE, layer secret)
  │       │       └─ Gate 5 (Buildx → quarantine)
  │       └─ Gate 1–4B (SAST, SCA, Secret, IaC, CI)
  └─ Gate 0 (pre-commit)
```

Hər addım yalnız əvvəlkinin PASS-i ilə mümkündür. **İmza bu zəncirin
xülasəsidir:** "bu artefakt bütün security bar-ımızdan keçdi" ifadəsi.

---

## Keyless imzalama — niyə statik açar deyil

Statik `cosign.key` problemi həll etmir, sadəcə köçürür: indi qorunmalı olan
uzunömürlü private key var. O sızarsa, hücumçu istənilən image-i "etibarlı"
kimi imzalayır və bunu aşkarlamaq praktiki olaraq mümkün olmur.

| | Statik açar | Keyless (OIDC) |
|---|---|---|
| Private key ömrü | Aylar/illər | ~10 dəqiqə, diskə yazılmır |
| Oğurlanma riski | Yüksək (repo secret) | Oğurlanacaq açar **yoxdur** |
| Kimlik | "açar sahibi" (anonim) | repo + workflow + branch |
| Audit izi | Yoxdur | Rekor transparency log |
| Rotasiya | Əl ilə, ağrılı | Hər imzada avtomatik |

Kimlik Fulcio sertifikatının SAN sahəsində saxlanılır:

```
https://github.com/OWNER/secure-cicd-capstone/.github/workflows/build.yml@refs/heads/main
```

---

## ⚠ Ən çox rast gəlinən səhv: "imzalanıbmı?" sualı

```bash
cosign verify myacr.azurecr.io/capstone/app@sha256:...   # ← MƏNASIZ
```

Sigstore **public instance**-dır. İstənilən şəxs istənilən image-i imzalaya
bilər. Kimlik məhdudiyyəti olmadan `cosign verify` yalnız "kimsə bunu
imzalayıb" deyir — heç bir təhlükəsizlik təminatı vermir.

Doğru sual: **"MƏHZ bizim repository-mizin MƏHZ bizim workflow-u imzalayıbmı?"**

```bash
cosign verify \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "^https://github\.com/OWNER/secure-cicd-capstone/\.github/workflows/build\.yml@refs/heads/main$" \
  --certificate-github-workflow-repository "OWNER/secure-cicd-capstone" \
  myacr.azurecr.io/capstone/app@sha256:...
```

Trust policy `security/cosign/trust-policy.env`-dədir — **yeganə həqiqət
mənbəyi**. Workflow-larda hardcoded kimlik yoxdur.

### Rədd edilən ssenarilər (test edilib)

| Ssenari | Nəticə |
|---|---|
| Legitim CI imzası (main, build.yml) | ✅ qəbul |
| Başqa branch-dən imza | ❌ rədd |
| Fork / başqa owner | ❌ rədd |
| Başqa workflow faylı (`pwn.yml`) | ❌ rədd |
| Tag ref-dən imza | ❌ rədd |

---

## Attestation-lar

İmzadan əlavə iki DSSE attestation bağlanır:

| Tip | Nə sübut edir |
|---|---|
| `cyclonedx` | Image-in **tam SBOM**-u (OS paketləri daxil) |
| `vuln` | İmzalandığı andakı **Trivy scan nəticəsi** |

**Niyə image SBOM-u, mənbə SBOM-u deyil:** Gate 2-dəki SBOM `package-lock.json`
əsasındadır. Bu isə base image-in OS paketlərini (glibc, openssl, ca-certificates)
də əhatə edir. İkisi fərqli artefaktdır; deploy edilən image olduğuna görə
imzalanan SBOM da image-in olmalıdır.

`vuln` attestation-ı "biz bunu skan etmişdik" iddiasını **yoxlanıla bilən
sübuta** çevirir (threat model § 3.3 STRIDE-R).

---

## Həmişə digest, heç vaxt tag

`cosign-sign.sh` və `cosign-verify.sh` tag qəbul etmir — `repo@sha256:...`
tələb edir və əks halda `exit 1`.

Səbəb: `cosign sign registry/app:v1` tag-ı həmin andakı digest-ə həll edir və
onu imzalayır. Tag sonra başqa manifest-ə keçirilərsə, imza "sanki" mövcuddur,
lakin **tamam başqa məzmuna** aiddir.

---

## Sıra: kilid imzalamadan SONRA

Phase 3-də manifest kilidi `acr-promote.sh`-də idi. **Bu səhv idi.**

Cosign imzanı OCI 1.1 Referrers API ilə subject manifest-ə bağlayır.
Kilidlənmiş manifest-ə referrer əlavə etmək ACR konfiqurasiyasından asılı
olaraq uğursuz ola bilər. Düzgün sıra:

```
promote → digest doğrula → SIGN + ATTEST → verify → LOCK
```

Konseptual olaraq da doğrudur: artefakt yalnız imzalandıqdan sonra
"buraxılmış" sayılır.

---

## ACR uyğunluğu

ACR OCI 1.1 Referrers API-ni dəstəkləyir — **istisna: customer-managed key
(CMK) ilə şifrələnmiş registry**. Belə halda:

```bash
# security/cosign/trust-policy.env
COSIGN_REFERRERS_MODE="legacy"    # sha256-<digest>.sig tag sxemi
```

İmzalama və doğrulama **eyni rejimdə** olmalıdır.

---

## Lokal doğrulama (auditor üçün)

```bash
bash ci/install-scanners.sh cosign
az acr login --name <ACR_NAME>

IMAGE_REF="<acr>.azurecr.io/capstone/app@sha256:..." \
  bash ci/cosign-verify.sh
```

Rekor-dakı şəffaflıq qeydini görmək:

```bash
cosign tree <acr>.azurecr.io/capstone/app@sha256:...
```

---

## Versiya qeydi — Cosign v3

`ci/scanner-versions.env`-də `COSIGN_VERSION=3.1.2` pinlənib. v3-də:

- `--tlog-upload` **deprecated**-dir və `--use-signing-config` ilə birlikdə
  xəta verir — skriptlərimizdə istifadə edilmir
- İmzalar default olaraq **OCI 1.1 referrers** ilə saxlanılır
- Verification-da `--certificate-identity*` və `--certificate-oidc-issuer`
  **məcburidir** (v2+ davranışı)
- `sign-blob` üçün `--bundle` artıq məcburidir
