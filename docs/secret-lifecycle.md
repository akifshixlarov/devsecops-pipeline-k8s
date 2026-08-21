# Secret Detection Lifecycle

Secret-lərə qarşı müdafiə **tək nöqtədə deyil, dörd mərhələdə** qurulur. Hər gate
əvvəlkinin buraxdığını tutur (defense in depth) və hər sonrakı gate-də düzəliş
dəyəri kəskin artır.

```text
Gate 1 — Pre-commit          →  Gitleaks (lokal git hook)          ✅ tətbiq olunub
    ↓
Gate 2 — CI / Push / PR      →  Gitleaks (GitHub Actions)          ✅ tətbiq olunub
    ↓
Gate 3 — Build / Artifact    →  Trivy image + layer secret scan    ⏳ Phase 3
    ↓
Gate 4 — Runtime / Monitor   →  Falco / Tetragon                   ⏳ Phase 8
```

## Niyə dörd gate?

| Gate | Secret harada tutulur | Düzəliş dəyəri | Rotasiya lazımdır? |
|---|---|---|---|
| **1 — Pre-commit** | Developer maşınında, commit yaranmazdan əvvəl | ~0 (faylı redaktə et) | **Xeyr** |
| **2 — CI/PR** | Push edildikdən sonra, merge-dən əvvəl | Orta (history təmizləmə) | **Bəli** |
| **3 — Image** | Build artefaktında | Yüksək (rebuild + repush) | **Bəli** |
| **4 — Runtime** | İşləyən konteynerdə | Ən yüksək (insident cavabı) | **Bəli + təhqiqat** |

Əsas fərq **Gate 1 ilə Gate 2 arasındadır**: Gate 1 secret-in git tarixçəsinə
ümumiyyətlə düşməsinin qarşısını alır. Gate 2-yə çatan secret isə artıq remote-da
immutable şəkildə mövcuddur — fayldan silmək **kifayət deyil**, credential
kompromis sayılmalı və rotasiya edilməlidir.

---

## Gate 1 — Pre-commit (developer setup)

### Aktivləşdirmə

Repository clone etdikdən sonra **bir dəfə**:

```bash
bash ci/setup-hooks.sh
```

Bu skript:
1. `git config core.hooksPath .githooks` təyin edir
2. Hook-un icra icazəsini yoxlayır
3. Gitleaks-in mövcudluğunu təsdiqləyir

Gitleaks quraşdırılmayıbsa:

```bash
bash ci/install-scanners.sh gitleaks
export PATH="$HOME/.local/bin:$PATH"   # .bashrc / .zshrc faylınıza əlavə edin
```

### Niyə `core.hooksPath`, `.git/hooks/` deyil

`.git/` qovluğu versiya nəzarətində **deyil** — ora fayl commit etmək mümkün
deyil. `core.hooksPath` isə Git-ə hook-ları repo daxilindəki `.githooks/`
qovluğundan oxumağı bildirir. Nəticədə hook:

- repo ilə birlikdə paylanır,
- code review-dən keçir,
- hər developer-də eynidir.

**Dizayn məhdudiyyəti (açıq şəkildə qeyd olunur):** `core.hooksPath` lokal
konfiqurasiyadır və hər developer bir dəfə işə salmalıdır. Həmçinin
`git commit --no-verify` hook-ları tamamilə atlayır. Məhz buna görə Gate 1
**tək müdafiə xətti sayılmır** — server tərəfindəki Gate 2 bypass edilə bilməz
və branch protection ilə məcburidir.

### Nə baş verir

```text
Developer → git commit → .githooks/pre-commit → Gitleaks
                                                    ↓
                                        secret tapıldı?
                                        ├── BƏLİ → exit 1 → COMMIT BLOKLANDI
                                        └── XEYR → exit 0 → COMMIT KEÇDİ
```

Hook yalnız **staged** məzmunu skan edir (`git show :<path>` ilə index-dən
oxunur), ona görə "faylın bir hissəsini stage etdim" ssenarisi düzgün işləyir.

### Gözlənilən çıxış

Secret tapıldıqda:

```text
$ git commit -m "test"

Gitleaks — pre-commit secret scan (1 staged fayl)

══════════════════════════════════════════════════════════
  Gitleaks detected a potential secret.
  COMMIT BLOCKED.
══════════════════════════════════════════════════════════

  1 finding staged dəyişikliklərdə tapıldı:

    • app/src/config.js:3
      qayda: capstone-generic-env-secret — ...
```

Təmiz dəyişiklikdə:

```text
$ git commit -m "safe change"

Gitleaks — pre-commit secret scan (2 staged fayl)
✓ Gitleaks passed. Commit allowed.
```

### Test

```bash
bash tests/red/run-precommit-test.sh
```

RED (secret bloklanır), GREEN (təmiz commit keçir) və allowlist testlərini
icra edir. Test secret-i **runtime-da generasiya olunur** və repo-da heç vaxt
saxlanmır — əks halda Gate 2 (bütün git tarixçəsini skan edir) onu tutub
pipeline-ı əbədi qırmızı saxlayardı.

---

## Gate 2 — CI / Push / Pull Request

GitHub Actions workflow-unda `Gate 3 — Secret Detection (Gitleaks)` job-u
(bax `.github/workflows/security.yml`). Bu remediation-da **dəyişdirilməyib**.

Fərqlər:

| | Gate 1 (pre-commit) | Gate 2 (CI) |
|---|---|---|
| Skan sahəsi | Yalnız staged fayllar | **Bütün git tarixçəsi** (`fetch-depth: 0`) |
| Bypass | `--no-verify` ilə mümkün | **Mümkün deyil** |
| DefectDojo | Yox | Bəli (`reimport-scan`) |
| Məcburilik | Könüllü setup | Branch protection ilə required |

**Hər iki gate eyni konfiqurasiyanı paylaşır:** `security/gitleaks/gitleaks.toml`.
Bu qəsdəndir — əks halda developer lokal olaraq "təmiz" görünüb CI-da qırmızı
alardı (və ya daha pisi, əksinə).

---

## False positive idarəetməsi

İki yol var, hər ikisi code review tələb edir:

1. **Sətir səviyyəsində:** `// gitleaks:allow` şərhi
2. **Fingerprint səviyyəsində:** `.gitleaksignore` faylına əlavə (səbəb şərhi ilə)

`security/gitleaks/gitleaks.toml` faylında artıq təhlükəsiz pattern-lər üçün
qayda səviyyəsində allowlist var: `process.env`, `secretKeyRef`, `valueFrom`,
`${...}` və s. Yəni **düzgün kod** (secret-i environment-dən oxumaq) heç vaxt
flag olunmur.

> ⚠️ **Real secret-i susdurmaq üçün allowlist əlavə etmək qadağandır.**
> Doğru addımlar: (1) credential-ı dərhal rotasiya et, (2) kodu env variable
> istifadə edəcək şəkildə düzəlt, (3) lazım gələrsə `git-filter-repo` ilə
> tarixçəni təmizlə.
