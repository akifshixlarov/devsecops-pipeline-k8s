# Evidence Plan — GREEN/RED Pipeline Sübutları

Bu sənəd capstone təqdimatı üçün hansı screenshot-ların, hansı ardıcıllıqla
alınacağını göstərir.

---

## Prinsip: `main` yaşıl, RED sübutlar branch-də

RED pipeline-lar GitHub Actions tarixçəsində **əbədi qalır** — bu, bizim
sübutumuzdur. Lakin `main` branch-inin tarixçəsi yaşıl olmalıdır ki, portfolio
"işləyən pipeline" təəssüratı versin.

Ona görə hər RED ssenarisi ayrıca `evidence/red/*` branch-ində və PR üzərində
göstərilir. Branch-lər sonra silinir — **Actions run tarixçəsi qalır**, yəni
screenshot-larınız etibarlı olur.

---

## Addım 1 — GREEN baseline (əvvəlcə bu)

RED-dən **əvvəl** GREEN alın. Səbəb: RED branch-ləri yaratdıqdan sonra
Actions siyahısında qırmızı run-lar üstdə görünəcək və GREEN screenshot-u
tapmaq çətinləşəcək.

```bash
git checkout main
git commit --allow-empty -m "chore: trigger green baseline"
git push
```

| # | Screenshot | Harada |
|---|---|---|
| G1 | Bütün job-lar yaşıl (workflow run səhifəsi) | Actions → Security Gates → son run |
| G2 | Job summary — hər gate-in severity cədvəli | Həmin run → aşağı scroll |
| G3 | Build & Image Security — 10 job yaşıl | Actions → Build & Image Security |
| G4 | Cosign imza + Rekor index | Gate 7B job log-u |
| G5 | Deploy — digest və hardening cədvəli | Actions → Deploy to AKS |
| G6 | Branch protection qaydaları | Settings → Rules → Rulesets |
| G7 | Actions permissions = Read | Settings → Actions → General |

---

## Addım 2 — RED ssenariləri

Hər biri üçün ayrıca branch avtomatik yaradılır:

```bash
bash tests/red/make-red-branch.sh --list      # siyahı
bash tests/red/make-red-branch.sh sast        # bir gate
bash tests/red/make-red-branch.sh all         # hamısı
```

| # | Əmr | Pozulan gate | Screenshot |
|---|---|---|---|
| R1 | `sast` | Gate 1 — Semgrep | Gate 1 ❌, digərləri ✅ |
| R2 | `sca` | Gate 2 — Trivy SCA | CVE siyahısı ilə summary |
| R3 | `secret` | Gate 3 — Gitleaks | Finding yeri (dəyər redaktə olunub) |
| R4 | `iac` | Gate 4 — Trivy config | HIGH misconfiguration cədvəli |
| R5 | `ci` | Gate 4B — zizmor | template-injection tapıntısı |
| R6 | `dockerfile` | Gate 6A — Hadolint | DL3002/DL3007/DL3066 |

**Hər RED üçün 3 screenshot alın:**

1. **Workflow run** — hansı job qırmızıdır
2. **Job summary** — severity cədvəli və bloklayan finding
3. **PR səhifəsi** — `Merge` düyməsinin bloklandığı (branch protection işləyir)

Üçüncüsü ən vacibdir: o, gate-in sadəcə "hesabat verdiyini" deyil, **merge-i
həqiqətən bloklaadığını** sübut edir.

---

## Addım 3 — GREEN-ə qayıdış (eyni PR-da)

Hər RED üçün ən azı birində "düzəliş → yaşıl" dövrəsini göstərin. Bu, ən güclü
sübutdur, çünki səbəb-nəticə əlaqəsini tam bağlayır:

```bash
git checkout evidence/red/sast
git rm app/src/config.js
git commit -m "fix: remove hardcoded secret and eval"
git push
```

| # | Screenshot |
|---|---|
| F1 | Eyni PR-da: əvvəlki run ❌, yeni run ✅ |
| F2 | `Merge` düyməsi artıq aktivdir |

---

## Addım 4 — DefectDojo (Phase 6-dan sonra)

| # | Screenshot |
|---|---|
| D1 | Engagement — bütün scan tipləri bir yerdə |
| D2 | Finding siyahısı, severity üzrə |
| D3 | Eyni finding-in RED və GREEN run-dakı statusu (Active → Mitigated) |
| D4 | **Pipeline uğursuz olsa da finding DefectDojo-dadır** — bu, dizaynın əsas prinsipidir |

---

## Addım 5 — Kubernetes (Phase 5)

Terminal çıxışları da screenshot sayılır:

```bash
kubectl get pods -n capstone -o wide
kubectl get svc,networkpolicy,sa,role,rolebinding -n capstone

# Hardening cluster-dən oxunur, manifestdən yox
NAMESPACE=capstone AKS_RESOURCE_GROUP="$RG" AKS_CLUSTER_NAME="$CLUSTER" \
  bash ci/k8s-evidence.sh

# Least privilege — hamısı "no" olmalıdır
kubectl auth can-i delete deployments -n capstone
kubectl auth can-i get secrets -n capstone
kubectl auth can-i patch networkpolicies -n capstone
```

| # | Screenshot |
|---|---|
| K1 | `k8s-evidence.sh` çıxışı — PASS/FAIL cədvəli |
| K2 | Pod `securityContext` (`kubectl get pod -o yaml`) |
| K3 | NetworkPolicy siyahısı + `networkProfile.networkPolicy: azure` |
| K4 | `kubectl auth can-i` — "no" cavabları |
| K5 | Deployment image sahəsi — digest görünür |

### K6 — Admission RED testi (çox güclü sübut)

```bash
kubectl run test-unsigned -n capstone --image=nginx:latest
```

Gözlənilən:
```
Error from server: admission webhook "mutate.kyverno.svc-fail" denied the request:
resource Pod/capstone/test-unsigned was blocked due to the following policies:
  verify-capstone-image-signature: image is not signed
```

Bu screenshot pipeline-ı **tamamilə bypass edən** cəhdin bloklandığını göstərir.

---

## Addım 6 — Təmizləmə

```bash
bash tests/red/make-red-branch.sh --cleanup
```

Branch-lər silinir, **Actions run tarixçəsi qalır**.

---

## Fayl təşkili

```
evidence/
├── green/
│   ├── G1-security-gates-all-green.png
│   ├── G2-job-summary.png
│   └── ...
├── red/
│   ├── R1-sast/
│   │   ├── run.png
│   │   ├── summary.png
│   │   └── pr-merge-blocked.png
│   └── ...
├── fixed/
│   └── F1-red-to-green-same-pr.png
├── k8s/
│   ├── K1-hardening-evidence.png
│   └── K6-kyverno-denied-unsigned.png
└── defectdojo/
    └── D1-engagement-overview.png
```

`evidence/` qovluğu `.gitignore`-a əlavə edilməyib — screenshot-lar repo-da
qalmalıdır ki, employer onları görsün. Yalnız ölçüyə diqqət edin (PNG-ləri
sıxın, 500KB-dan böyük olmasın).

---

## ⚠ Screenshot alarkən

- **Secret dəyərləri görünməsin.** Gitleaks artifact-ları redaktə olunub, lakin
  terminal çıxışınızda real dəyər ola bilər.
- **Azure subscription ID və tenant ID-ni gizlədin** — `az account show`
  çıxışını screenshot-a salmayın.
- **ACR adı görünə bilər** (secret deyil), amma tam resource ID-ni gizlədin.
- Tarix/saat görünsün — bu, sübutun autentikliyini artırır.
