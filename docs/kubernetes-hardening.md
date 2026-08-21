# Kubernetes Hardening (Phase 5)

## Manifest strukturu — məsuliyyət ayrılığı

```
k8s/
├── bootstrap/     ← ADMIN, bir dəfəlik. CI bunlara toxuna BİLMİR.
│   ├── namespace.yaml       (Pod Security Standards: restricted)
│   ├── rbac.yaml            (ServiceAccount + CI Role/RoleBinding)
│   ├── networkpolicy.yaml   (default-deny + açıq allow)
│   └── service.yaml
├── app/           ← CI, hər deploy-da
│   ├── deployment.yaml
│   └── pdb.yaml
└── policy/
    └── kyverno-verify-images.yaml   (şablon — render olunur)
```

### Bu ayrılıq niyə var — real tapıntı

İlk versiyada hamısı bir yerdə idi və CI Role-una `networkpolicies` + `services`
üzərində yazma icazəsi verilmişdi. **Öz Gate 4-ümüz (Trivy config) onu tutdu:**

```
HIGH  KSV-0056  rbac.yaml  Manage Kubernetes networking
"The ability to control which pods get service traffic directed to them
 allows for interception attacks. Controlling network policy allows for
 bypassing lateral movement restrictions."
```

İki konkret hücum mümkün idi:

1. **NetworkPolicy silmək** → CI kompromis olarsa, hücumçu əvvəlcə default-deny
   policy-ni silib sonra sərbəst egress (reverse shell, data exfiltration) edir.
2. **Service selector dəyişmək** → trafik başqa pod-a yönləndirilir; URL eyni
   qalır, istifadəçi fərqi görmür, trafik oğurlanır.

Susdurmaq əvəzinə arxitekturanı dəyişdik: **CI tətbiqin yeni versiyasını deploy
edə bilir, lakin onu qoruyan təhlükəsizlik hasarına toxuna bilmir.**

Nəticə: HIGH tapıntı 0-a düşdü, Gate 4 PASS.

---

## Müdafiə qatları

| Qat | Harada | Bypass edilə bilərmi |
|---|---|---|
| Gate 4 — Trivy config | CI, merge-dən əvvəl | Bəli (əl ilə `kubectl apply`) |
| `ci/k8s-deploy.sh` imza yoxlaması | Deploy skripti | Bəli (skripti işlətməmək) |
| **Pod Security Standards** | API server admission | **Xeyr** |
| **Kyverno verifyImages** | API server admission | **Xeyr** |

Son iki qat kritikdir: onlar "pipeline nizam-intizamı"ndan "texniki təminat"a
keçidi təmin edir.

---

## Hardening control-ları

| Control | Dəyər | Hansı threat | Pozularsa |
|---|---|---|---|
| `runAsNonRoot` | `true` | T3 (High) | Container escape → birbaşa root |
| `runAsUser` | `65532` **rəqəmsal** | T3 | Simvolik ad → `CreateContainerConfigError` |
| `readOnlyRootFilesystem` | `true` | §3.8 STRIDE-T | Runtime-da binary dəyişdirilməsi, webshell |
| `allowPrivilegeEscalation` | `false` | §3.8 STRIDE-E | setuid ilə imtiyaz artımı |
| `capabilities.drop` | `[ALL]` | §3.8 STRIDE-E | Lazımsız kernel imkanları |
| `seccompProfile` | `RuntimeDefault` | §3.8 | Kernel exploit səthi genişlənir |
| `automountServiceAccountToken` | `false` | §3.8 STRIDE-E | RCE → K8s API kəşfiyyatı |
| `memory limits` | `256Mi` | §3.7 STRIDE-D | OOM → bütün node |

### `runAsUser: 65532` — niyə rəqəmsal

Phase 3-də Hadolint `DL3066` ilə tapdı. Kubelet simvolik adı doğrulaya bilmir:

```
container has runAsNonRoot and image has non-numeric user (nonroot),
cannot verify user is non-root
```

Dəyər `app/Dockerfile`-dakı `USER 65532:65532` ilə **eyni olmalıdır**.

### `automountServiceAccountToken: false` — iki yerdə

Həm ServiceAccount-da, həm pod spec-də. Pod spec SA-dakını override edir —
yalnız SA-da yazılsaydı, kimsə pod spec-ə `true` əlavə edərək müdafiəni
sükutla ləğv edə bilərdi.

### CPU limit-i niyə yoxdur

CPU **sıxıla bilən** resursdur — limit olmadan pod digərlərini "öldürə" bilmir,
sadəcə yavaşlayır. CPU throttling isə Node.js event loop-unda gecikmə yaradır.
Memory **sıxılmayan** resursdur — limit məcburidir.

Trivy bunu `LOW KSV-0011` kimi qeyd edir; policy-mizdə `low → warn`, ona görə
bloklamır. Bu, şüurlu qərardır, unutqanlıq deyil.

---

## NetworkPolicy

Kubernetes-də default davranış **"hamıya icazə"**dir. Policy olmayan
namespace-də istənilən pod istənilən pod-a müraciət edə bilər.

```
default-deny-all              → Ingress + Egress bağlanır
allow-dns-egress              → yalnız kube-dns:53
allow-ingress-from-controller → yalnız ingress-nginx → :3000
allow-dast-scanner            → yalnız capstone-dast (LAB-ONLY)
```

**Egress-in bağlanması qəsdəndir.** Əksər nümunələr yalnız ingress-i bağlayır.
Halbuki data exfiltration, reverse shell və C2 əlaqəsi egress-dir.

**DNS mütləq açılmalıdır** — default-deny tətbiq edərkən ən çox rast gəlinən
nasazlıq səbəbi budur.

### ⚠ AKS-də kritik tələb

Cluster `--network-policy azure` (və ya `cilium`) ilə yaradılmalıdır. Bu
parametr olmadan NetworkPolicy obyektləri **qəbul olunur, lakin heç bir təsir
göstərmir** — yəni "policy var" görünür, əslində heç nə bloklanmır.

```bash
az aks show -g "$RG" -n "$CLUSTER" --query networkProfile.networkPolicy -o tsv
# gözlənilən: azure
```

`ci/k8s-evidence.sh` bunu avtomatik yoxlayır.

---

## AKS Setup

```bash
export RG="rg-capstone-devsecops"
export CLUSTER="aks-capstone"
export ACR_NAME="<phase3-dəki ACR adı>"
export LOCATION="westeurope"

az aks create \
  --resource-group "$RG" \
  --name "$CLUSTER" \
  --location "$LOCATION" \
  --node-count 2 \
  --node-vm-size Standard_B2s \
  --network-plugin azure \
  --network-policy azure \
  --enable-aad \
  --enable-azure-rbac \
  --disable-local-accounts \
  --attach-acr "$ACR_NAME" \
  --generate-ssh-keys
```

| Parametr | Niyə |
|---|---|
| `--network-policy azure` | Bunsuz NetworkPolicy **təsirsizdir** |
| `--enable-aad --enable-azure-rbac` | Entra ID kimliyi; kubeconfig secret-i lazım deyil |
| `--disable-local-accounts` | `--admin` kubeconfig bütün RBAC-ı bypass edir |
| `--attach-acr` | Kubelet identity-yə `AcrPull`; **imagePullSecret lazım deyil** |

### CI identity-yə AKS icazəsi

```bash
CLUSTER_ID=$(az aks show -g "$RG" -n "$CLUSTER" --query id -o tsv)
SP_ID=$(az ad sp show --id "$AZURE_CLIENT_ID" --query id -o tsv)

# Yalnız kubeconfig almaq üçün — cluster-admin DEYİL
az role assignment create \
  --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
  --role "Azure Kubernetes Service Cluster User Role" \
  --scope "$CLUSTER_ID"
```

Faktiki icazələr Kubernetes RBAC ilə verilir (`k8s/bootstrap/rbac.yaml`) və
yalnız `capstone` namespace-i ilə məhdudlaşır.

### Federated credential əlavəsi

Phase 3-dəki `production` environment credential-ı deploy üçün də işləyir —
əlavə heç nə lazım deyil.

---

## Bootstrap (bir dəfəlik, admin)

```bash
# 1. CI principal-ın OBJECT ID-si (application ID DEYİL — ən çox səhv burada olur)
CI_OBJECT_ID=$(az ad sp show --id "$AZURE_CLIENT_ID" --query id -o tsv)
sed -i "s|__CI_PRINCIPAL_OBJECT_ID__|${CI_OBJECT_ID}|" k8s/bootstrap/rbac.yaml

# 2. Tətbiq
kubectl apply -f k8s/bootstrap/

# 3. Kyverno
helm repo add kyverno https://kyverno.github.io/kyverno
helm install kyverno kyverno/kyverno -n kyverno --create-namespace --wait

# 4. Admission policy (trust-policy.env-dən render olunur)
ACR_NAME="$ACR_NAME" bash ci/render-kyverno-policy.sh /tmp/kyverno.yaml
kubectl apply -f /tmp/kyverno.yaml
```

---

## Doğrulama

```bash
kubectl get pods -n capstone -o wide
kubectl get svc,networkpolicy,sa,role,rolebinding,pdb -n capstone

# Hardening cluster-dən oxunur (manifestdən deyil)
NAMESPACE=capstone AKS_RESOURCE_GROUP="$RG" AKS_CLUSTER_NAME="$CLUSTER" \
  bash ci/k8s-evidence.sh

# Least privilege sübutu — hamısı "no" olmalıdır
kubectl auth can-i delete deployments -n capstone
kubectl auth can-i get secrets -n capstone
kubectl auth can-i patch networkpolicies -n capstone
```

### İmzasız image RED testi

```bash
# Kyverno bunu admission səviyyəsində rədd etməlidir
kubectl run test-unsigned -n capstone --image=nginx:latest
# gözlənilən: admission webhook "mutate.kyverno.svc-fail" denied the request
```

---

## Lokal test (cluster olmadan)

```bash
bash tests/red/run-k8s-test.sh
```

8 yoxlama: sxem validliyi, Gate 4 GREEN/RED, tag rədd edilməsi, hardening
control-larının mövcudluğu, NetworkPolicy default-deny, CI Role least privilege.
