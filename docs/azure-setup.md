# Azure Setup — ACR + GitHub OIDC (Phase 3)

Bu sənəd Phase 3-ün işləməsi üçün Azure tərəfində bir dəfə edilməli
konfiqurasiyanı təsvir edir. Bütün əmrlər `az` CLI ilə icra olunur.

## Cloud seçimi əsaslandırması

Kubernetes üçün **AKS** seçilib (Phase 5). Səbəb: registry ACR olduğuna görə
eyni Entra ID tenant-ında qalmaq authentication zəncirini sadələşdirir —
AKS-in kubelet identity-sinə birbaşa `AcrPull` rolu verilir, yəni cluster-də
**imagePullSecret saxlamağa ehtiyac qalmır**. Bu, threat model-dəki T7
(secret sızması) səthini azaldır.

---

## 0. Dəyişənlər

```bash
export SUBSCRIPTION_ID="00000000-0000-0000-0000-000000000000"   # öz dəyəriniz
export RESOURCE_GROUP="rg-capstone-devsecops"
export LOCATION="westeurope"
export ACR_NAME="acrcapstone$RANDOM"      # qlobal unikal, yalnız kiçik hərf+rəqəm
export GITHUB_ORG="<github-user-or-org>"
export GITHUB_REPO="secure-cicd-capstone"
export APP_NAME="gh-capstone-oidc"

az account set --subscription "$SUBSCRIPTION_ID"
az group create --name "$RESOURCE_GROUP" --location "$LOCATION"
```

---

## 1. ACR yaratmaq

```bash
az acr create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$ACR_NAME" \
  --sku Standard \
  --location "$LOCATION"
```

**SKU seçimi:** `Standard` capstone üçün kifayətdir. `Premium` yalnız o halda
lazımdır ki, private endpoint, geo-replication və ya content trust tələb olunsun.

**Admin user AÇILMIR** (default olaraq bağlıdır — belə də qalmalıdır):

```bash
# Bunu YOXLAYIN — false olmalıdır
az acr show --name "$ACR_NAME" --query adminUserEnabled -o tsv
```

Admin user uzunömürlü registry parolu deməkdir. Biz OIDC ilə qısaömürlü
token istifadə edirik — admin user açıq olarsa, bütün keyless dizayn
mənasızlaşır.

---

## 2. Entra ID tətbiqi və federated credential

```bash
# Tətbiq + service principal
APP_ID=$(az ad app create --display-name "$APP_NAME" --query appId -o tsv)
az ad sp create --id "$APP_ID"
OBJECT_ID=$(az ad app show --id "$APP_ID" --query id -o tsv)

echo "AZURE_CLIENT_ID = $APP_ID"
```

### Federated credential-lar

Hər trigger konteksti üçün **ayrıca** credential lazımdır. Subject filtri
dar olmalıdır — bu, kimin token ala biləcəyini müəyyən edir.

```bash
# 1) main branch-ə push (build + promote)
az ad app federated-credential create --id "$OBJECT_ID" --parameters "{
  \"name\": \"gh-main\",
  \"issuer\": \"https://token.actions.githubusercontent.com\",
  \"subject\": \"repo:${GITHUB_ORG}/${GITHUB_REPO}:ref:refs/heads/main\",
  \"audiences\": [\"api://AzureADTokenExchange\"]
}"

# 2) production environment (promote job-u `environment: production` istifadə edir)
az ad app federated-credential create --id "$OBJECT_ID" --parameters "{
  \"name\": \"gh-env-production\",
  \"issuer\": \"https://token.actions.githubusercontent.com\",
  \"subject\": \"repo:${GITHUB_ORG}/${GITHUB_REPO}:environment:production\",
  \"audiences\": [\"api://AzureADTokenExchange\"]
}"

# 3) pull request (yalnız quarantine-ə build/scan üçün)
az ad app federated-credential create --id "$OBJECT_ID" --parameters "{
  \"name\": \"gh-pull-request\",
  \"issuer\": \"https://token.actions.githubusercontent.com\",
  \"subject\": \"repo:${GITHUB_ORG}/${GITHUB_REPO}:pull_request\",
  \"audiences\": [\"api://AzureADTokenExchange\"]
}"
```

> **Fork PR qeydi:** `pull_request` subject-i **yalnız eyni repository-dən**
> gələn PR-lara verilir. Fork-dan gələn PR OIDC token ala bilmir — bu, GitHub-un
> təhlükəsizlik modelidir və doğrudur. Nəticədə fork PR-larda build job-u
> uğursuz olur, Phase 2 gate-ləri isə normal işləyir.

> **`repo:...:*` istifadə ETMƏYİN.** Wildcard subject istənilən branch-dən
> token almağa imkan verir — yəni hər hansı developer branch push edərək
> ACR-ə yaza bilər.

---

## 3. RBAC — least privilege

```bash
ACR_ID=$(az acr show --name "$ACR_NAME" --query id -o tsv)
SP_ID=$(az ad sp show --id "$APP_ID" --query id -o tsv)

# Push + pull (build və promote üçün)
az role assignment create \
  --assignee-object-id "$SP_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "AcrPush" \
  --scope "$ACR_ID"
```

`AcrPush` daxilində `AcrPull` da var, yəni Trivy skan üçün ayrıca rol lazım deyil.

### Manifest kilidləmə üçün əlavə icazə

`az acr repository update --write-enabled false` **data-plane** əməliyyatıdır,
lakin ACR-in `changeableAttributes` dəyişdirilməsi `Microsoft.ContainerRegistry/registries/*/write`
tələb edir. `AcrPush` bunu **əhatə etmir**. Ən dar həll — custom rol:

```bash
cat > /tmp/acr-image-lock-role.json <<EOF
{
  "Name": "ACR Image Lock Manager",
  "Description": "Yalniz manifest/tag atributlarini deyisdirmeye icaze verir",
  "Actions": [
    "Microsoft.ContainerRegistry/registries/read",
    "Microsoft.ContainerRegistry/registries/metadata/read",
    "Microsoft.ContainerRegistry/registries/metadata/write"
  ],
  "AssignableScopes": ["$ACR_ID"]
}
EOF

az role definition create --role-definition /tmp/acr-image-lock-role.json

az role assignment create \
  --assignee-object-id "$SP_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "ACR Image Lock Manager" \
  --scope "$ACR_ID"
```

> Alternativ (daha sadə, lakin daha geniş): `Contributor` rolunu ACR scope-unda
> vermək. **Capstone üçün custom rol tövsiyə olunur** — least privilege
> prinsipini nümayiş etdirir və threat model T4-ə (over-privileged identity)
> birbaşa cavab verir.

### Doğrulama

```bash
az role assignment list --assignee "$APP_ID" --scope "$ACR_ID" -o table
```

---

## 4. GitHub Secrets

Repository → Settings → Secrets and variables → Actions:

| Secret | Haradan alınır |
|---|---|
| `AZURE_CLIENT_ID` | `echo $APP_ID` |
| `AZURE_TENANT_ID` | `az account show --query tenantId -o tsv` |
| `AZURE_SUBSCRIPTION_ID` | `echo $SUBSCRIPTION_ID` |
| `ACR_NAME` | `echo $ACR_NAME` (login server-siz, yalnız ad) |

Phase 2-dən qalan: `DD_URL`, `DD_API_KEY`, `DD_ENGAGEMENT_ID`.

> Bu dördü texniki mənada "secret" deyil (identifikatordur, parol deyil), lakin
> Secrets-də saxlanılır ki, abunəlik strukturu log-larda görünməsin.

---

## 5. GitHub Environment: `production`

Settings → Environments → **New environment** → `production`

Aktivləşdirin:
- **Required reviewers** — promote addımı üçün insan təsdiqi
- **Deployment branches** → `main` (yalnız)

`promote-to-release` job-u `environment: production` istifadə edir, yəni
release repository-yə keçid **insan təsdiqi tələb edir**. Bu, avtomatik
pipeline-ın son qərar nöqtəsində insan nəzarətini saxlayır.

---

## 6. Yoxlama

```bash
# ACR əlçatandır?
az acr show --name "$ACR_NAME" --query "{name:name, sku:sku.name, adminEnabled:adminUserEnabled}" -o table

# Federated credential-lar
az ad app federated-credential list --id "$OBJECT_ID" -o table

# Rol təyinatları
az role assignment list --assignee "$APP_ID" --all -o table
```

---

## Təmizləmə (capstone bitdikdən sonra)

```bash
az group delete --name "$RESOURCE_GROUP" --yes --no-wait
az ad app delete --id "$APP_ID"
az role definition delete --name "ACR Image Lock Manager"
```
