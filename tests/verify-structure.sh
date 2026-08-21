#!/usr/bin/env bash
# Repository struktur yoxlamasi — Phase 1 + 2 + 3
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
ok=0; miss=0
check() {
  if [ -e "$1" ]; then printf '  \033[32m✅\033[0m %s\n' "$1"; ok=$((ok+1))
  else printf '  \033[31m❌ ÇATIŞMIR:\033[0m %s\n' "$1"; miss=$((miss+1)); fi
}

echo ""
echo "── Phase 1 — Threat Model + App + Dockerfile ──"
for f in docs/threat-model.md \
         app/Dockerfile app/.dockerignore app/.env.example app/.eslintrc.json \
         app/package.json app/package-lock.json app/healthcheck.js \
         app/src/server.js app/src/app.js app/src/logger.js app/src/routes/tasks.js \
         app/test/security.test.js; do check "$f"; done

echo ""
echo "── Phase 2 — GitHub Actions Security Gates ──"
for f in .github/workflows/security.yml .github/dependabot.yml .gitleaksignore \
         ci/severity_gate.py ci/defectdojo_upload.py ci/redact_gitleaks.py \
         ci/policy.yaml ci/requirements.txt ci/scanner-versions.env \
         ci/install-scanners.sh ci/pin-actions.sh \
         security/semgrep/rules/capstone-nodejs.yml security/gitleaks/gitleaks.toml \
         security/trivy/trivy.yaml \
         tests/red/run-red-test.sh tests/red/sast-vulnerable.js.txt tests/red/README.md; do check "$f"; done

echo ""
echo "── Phase 2 Remediation — Secret Lifecycle Gate 1 ──"
for f in .githooks/pre-commit ci/setup-hooks.sh \
         tests/red/run-precommit-test.sh docs/secret-lifecycle.md; do check "$f"; done

echo ""
echo "── Phase 3 — Build + Image Security (ACR) ──"
for f in .github/workflows/build.yml \
         ci/azure-login.sh ci/acr-promote.sh ci/redact_trivy_secrets.py \
         security/hadolint/hadolint.yaml docs/azure-setup.md \
         tests/red/run-image-test.sh tests/red/Dockerfile.red.txt; do check "$f"; done

echo ""
echo "── Phase 4 — Cosign + Supply Chain ──"
for f in ci/cosign-sign.sh ci/cosign-verify.sh ci/acr-lock.sh ci/init-trust-policy.sh \
         security/cosign/trust-policy.env docs/supply-chain.md \
         tests/red/run-supply-chain-test.sh; do check "$f"; done

echo ""
echo "── Phase 5 — AKS + Hardened Deployment ──"
for f in .github/workflows/deploy.yml \
         k8s/bootstrap/namespace.yaml k8s/bootstrap/rbac.yaml \
         k8s/bootstrap/networkpolicy.yaml k8s/bootstrap/service.yaml \
         k8s/app/deployment.yaml k8s/app/pdb.yaml \
         k8s/policy/kyverno-verify-images.yaml \
         ci/aks-login.sh ci/k8s-deploy.sh ci/k8s-evidence.sh \
         ci/render-kyverno-policy.sh docs/kubernetes-hardening.md \
         tests/red/run-k8s-test.sh tests/red/Deployment.red.txt; do check "$f"; done

echo ""
echo "── Evidence toplama ──"
for f in tests/red/make-red-branch.sh docs/evidence-plan.md; do check "$f"; done

echo ""
echo "── Icra icazeleri (+x) ──"
for f in .githooks/pre-commit ci/install-scanners.sh ci/pin-actions.sh \
         ci/setup-hooks.sh ci/azure-login.sh ci/acr-promote.sh \
         tests/red/run-red-test.sh tests/red/run-precommit-test.sh \
         ci/cosign-sign.sh ci/cosign-verify.sh ci/acr-lock.sh ci/init-trust-policy.sh \
         tests/red/run-image-test.sh tests/red/run-supply-chain-test.sh \
         ci/aks-login.sh ci/k8s-deploy.sh ci/k8s-evidence.sh \
         ci/render-kyverno-policy.sh tests/red/run-k8s-test.sh \
         tests/red/make-red-branch.sh tests/verify-structure.sh; do
  if [ -x "$f" ]; then printf '  \033[32m✅\033[0m +x %s\n' "$f"
  else printf '  \033[33m⚠️  +x YOXDUR:\033[0m %s\n' "$f"; fi
done

echo ""
echo "── Ignore edilmelidir (commit OLUNMAMALIDIR) ──"
for d in app/node_modules reports coverage; do
  if [ -e "$d" ] && git check-ignore -q "$d" 2>/dev/null; then
    printf '  \033[32m✅\033[0m %s duzgun ignore olunub\n' "$d"
  elif [ -e "$d" ]; then
    printf '  \033[31m❌\033[0m %s ignore EDILMEYIB — .gitignore-a elave edin\n' "$d"
  fi
done

echo ""
echo "Netice: $ok movcud, $miss catismir"
[ "$miss" -eq 0 ] && echo "🎉 Struktur tamdir (Phase 1-5)." || echo "⚠️  Yuxaridaki fayllari elave edin."
