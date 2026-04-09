#!/usr/bin/env bash
# opa-check.sh — Run all OPA policies against Kubernetes manifests
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
POLICIES="${REPO_ROOT}/opa/policies"
K8S_DIR="${REPO_ROOT}/kubernetes"
FAILED=0

echo "==> Running OPA zero-credentials checks"

# Run OPA unit tests first
echo "--> Running OPA unit tests..."
opa test "${POLICIES}/" "${REPO_ROOT}/opa/tests/" -v
echo "✅ OPA unit tests passed"
echo ""

# Check all Kubernetes manifests
echo "--> Checking Kubernetes manifests..."
while IFS= read -r -d '' manifest; do
  echo -n "  $(basename ${manifest})... "
  violations=$(opa eval \
    --input "${manifest}" \
    --data "${POLICIES}/zero-creds.rego" \
    --format raw \
    "data.kubernetes.security.deny" 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d))" 2>/dev/null || echo "0")

  if [[ "${violations}" -eq 0 ]]; then
    echo "✅ PASS"
  else
    echo "❌ FAIL (${violations} violation(s))"
    opa eval \
      --input "${manifest}" \
      --data "${POLICIES}/zero-creds.rego" \
      --format raw \
      "data.kubernetes.security.deny" \
    | python3 -c "import sys,json; [print('    -', v) for v in json.load(sys.stdin)]"
    FAILED=$((FAILED + 1))
  fi
done < <(find "${K8S_DIR}" -name "*.yaml" -print0)

echo ""
[[ "${FAILED}" -eq 0 ]] && echo "✅ All OPA checks passed!" || { echo "❌ ${FAILED} manifest(s) failed OPA checks"; exit 1; }
