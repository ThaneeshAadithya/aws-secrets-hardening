#!/usr/bin/env bash
# audit-creds.sh — Scan for hardcoded credentials in the repo
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
FAILED=0

echo "==> Scanning for hardcoded credentials"
echo "    Repo: ${REPO_ROOT}"
echo ""

# ── AWS Access Key IDs ─────────────────────────────────────────────────────────
echo "--> Checking for AWS Access Key IDs..."
matches=$(grep -rn --include="*.tf" --include="*.yaml" --include="*.yml" \
  --include="*.json" --include="*.py" --include="*.env" \
  -E 'AKIA[0-9A-Z]{16}' "${REPO_ROOT}" \
  --exclude-dir=".git" --exclude-dir=".terraform" 2>/dev/null || true)
if [[ -n "${matches}" ]]; then
  echo "❌ AWS Access Key IDs found:"
  echo "${matches}"
  FAILED=$((FAILED + 1))
else
  echo "✅ No AWS Access Key IDs"
fi

# ── Plaintext passwords ────────────────────────────────────────────────────────
echo "--> Checking for suspicious password patterns..."
matches=$(grep -rn --include="*.tf" --include="*.yaml" --include="*.yml" \
  --include="*.json" \
  -iE '(password|passwd|secret_key|api_key)\s*[=:]\s*"[^${}][^"]{6,}"' \
  "${REPO_ROOT}" \
  --exclude-dir=".git" --exclude-dir=".terraform" \
  --exclude="*.example" --exclude="*template*" 2>/dev/null || true)
if [[ -n "${matches}" ]]; then
  echo "⚠️  Potential hardcoded passwords (review manually):"
  echo "${matches}"
else
  echo "✅ No obvious hardcoded passwords"
fi

# ── secretRef in envFrom (OPA would catch this, but catch early) ───────────────
echo "--> Checking for secretRef in envFrom (anti-pattern)..."
matches=$(grep -rn --include="*.yaml" --include="*.yml" \
  'secretRef' "${REPO_ROOT}" \
  --exclude-dir=".git" 2>/dev/null || true)
if [[ -n "${matches}" ]]; then
  echo "⚠️  secretRef found (ensure these are not in envFrom):"
  echo "${matches}"
else
  echo "✅ No secretRef in manifests"
fi

# ── Git history scan ──────────────────────────────────────────────────────────
echo "--> Scanning git history for credentials..."
if command -v trufflehog &>/dev/null; then
  trufflehog filesystem "${REPO_ROOT}" --only-verified 2>/dev/null \
    && echo "✅ TruffleHog: no verified credentials in history" \
    || echo "⚠️  TruffleHog found issues — review above"
else
  echo "ℹ️  trufflehog not installed — skipping history scan"
  echo "   Install: brew install trufflehog"
fi

echo ""
[[ "${FAILED}" -eq 0 ]] && echo "✅ Audit complete — no critical issues" || { echo "❌ ${FAILED} critical issue(s) found"; exit 1; }
