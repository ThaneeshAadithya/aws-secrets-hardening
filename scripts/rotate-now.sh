#!/usr/bin/env bash
# rotate-now.sh — Trigger immediate rotation for a secret
set -euo pipefail

SECRET_NAME="${1:?Usage: $0 <secret-name-or-arn>}"
REGION="${2:-us-east-1}"

echo "==> Triggering rotation for: ${SECRET_NAME}"

# Check rotation is configured
INFO=$(aws secretsmanager describe-secret --secret-id "${SECRET_NAME}" --region "${REGION}")
ROTATION_ENABLED=$(echo "${INFO}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('RotationEnabled', False))")

if [[ "${ROTATION_ENABLED}" != "True" ]]; then
  echo "❌ Rotation is not enabled for ${SECRET_NAME}"
  echo "   Enable it first: aws secretsmanager rotate-secret --secret-id ${SECRET_NAME} --rotation-lambda-arn <arn>"
  exit 1
fi

aws secretsmanager rotate-secret \
  --secret-id "${SECRET_NAME}" \
  --region "${REGION}"

echo "✅ Rotation triggered for ${SECRET_NAME}"
echo "   Monitor in CloudWatch: /aws/lambda/*rotation*"
echo "   Check status: aws secretsmanager describe-secret --secret-id ${SECRET_NAME} --region ${REGION}"
