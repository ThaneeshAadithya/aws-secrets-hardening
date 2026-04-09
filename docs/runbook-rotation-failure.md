# Runbook: Secret Rotation Failure

## Symptoms

- Alertmanager: `SecretsManagerRotationFailed`
- CloudWatch alarm on Lambda errors
- Application `AccessDeniedException` after rotation attempt

## Investigation

```bash
# Check rotation status
aws secretsmanager describe-secret \
  --secret-id prod/myapp/database/primary \
  --query '{LastRotated: LastRotatedDate, RotationEnabled: RotationEnabled, LastChanged: LastChangedDate}'

# Check Lambda logs
aws logs tail /aws/lambda/prod-myapp-rotation --since 1h | grep -i error

# List secret versions
aws secretsmanager list-secret-version-ids \
  --secret-id prod/myapp/database/primary
```

## Recovery Steps

### If AWSPENDING is stuck

```bash
# Force the secret back to AWSCURRENT only
aws secretsmanager update-secret-version-stage \
  --secret-id prod/myapp/database/primary \
  --version-stage AWSPENDING \
  --remove-from-version-id PENDING_VERSION_ID

# Trigger fresh rotation
./scripts/rotate-now.sh prod/myapp/database/primary
```

### If application cannot connect after rotation

```bash
# Force ESO to re-sync
kubectl annotate externalsecret backend-db-credentials \
  -n backend \
  force-sync=$(date +%s) --overwrite

# Check K8s secret was updated
kubectl get secret backend-db-credentials -n backend \
  -o jsonpath='{.metadata.annotations.reconciled-time}'
```

### Emergency: revert to previous password

```bash
# Get the previous version ID
PREV_VERSION=$(aws secretsmanager list-secret-version-ids \
  --secret-id prod/myapp/database/primary \
  --query 'Versions[?contains(VersionStages, `AWSPREVIOUS`)].VersionId' \
  --output text)

# Promote it back to AWSCURRENT
aws secretsmanager update-secret-version-stage \
  --secret-id prod/myapp/database/primary \
  --version-stage AWSCURRENT \
  --move-to-version-id "${PREV_VERSION}" \
  --remove-from-version-id $(aws secretsmanager describe-secret \
    --secret-id prod/myapp/database/primary \
    --query 'VersionIdsToStages' --output json \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(next(v for v,s in d.items() if 'AWSCURRENT' in s))")
```
