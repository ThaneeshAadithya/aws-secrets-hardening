# Architecture: Zero-Credentials Secrets Pattern

## Principle

No container ever holds a static AWS credential.
All access to secrets is mediated by short-lived tokens via IRSA.

## Flow

```
1. Pod starts with IRSA-annotated ServiceAccount
2. EKS projects a web identity token into the pod (/var/run/secrets/eks.amazonaws.com/serviceaccount/token)
3. Pod SDK calls sts:AssumeRoleWithWebIdentity with the token
4. STS issues 15-minute temporary credentials
5. Pod calls secretsmanager:GetSecretValue with temporary credentials
6. Secrets Manager returns the secret value
7. External Secrets Operator re-syncs hourly from Secrets Manager → K8s Secret
8. Pod reads secret from mounted volume at /run/secrets/
```

## Why Volume Mounts, Not Env Vars

| Env Var Injection | Volume Mount |
|-------------------|--------------|
| Visible in `kubectl describe pod` | Not visible in pod description |
| Included in crash dumps | Not in crash dumps |
| Passed to child processes | Not automatically inherited |
| Cannot be updated without restart | Can be updated by ESO without restart |
| Captured by debug tools | Requires explicit file read |

## IAM Scope

Each service has its own IAM role, scoped to ONLY the secrets it needs:

```
backend-api-sa → backend-api-secrets-role → prod/myapp/database/primary ONLY
payment-sa     → payment-secrets-role     → prod/myapp/api/stripe-key ONLY
auth-sa        → auth-secrets-role        → prod/myapp/jwt/signing-key ONLY
```

No role can access another service's secrets.

## Rotation

Rotation uses a 4-step Lambda process:
1. **createSecret** — generate new credential
2. **setSecret** — apply to the backend (e.g., change DB password)
3. **testSecret** — verify new credential works
4. **finishSecret** — promote AWSPENDING to AWSCURRENT

If any step fails, rotation rolls back and the old credential remains valid.
