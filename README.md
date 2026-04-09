# 🔐 aws-secrets-hardening

> Production-grade AWS Secrets Manager patterns for containerized workloads.
> IAM least-privilege, automatic rotation, OPA zero-credentials enforcement, and External Secrets Operator integration.

![AWS](https://img.shields.io/badge/AWS-Secrets_Manager-FF9900?logo=amazonaws)
![Terraform](https://img.shields.io/badge/Terraform-1.7+-623CE4?logo=terraform)
![OPA](https://img.shields.io/badge/OPA-Zero--Creds-7D3C98?logo=openpolicyagent)
![Kubernetes](https://img.shields.io/badge/Kubernetes-External_Secrets-326CE5?logo=kubernetes)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Zero-Credentials Architecture                     │
│                                                                     │
│  Pod (no env creds)                                                 │
│    │                                                                │
│    │  IRSA (IAM Role for Service Account)                          │
│    ▼                                                                │
│  AWS STS ──► Temporary credentials (15min TTL)                     │
│    │                                                                │
│    ▼                                                                │
│  Secrets Manager ──► Secret value                                   │
│    │                                                                │
│    ▼ (via External Secrets Operator)                               │
│  Kubernetes Secret ──► Pod env / volume mount                      │
│                                                                     │
│  OPA Gatekeeper enforces: no hardcoded creds in any manifest       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## ✨ What's Included

| Component | Details |
|-----------|---------|
| **Terraform modules** | Secrets Manager, IRSA, rotation IAM roles — multi-env |
| **Auto-rotation** | Lambda-based RDS + API key rotation, configurable schedules |
| **IAM least-privilege** | Per-secret, per-service scoped policies with conditions |
| **External Secrets Operator** | ClusterSecretStore, ExternalSecret CRs for all patterns |
| **OPA policies** | Zero-creds enforcement — reject any manifest with hardcoded secrets |
| **Pod security** | SecurityContext, read-only root FS, no env-var credentials |
| **Network policies** | Restrict secrets traffic to metadata endpoint only |
| **CI/CD** | GitHub Actions: OPA check, Terraform plan, secret audit |

---

## 📁 Repository Structure

```
aws-secrets-hardening/
├── terraform/
│   ├── modules/
│   │   ├── secrets-manager/    # Secret creation, KMS, resource policy
│   │   ├── irsa-secrets/       # IRSA role scoped to specific secrets
│   │   └── iam-rotation-role/  # Lambda rotation execution role
│   └── environments/
│       ├── dev/
│       ├── staging/
│       └── prod/
├── kubernetes/
│   ├── external-secrets/       # ClusterSecretStore + ExternalSecret CRs
│   ├── pod-security/           # SecurityContext policies
│   └── network-policy/         # Restrict metadata endpoint access
├── rotation/
│   ├── lambdas/
│   │   ├── rds-rotation/       # RDS password rotation Lambda
│   │   └── api-key-rotation/   # Generic API key rotation Lambda
│   └── schedules/              # Rotation schedule configs
├── opa/
│   ├── policies/               # Rego policies: zero-creds enforcement
│   └── tests/                  # Rego unit tests
├── iam/
│   ├── policies/               # Least-privilege JSON policies
│   └── roles/                  # Role trust policies
├── scripts/                    # Audit, rotate, bootstrap scripts
└── docs/                       # Architecture decisions & runbooks
```

---

## 🚀 Quick Start

```bash
# 1. Bootstrap Terraform (remote state first)
cd terraform/environments/dev
terraform init -backend-config=backend.hcl
terraform apply -var-file=terraform.tfvars

# 2. Install External Secrets Operator
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace

# 3. Apply ClusterSecretStore + ExternalSecrets
kubectl apply -f kubernetes/external-secrets/

# 4. Run OPA policy checks
./scripts/opa-check.sh

# 5. Audit for any hardcoded credentials
./scripts/audit-creds.sh
```

---

## 🔒 OPA Zero-Credentials Policy

Every Kubernetes resource is checked for:
- Hardcoded AWS keys (`AKIA*` pattern)
- Hardcoded passwords in env vars
- Secrets mounted as environment variables (must use secretRef with ESO)
- Missing securityContext restrictions

```bash
# Run all OPA checks locally
opa test opa/policies/ opa/tests/ -v

# Check a specific manifest
opa eval --input my-deployment.yaml \
  --data opa/policies/zero-creds.rego \
  "data.kubernetes.security.deny"
```

---

## 📄 License  MIT
