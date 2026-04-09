################################################################################
# Production Secrets Environment
################################################################################
terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws        = { source = "hashicorp/aws";        version = ">= 5.0" }
    kubernetes = { source = "hashicorp/kubernetes";  version = ">= 2.0" }
  }
  backend "s3" {}
}

provider "aws"        { region = local.region; default_tags { tags = local.tags } }
provider "kubernetes" {
  host                   = data.aws_eks_cluster.this.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", local.cluster_name]
  }
}

data "aws_caller_identity" "current" {}
data "aws_eks_cluster" "this" { name = local.cluster_name }

locals {
  env          = "prod"
  region       = "us-east-1"
  cluster_name = "eks-prod"
  prefix       = "myapp-${local.env}"
  tags = {
    Environment = local.env
    ManagedBy   = "terraform"
    Owner       = "platform-team"
    CostCenter  = "engineering"
  }
}

################################################################################
# IAM Rotation Role (shared across all secrets in this env)
################################################################################

module "rotation_role" {
  source = "../../modules/iam-rotation-role"

  environment        = local.env
  secret_path_prefix = "myapp"
  secret_arns        = ["arn:aws:secretsmanager:${local.region}:${data.aws_caller_identity.current.account_id}:secret:${local.env}/myapp/*"]
  kms_key_arns       = [module.app_secrets.kms_key_arn]
  vpc_enabled        = true
  tags               = local.tags
}

################################################################################
# Application Secrets
################################################################################

module "app_secrets" {
  source = "../../modules/secrets-manager"

  environment        = local.env
  secret_path_prefix = "myapp"
  aws_org_id         = var.aws_org_id
  create_kms_key     = true

  rotation_lambda_arn      = var.rotation_lambda_arn
  rotation_lambda_role_arn = module.rotation_role.role_arn

  secrets = {
    "database/primary" = {
      description       = "Primary RDS PostgreSQL credentials"
      service           = "backend-api"
      enable_rotation   = true
      rotation_days     = 30
      rotation_schedule = "rate(30 days)"
      allowed_role_arns = [module.backend_irsa.role_arn]
    }
    "database/readonly" = {
      description       = "Read-only RDS credentials for analytics"
      service           = "analytics"
      enable_rotation   = true
      rotation_days     = 30
      allowed_role_arns = [module.analytics_irsa.role_arn]
    }
    "api/stripe-key" = {
      description       = "Stripe API secret key"
      service           = "payment-service"
      enable_rotation   = false
      allowed_role_arns = [module.payment_irsa.role_arn]
    }
    "api/sendgrid-key" = {
      description       = "SendGrid API key for transactional email"
      service           = "notification-service"
      enable_rotation   = false
      allowed_role_arns = [module.notification_irsa.role_arn]
    }
    "jwt/signing-key" = {
      description       = "JWT signing secret — rotate every 90 days"
      service           = "auth-service"
      enable_rotation   = true
      rotation_days     = 90
      allowed_role_arns = [module.auth_irsa.role_arn]
    }
  }

  tags = local.tags
}

################################################################################
# IRSA Roles — one per service, scoped to only its secrets
################################################################################

module "backend_irsa" {
  source = "../../modules/irsa-secrets"

  environment          = local.env
  service_name         = "backend-api"
  namespace            = "backend"
  service_account_name = "backend-api-sa"
  oidc_provider_arn    = var.oidc_provider_arn
  oidc_provider_url    = var.oidc_provider_url
  secret_arns          = [module.app_secrets.secret_arns["database/primary"]]
  kms_key_arns         = [module.app_secrets.kms_key_arn]
  token_expiration_seconds = 3600
  tags                 = local.tags
}

module "analytics_irsa" {
  source = "../../modules/irsa-secrets"

  environment          = local.env
  service_name         = "analytics"
  namespace            = "analytics"
  service_account_name = "analytics-sa"
  oidc_provider_arn    = var.oidc_provider_arn
  oidc_provider_url    = var.oidc_provider_url
  secret_arns          = [module.app_secrets.secret_arns["database/readonly"]]
  kms_key_arns         = [module.app_secrets.kms_key_arn]
  tags                 = local.tags
}

module "payment_irsa" {
  source = "../../modules/irsa-secrets"

  environment          = local.env
  service_name         = "payment-service"
  namespace            = "payments"
  service_account_name = "payment-sa"
  oidc_provider_arn    = var.oidc_provider_arn
  oidc_provider_url    = var.oidc_provider_url
  secret_arns          = [module.app_secrets.secret_arns["api/stripe-key"]]
  kms_key_arns         = [module.app_secrets.kms_key_arn]
  tags                 = local.tags
}

module "notification_irsa" {
  source = "../../modules/irsa-secrets"

  environment          = local.env
  service_name         = "notification-service"
  namespace            = "notifications"
  service_account_name = "notification-sa"
  oidc_provider_arn    = var.oidc_provider_arn
  oidc_provider_url    = var.oidc_provider_url
  secret_arns          = [module.app_secrets.secret_arns["api/sendgrid-key"]]
  kms_key_arns         = [module.app_secrets.kms_key_arn]
  tags                 = local.tags
}

module "auth_irsa" {
  source = "../../modules/irsa-secrets"

  environment          = local.env
  service_name         = "auth-service"
  namespace            = "auth"
  service_account_name = "auth-sa"
  oidc_provider_arn    = var.oidc_provider_arn
  oidc_provider_url    = var.oidc_provider_url
  secret_arns          = [module.app_secrets.secret_arns["jwt/signing-key"]]
  kms_key_arns         = [module.app_secrets.kms_key_arn]
  tags                 = local.tags
}

variable "aws_org_id"           { type = string }
variable "oidc_provider_arn"    { type = string }
variable "oidc_provider_url"    { type = string }
variable "rotation_lambda_arn"  { type = string; default = "" }
