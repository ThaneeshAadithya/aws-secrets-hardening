################################################################################
# Dev Secrets Environment — shorter recovery window, no rotation
################################################################################
terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws        = { source = "hashicorp/aws";       version = ">= 5.0" }
    kubernetes = { source = "hashicorp/kubernetes"; version = ">= 2.0" }
  }
  backend "s3" {}
}

provider "aws" { region = "us-east-1"; default_tags { tags = local.tags } }
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
  env          = "dev"
  region       = "us-east-1"
  cluster_name = "eks-dev"
  tags = { Environment = local.env; ManagedBy = "terraform"; Owner = "platform-team" }
}

module "app_secrets" {
  source = "../../modules/secrets-manager"

  environment        = local.env
  secret_path_prefix = "myapp"
  aws_org_id         = var.aws_org_id
  create_kms_key     = true

  secrets = {
    "database/primary" = {
      description   = "Dev RDS credentials"
      service       = "backend-api"
      enable_rotation = false
      allowed_role_arns = [module.backend_irsa.role_arn]
    }
    "api/stripe-key" = {
      description   = "Dev Stripe test key"
      service       = "payment-service"
      enable_rotation = false
      allowed_role_arns = [module.payment_irsa.role_arn]
    }
  }
  tags = local.tags
}

module "backend_irsa" {
  source = "../../modules/irsa-secrets"
  environment = local.env; service_name = "backend-api"; namespace = "backend"
  service_account_name = "backend-api-sa"
  oidc_provider_arn = var.oidc_provider_arn; oidc_provider_url = var.oidc_provider_url
  secret_arns = [module.app_secrets.secret_arns["database/primary"]]
  kms_key_arns = [module.app_secrets.kms_key_arn]
  tags = local.tags
}

module "payment_irsa" {
  source = "../../modules/irsa-secrets"
  environment = local.env; service_name = "payment-service"; namespace = "payments"
  service_account_name = "payment-sa"
  oidc_provider_arn = var.oidc_provider_arn; oidc_provider_url = var.oidc_provider_url
  secret_arns = [module.app_secrets.secret_arns["api/stripe-key"]]
  kms_key_arns = [module.app_secrets.kms_key_arn]
  tags = local.tags
}

variable "aws_org_id"        { type = string }
variable "oidc_provider_arn" { type = string }
variable "oidc_provider_url" { type = string }
