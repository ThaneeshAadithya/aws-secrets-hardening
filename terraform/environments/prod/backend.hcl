bucket         = "terraform-state-ACCOUNT_ID-us-east-1"
key            = "aws-secrets-hardening/prod/terraform.tfstate"
region         = "us-east-1"
dynamodb_table = "terraform-state-lock"
encrypt        = true
