output "secret_arns"         { value = module.app_secrets.secret_arns }
output "kms_key_arn"         { value = module.app_secrets.kms_key_arn }
output "backend_role_arn"    { value = module.backend_irsa.role_arn }
output "payment_role_arn"    { value = module.payment_irsa.role_arn }
output "auth_role_arn"       { value = module.auth_irsa.role_arn }
output "rotation_role_arn"   { value = module.rotation_role.role_arn }
