# OPA Policy: IAM Least-Privilege for Terraform Plans
# Checks Terraform plan JSON for IAM policy violations
package terraform.iam

import future.keywords.contains
import future.keywords.if
import future.keywords.in

################################################################################
# Deny rules for Terraform plans
################################################################################

# ── 1. No wildcard actions in IAM policies ────────────────────────────────────
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type in ["aws_iam_role_policy", "aws_iam_policy"]
  policy   := json.unmarshal(resource.change.after.policy)
  stmt     := policy.Statement[_]
  stmt.Effect == "Allow"
  stmt.Action == "*"
  msg := sprintf(
    "IAM VIOLATION: Resource '%v' allows Action '*'. Specify exact actions needed.",
    [resource.address]
  )
}

# ── 2. No wildcard Resource in sensitive action statements ────────────────────
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type in ["aws_iam_role_policy", "aws_iam_policy"]
  policy   := json.unmarshal(resource.change.after.policy)
  stmt     := policy.Statement[_]
  stmt.Effect == "Allow"
  stmt.Resource == "*"
  sensitive_actions := {"secretsmanager:*", "kms:*", "iam:*", "sts:AssumeRole"}
  some action in stmt.Action
  action in sensitive_actions
  msg := sprintf(
    "IAM VIOLATION: Resource '%v' allows '%v' on Resource '*'. Restrict to specific ARNs.",
    [resource.address, action]
  )
}

# ── 3. No iam:* permissions ───────────────────────────────────────────────────
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type in ["aws_iam_role_policy", "aws_iam_policy"]
  policy   := json.unmarshal(resource.change.after.policy)
  stmt     := policy.Statement[_]
  stmt.Effect == "Allow"
  "iam:*" in stmt.Action
  msg := sprintf(
    "IAM VIOLATION: Resource '%v' grants iam:*. This is overly permissive.",
    [resource.address]
  )
}

# ── 4. SecretManager access must have Condition on SecureTransport ────────────
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type in ["aws_iam_role_policy", "aws_iam_policy", "aws_secretsmanager_secret_policy"]
  policy   := json.unmarshal(resource.change.after.policy)
  stmt     := policy.Statement[_]
  stmt.Effect == "Allow"
  some action in stmt.Action
  startswith(action, "secretsmanager:")
  not stmt.Condition
  msg := sprintf(
    "IAM VIOLATION: Resource '%v' allows secretsmanager actions without Condition. Add aws:SecureTransport condition.",
    [resource.address]
  )
}

# ── 5. KMS Decrypt must be scoped via kms:ViaService ─────────────────────────
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type in ["aws_iam_role_policy", "aws_iam_policy"]
  policy   := json.unmarshal(resource.change.after.policy)
  stmt     := policy.Statement[_]
  stmt.Effect == "Allow"
  "kms:Decrypt" in stmt.Action
  not stmt.Condition["StringEquals"]["kms:ViaService"]
  msg := sprintf(
    "IAM VIOLATION: Resource '%v' allows kms:Decrypt without kms:ViaService condition. Restrict to specific service.",
    [resource.address]
  )
}

# ── 6. Rotation Lambda role must not have GetSecretValue on * ─────────────────
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_role_policy"
  contains(resource.change.after.name, "rotation")
  policy   := json.unmarshal(resource.change.after.policy)
  stmt     := policy.Statement[_]
  stmt.Effect == "Allow"
  "secretsmanager:GetSecretValue" in stmt.Action
  stmt.Resource == "*"
  msg := sprintf(
    "IAM VIOLATION: Rotation role '%v' allows GetSecretValue on '*'. Scope to specific secret ARNs.",
    [resource.address]
  )
}
