# OPA Policy: Zero-Credentials Enforcement
# Rejects any Kubernetes manifest that contains hardcoded credentials,
# AWS access keys, or secrets mounted as environment variables.
#
# Usage:
#   opa eval --input manifest.yaml --data zero-creds.rego "data.kubernetes.security.deny"

package kubernetes.security

import future.keywords.contains
import future.keywords.if
import future.keywords.in

################################################################################
# Deny rules — any match causes rejection
################################################################################

# ── 1. No hardcoded AWS Access Key IDs ────────────────────────────────────────
deny contains msg if {
  container := input.spec.template.spec.containers[_]
  env       := container.env[_]
  regex.match(`AKIA[0-9A-Z]{16}`, env.value)
  msg := sprintf(
    "VIOLATION [zero-creds]: Container '%v' has a hardcoded AWS Access Key ID in env var '%v'. Use IRSA instead.",
    [container.name, env.name]
  )
}

# ── 2. No hardcoded AWS Secret Access Keys ────────────────────────────────────
deny contains msg if {
  container := input.spec.template.spec.containers[_]
  env       := container.env[_]
  regex.match(`(?i)(aws.?secret.?access.?key|aws.?secret.?key)`, env.name)
  msg := sprintf(
    "VIOLATION [zero-creds]: Container '%v' env var '%v' looks like an AWS secret key. Use IRSA instead.",
    [container.name, env.name]
  )
}

# ── 3. No plaintext passwords in env vars ─────────────────────────────────────
deny contains msg if {
  container := input.spec.template.spec.containers[_]
  env       := container.env[_]
  regex.match(`(?i)(password|passwd|secret|token|api.?key|private.?key)`, env.name)
  not env.valueFrom    # Has a value directly (not from secretRef/configMapRef)
  env.value != null
  env.value != ""
  msg := sprintf(
    "VIOLATION [zero-creds]: Container '%v' has a sensitive env var '%v' with a literal value. Use ExternalSecret + volume mount.",
    [container.name, env.name]
  )
}

# ── 4. No secretRef in envFrom (secrets as env vars) ─────────────────────────
deny contains msg if {
  container := input.spec.template.spec.containers[_]
  envFrom   := container.envFrom[_]
  envFrom.secretRef
  msg := sprintf(
    "VIOLATION [zero-creds]: Container '%v' uses secretRef in envFrom. Secrets must be mounted as volumes, not injected as environment variables.",
    [container.name]
  )
}

# ── 5. No secret valueFrom in individual env vars ────────────────────────────
deny contains msg if {
  container := input.spec.template.spec.containers[_]
  env       := container.env[_]
  regex.match(`(?i)(password|passwd|secret|token|api.?key|private.?key)`, env.name)
  env.valueFrom.secretKeyRef    # Using secretKeyRef for sensitive vars
  msg := sprintf(
    "VIOLATION [zero-creds]: Container '%v' env var '%v' uses secretKeyRef. Mount the secret as a volume at /run/secrets/ instead.",
    [container.name, env.name]
  )
}

# ── 6. Secrets must be mounted read-only ──────────────────────────────────────
deny contains msg if {
  container := input.spec.template.spec.containers[_]
  volumeMount := container.volumeMounts[_]
  volume      := input.spec.template.spec.volumes[_]
  volume.name == volumeMount.name
  volume.secret
  volumeMount.readOnly != true
  msg := sprintf(
    "VIOLATION [zero-creds]: Container '%v' mounts secret volume '%v' without readOnly: true.",
    [container.name, volumeMount.name]
  )
}

# ── 7. Secret volumes must use restrictive file permissions ───────────────────
deny contains msg if {
  volume := input.spec.template.spec.volumes[_]
  volume.secret
  volume.secret.defaultMode > 256    # 0400 octal = 256 decimal
  msg := sprintf(
    "VIOLATION [zero-creds]: Secret volume '%v' has defaultMode %v (must be 0400 or less).",
    [volume.name, volume.secret.defaultMode]
  )
}

# ── 8. No privileged containers (could steal node credentials) ────────────────
deny contains msg if {
  container := input.spec.template.spec.containers[_]
  container.securityContext.privileged == true
  msg := sprintf(
    "VIOLATION [zero-creds]: Container '%v' is privileged. Privileged containers can access node-level credentials.",
    [container.name]
  )
}

# ── 9. Must run as non-root ───────────────────────────────────────────────────
deny contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot
  not input.spec.template.spec.securityContext.runAsUser
  msg := "VIOLATION [zero-creds]: Pod securityContext must set runAsNonRoot: true or a non-zero runAsUser."
}

# ── 10. No hostPID / hostIPC (privilege escalation paths) ────────────────────
deny contains msg if {
  input.spec.template.spec.hostPID == true
  msg := "VIOLATION [zero-creds]: hostPID: true allows reading credentials from other processes on the node."
}

deny contains msg if {
  input.spec.template.spec.hostIPC == true
  msg := "VIOLATION [zero-creds]: hostIPC: true is a security risk."
}

################################################################################
# Warn rules — flags for review, does not block
################################################################################

warn contains msg if {
  input.kind == "Deployment"
  namespace := input.metadata.namespace
  not regex.match(`^(backend|payments|auth|notifications|analytics)$`, namespace)
  count(input.spec.template.spec.volumes) > 0
  msg := sprintf(
    "WARNING [zero-creds]: Deployment in namespace '%v' uses volumes. Ensure no sensitive data is exposed.",
    [namespace]
  )
}
