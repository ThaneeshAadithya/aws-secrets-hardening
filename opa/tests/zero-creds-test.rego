# Unit tests for zero-creds OPA policy
package kubernetes.security_test

import data.kubernetes.security.deny
import data.kubernetes.security.warn

# ── Test: Should DENY deployment with AWS key in env ──────────────────────────
test_deny_hardcoded_aws_key if {
  result := deny with input as {
    "kind": "Deployment",
    "metadata": {"name": "bad-app", "namespace": "backend"},
    "spec": {
      "template": {
        "spec": {
          "securityContext": {"runAsNonRoot": true},
          "containers": [{
            "name": "app",
            "env": [{
              "name": "AWS_ACCESS_KEY_ID",
              "value": "AKIAIOSFODNN7EXAMPLE"
            }]
          }]
        }
      }
    }
  }
  count(result) > 0
}

# ── Test: Should DENY secretRef in envFrom ────────────────────────────────────
test_deny_secret_ref_in_envfrom if {
  result := deny with input as {
    "kind": "Deployment",
    "metadata": {"name": "bad-app", "namespace": "backend"},
    "spec": {
      "template": {
        "spec": {
          "securityContext": {"runAsNonRoot": true},
          "containers": [{
            "name": "app",
            "envFrom": [{"secretRef": {"name": "my-secret"}}]
          }]
        }
      }
    }
  }
  count(result) > 0
}

# ── Test: Should DENY privileged container ────────────────────────────────────
test_deny_privileged_container if {
  result := deny with input as {
    "kind": "Deployment",
    "metadata": {"name": "bad-app", "namespace": "backend"},
    "spec": {
      "template": {
        "spec": {
          "securityContext": {"runAsNonRoot": true},
          "containers": [{
            "name": "app",
            "securityContext": {"privileged": true},
            "env": []
          }]
        }
      }
    }
  }
  count(result) > 0
}

# ── Test: Should ALLOW compliant deployment ───────────────────────────────────
test_allow_compliant_deployment if {
  result := deny with input as {
    "kind": "Deployment",
    "metadata": {"name": "good-app", "namespace": "backend"},
    "spec": {
      "template": {
        "spec": {
          "securityContext": {"runAsNonRoot": true, "runAsUser": 1000},
          "containers": [{
            "name": "app",
            "securityContext": {"privileged": false, "allowPrivilegeEscalation": false},
            "env": [
              {"name": "PORT", "value": "8080"},
              {"name": "LOG_LEVEL", "value": "info"}
            ],
            "volumeMounts": [{
              "name": "db-credentials",
              "mountPath": "/run/secrets/db",
              "readOnly": true
            }]
          }],
          "volumes": [{
            "name": "db-credentials",
            "secret": {
              "secretName": "backend-db-credentials",
              "defaultMode": 256
            }
          }]
        }
      }
    }
  }
  count(result) == 0
}

# ── Test: Should DENY secret volume without readOnly ─────────────────────────
test_deny_secret_volume_not_readonly if {
  result := deny with input as {
    "kind": "Deployment",
    "metadata": {"name": "bad-app", "namespace": "backend"},
    "spec": {
      "template": {
        "spec": {
          "securityContext": {"runAsNonRoot": true},
          "containers": [{
            "name": "app",
            "env": [],
            "volumeMounts": [{
              "name": "secret-vol",
              "mountPath": "/run/secrets/db",
              "readOnly": false
            }]
          }],
          "volumes": [{
            "name": "secret-vol",
            "secret": {"secretName": "my-secret", "defaultMode": 256}
          }]
        }
      }
    }
  }
  count(result) > 0
}
