.PHONY: help audit opa-check plan-dev plan-prod rotate

ENV    ?= dev
SECRET ?= ""

help:
	@echo "Targets:"
	@echo "  audit          Scan for hardcoded credentials"
	@echo "  opa-check      Run OPA zero-creds policy on all K8s manifests"
	@echo "  opa-test       Run OPA unit tests"
	@echo "  plan-dev       Terraform plan for dev"
	@echo "  plan-prod      Terraform plan for prod"
	@echo "  rotate         Trigger rotation (SECRET=secret-name)"

audit:
	./scripts/audit-creds.sh

opa-check:
	./scripts/opa-check.sh

opa-test:
	opa test opa/policies/ opa/tests/ -v

plan-dev:
	cd terraform/environments/dev && terraform init -backend-config=backend.hcl && terraform plan

plan-prod:
	cd terraform/environments/prod && terraform init -backend-config=backend.hcl && terraform plan

rotate:
	./scripts/rotate-now.sh $(SECRET)
