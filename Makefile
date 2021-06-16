SHELL:=bash

aws_profile=default
aws_region=eu-west-2
aws_mgmt_dev_account=

default: help

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: bootstrap
bootstrap: ## Bootstrap local environment for first use
	@make git-hooks
	pip3 install --user Jinja2 PyYAML boto3
	@{ \
		export AWS_PROFILE=$(aws_profile); \
		export AWS_REGION=$(aws_region); \
		python3 bootstrap_terraform.py; \
	}
	terraform fmt -recursive

.PHONY: git-hooks
git-hooks: ## Set up hooks in .githooks
	@git submodule update --init .githooks ; \
	git config core.hooksPath .githooks \


.PHONY: terraform-init
terraform-init: ## Run `terraform init` from repo root
	terraform init

.PHONY: terraform-plan
terraform-plan: ## Run `terraform plan` from repo root
	terraform plan

.PHONY: terraform-apply
terraform-apply: ## Run `terraform apply` from repo root
	terraform apply

.PHONY: terraform-workspace-new
terraform-workspace-new: ## Creates new Terraform workspace with Concourse remote execution. Run `terraform-workspace-new workspace=<workspace_name>`
	fly -t aws-concourse execute --config create-workspace.yml --input repo=. -v workspace="$(workspace)"

certificates:
	./generate-certificates.sh

localstack:
	docker-compose up -d localstack
	@{ \
		while ! docker logs localstack 2> /dev/null | grep -q "^Ready\." ; do \
			echo Waiting for localstack.; \
			sleep 2; \
		done; \
	}
	docker-compose up localstack-init

dks:
	docker-compose up -d dks

services: localstack dks

dataworks-data-egress: services
	docker-compose up -d dataworks-data-egress

integration-tests: dataworks-data-egress
	docker-compose up dataworks-data-egress-integration-tests

ecr:
	aws ecr get-login-password --region $(aws_region) --profile dataworks-management-dev | docker login --username AWS --password-stdin $(aws_mgmt_dev_account).dkr.ecr.$(aws_region).amazonaws.com
	docker tag dataworks-data-egress $(aws_mgmt_dev_account).dkr.ecr.$(aws_region).amazonaws.com/dataworks-data-egress:development
	docker push $(aws_mgmt_dev_account).dkr.ecr.$(aws_region).amazonaws.com/dataworks-data-egress:development
