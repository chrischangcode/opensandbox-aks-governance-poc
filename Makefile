SHELL := /bin/bash

LOCAL_CONFIG ?= .make.env
LOCAL_CONFIG_PATH := $(abspath $(LOCAL_CONFIG))
REPO_ROOT := $(shell git rev-parse --show-toplevel 2>/dev/null)
ifneq ($(words $(LOCAL_CONFIG)),1)
$(error LOCAL_CONFIG must be a single path without whitespace)
endif
ifneq ($(wildcard $(LOCAL_CONFIG)),)
ifeq ($(shell test -L '$(LOCAL_CONFIG)' && echo yes),yes)
$(error Refusing to include symlinked LOCAL_CONFIG $(LOCAL_CONFIG))
endif
ifeq ($(REPO_ROOT),)
-include $(LOCAL_CONFIG)
else
LOCAL_CONFIG_REL := $(patsubst $(REPO_ROOT)/%,%,$(LOCAL_CONFIG_PATH))
ifeq ($(LOCAL_CONFIG_REL),$(LOCAL_CONFIG_PATH))
-include $(LOCAL_CONFIG)
else ifeq ($(shell git -C '$(REPO_ROOT)' check-ignore -q -- '$(LOCAL_CONFIG_REL)' && echo yes),yes)
-include $(LOCAL_CONFIG)
else
$(error Refusing to include unignored repo local config $(LOCAL_CONFIG_REL); add it to .gitignore or use LOCAL_CONFIG outside the repo)
endif
endif
endif
export OPEN_SANDBOX_API_KEY

# Environment identity values are written to LOCAL_CONFIG by make local-config.
RESOURCE_GROUP ?= rg-opensandbox-kata
SUBSCRIPTION_ID ?=
LOCATION ?= westus3
AKS_NAME ?= osb-kata-aks
ACR_NAME ?=
NODE_VM_SIZE ?= Standard_D4s_v3
SYSTEM_NODE_COUNT ?= 1
KATA_NODEPOOL_NAME ?= katauser
KATA_NODE_COUNT ?= 1
GVISOR_NODEPOOL_NAME ?= gvisorpool
GVISOR_NODE_COUNT ?= 1
FIRECRACKER_NODEPOOL_NAME ?= fcpool
FIRECRACKER_NODE_COUNT ?= 1

# Stable workflow defaults stay in this Makefile unless explicitly overridden.
ASSIGN_ACR_PULL_ROLE ?= true
ACR_ADMIN_USER_ENABLED ?= true
OPEN_SANDBOX_NAMESPACE ?= opensandbox
OPEN_SANDBOX_CONTROLLER_VERSION ?= 0.2.0
OPEN_SANDBOX_CLI_VERSION ?= 0.1.1
KATA_DEPLOY_CHART ?= https://github.com/kata-containers/kata-containers/releases/download/3.31.0/kata-deploy-3.31.0.tgz
ENABLE_SNAPSHOT_REGISTRY_SECRET ?= true
OPEN_SANDBOX_SNAPSHOT_REGISTRY ?= $(ACR_LOGIN_SERVER)/opensandbox-snapshots
OPEN_SANDBOX_SNAPSHOT_REGISTRY_INSECURE ?= false
OPEN_SANDBOX_SNAPSHOT_SECRET ?= opensandbox-snapshot-registry
OPEN_SANDBOX_IMAGE_COMMITTER_IMAGE ?= opensandbox/image-committer:v0.1.0
ENABLE_INGRESS_GATEWAY ?= true
INGRESS_GATEWAY_IMAGE ?= sandbox-registry.cn-zhangjiakou.cr.aliyuncs.com/opensandbox/ingress:v1.0.7
INGRESS_GATEWAY_ROUTE_MODE ?= header
INGRESS_GATEWAY_LOCAL_PORT ?= 8081
INGRESS_GATEWAY_HOST ?= 127.0.0.1:$(INGRESS_GATEWAY_LOCAL_PORT)
INGRESS_GATEWAY_REPLICAS ?= 1
VSCODE_GATEWAY_DOMAIN ?= 127.0.0.1.nip.io
SERVER_IMAGE_NAME ?= opensandbox-kata-server
SERVER_IMAGE_TAG ?= latest
SANDBOX_IMAGE ?= python:3.12-slim
VSCODE_IMAGE_NAME ?= opensandbox-vscode
VSCODE_IMAGE_TAG ?= latest
COPILOT_CLI_IMAGE_NAME ?= opensandbox-copilot-cli
COPILOT_CLI_IMAGE_TAG ?= latest
SERVER_PORT ?= 8080
VSCODE_PORT ?= 8443
COPILOT_CREDENTIAL_HOSTS ?= api.github.com,github.com,api.enterprise.githubcopilot.com
COPILOT_EGRESS_HOSTS ?= api.github.com,github.com,copilot-proxy.githubusercontent.com,api.githubcopilot.com,api.enterprise.githubcopilot.com,copilot-telemetry.githubusercontent.com,telemetry.enterprise.githubcopilot.com
UV ?= uv

SERVER_DEPLOY_DIR := deploy/opensandbox-server
PYTHON_CLIENT_DIR := examples/python-client
CLI_CLIENT_DIR := examples/cli-client
PAUSE_RENEW_EXAMPLE_DIR := examples/pause-renew
PAUSE_RENEW_CLI_EXAMPLE_DIR := examples/pause-renew-cli
VSCODE_EXAMPLE_DIR := examples/vscode
GITHUB_COPILOT_CLI_EXAMPLE_DIR := examples/github-copilot-cli

ACR_LOGIN_SERVER := $(ACR_NAME).azurecr.io
SERVER_IMAGE := $(ACR_LOGIN_SERVER)/$(SERVER_IMAGE_NAME):$(SERVER_IMAGE_TAG)
VSCODE_IMAGE := $(ACR_LOGIN_SERVER)/$(VSCODE_IMAGE_NAME):$(VSCODE_IMAGE_TAG)
COPILOT_CLI_IMAGE := $(ACR_LOGIN_SERVER)/$(COPILOT_CLI_IMAGE_NAME):$(COPILOT_CLI_IMAGE_TAG)
INGRESS_MODE := $(if $(filter true,$(ENABLE_INGRESS_GATEWAY)),gateway,direct)
INGRESS_GATEWAY_ADDRESS_LINE := $(if $(filter true,$(ENABLE_INGRESS_GATEWAY)),gateway.address = "$(INGRESS_GATEWAY_HOST)",)
INGRESS_GATEWAY_ROUTE_MODE_LINE := $(if $(filter true,$(ENABLE_INGRESS_GATEWAY)),gateway.route.mode = "$(INGRESS_GATEWAY_ROUTE_MODE)",)
AZ_SUBSCRIPTION_ARG := $(if $(SUBSCRIPTION_ID),--subscription "$(SUBSCRIPTION_ID)",)
WAIT_FOR_AKS_SUCCEEDED = set -euo pipefail; for i in $$(seq 1 180); do state=$$(az aks show --resource-group "$(RESOURCE_GROUP)" --name "$(AKS_NAME)" $(AZ_SUBSCRIPTION_ARG) --query provisioningState -o tsv 2>/dev/null || true); if [ "$$state" = "Succeeded" ]; then exit 0; fi; if [ -z "$$state" ]; then echo "Waiting for AKS $(AKS_NAME) to be readable"; else echo "Waiting for AKS $(AKS_NAME) provisioningState=$$state"; fi; sleep 10; done; echo "Timed out waiting for AKS $(AKS_NAME) to reach provisioningState=Succeeded"; exit 1

CONFIGURED_TARGETS := all print-config infra-deploy aks-credentials acr-login image-build image-push images-build images-push controller-install k8s-deploy python-client-example cli-client-example pause-renew-example pause-renew-cli-example vscode-image-build vscode-image-push vscode-example github-copilot-cli-image-build github-copilot-cli-image-push github-copilot-cli-example
INTERNAL_TARGETS := $(addprefix _,$(CONFIGURED_TARGETS))
MAKEFILE_PATH := $(abspath $(firstword $(MAKEFILE_LIST)))

.PHONY: $(CONFIGURED_TARGETS) $(INTERNAL_TARGETS) help local-config check-tools check-example-tools check-acr-vars check-api-key check-ingress-gateway check-client-ingress-gateway check-publication-safety status clean-k8s clean-opensandbox-crds infra-delete gvisor-nodepool-add gvisor-install gvisor-example gvisor-clean firecracker-nodepool-add firecracker-install firecracker-example firecracker-clean

define configured_target
$1: local-config
	@$$(MAKE) --no-print-directory -f "$$(MAKEFILE_PATH)" LOCAL_CONFIG="$$(LOCAL_CONFIG)" _$1
endef

define reject_env_var
@if [ "$(origin $(1))" = "environment" ]; then echo "For $(2), pass $(1) explicitly on the make command line or store it in $(LOCAL_CONFIG); environment values are not accepted"; exit 1; fi
endef

define require_cli_or_config
@if [ "$(origin $(1))" != "command line" ] && ! grep -Eq '^(export[[:space:]]+)?$(1)[[:space:]]*([?:+]?=|=)' "$(LOCAL_CONFIG)" 2>/dev/null; then echo "$(LOCAL_CONFIG) is missing $(1); run make local-config or pass $(1) explicitly on the make command line"; exit 1; fi
endef

define confirm_var
@if [ "$(CONFIRM_$(1))" != "$($(1))" ]; then echo "Set CONFIRM_$(1)=$($(1)) to $(2)"; exit 1; fi
endef

$(foreach target,$(CONFIGURED_TARGETS),$(eval $(call configured_target,$(target))))

_all: check-tools check-api-key _infra-deploy _aks-credentials _acr-login _image-build _image-push _controller-install _k8s-deploy _python-client-example

help:
	@printf '%s\n' \
		'OpenSandbox AKS Make targets' \
		'' \
		'Core workflow:' \
		'  make all                  Deploy infra, install app, and run Python example' \
		'  make local-config         Create/update ignored local config file' \
		'  make print-config         Show effective configuration' \
		'  make infra-deploy         Deploy AKS, ACR, system pool, and Kata user pool' \
		'  make aks-credentials      Fetch kubectl credentials' \
		'  make image-build          Build opensandbox-server image' \
		'  make image-push           Push opensandbox-server image' \
		'  make images-build         Build all repository images' \
		'  make images-push          Build and push all repository images' \
		'  make controller-install   Install OpenSandbox controller' \
		'  make k8s-deploy           Build/push image and deploy Kubernetes resources' \
		'  make check-publication-safety Validate disabled-by-default MCP and digest guards' \
		'' \
		'Runtime experiments:' \
		'  make gvisor-nodepool-add      Add dedicated gVisor pool through Bicep' \
		'  make gvisor-install           Install gVisor on the dedicated pool' \
		'  make gvisor-example           Run gVisor runtime example pod' \
		'  make gvisor-clean             Remove gVisor Kubernetes resources' \
		'  make firecracker-nodepool-add Add dedicated Firecracker pool through Bicep' \
		'  make firecracker-install      Install Kata Firecracker runtime support' \
		'  make firecracker-example      Run Firecracker runtime example pod' \
		'  make firecracker-clean        Remove Firecracker Kubernetes resources' \
		'' \
		'Examples:' \
		'  make python-client-example Run Python SDK client example' \
		'  make cli-client-example    Run osb CLI client example' \
		'  make pause-renew-example      Run Python pause/resume example' \
		'  make pause-renew-cli-example  Run CLI pause/resume example' \
		'  make vscode-image-push        Build and push VS Code sandbox image' \
		'  make vscode-example           Run VS Code Web sandbox example' \
		'  make github-copilot-cli-image-push Build and push Copilot CLI sandbox image' \
		'  make github-copilot-cli-example Run GitHub Copilot CLI in a sandbox' \
		'' \
		'Cleanup:' \
		'  make clean-k8s                Delete app/controller resources; requires CONFIRM_*' \
		'  make clean-opensandbox-crds   Delete OpenSandbox CRDs; requires CONFIRM_*' \
		'  make infra-delete             Delete resource group; no CONFIRM_* required' \
		'' \
		'Common overrides:' \
		'  LOCAL_CONFIG=.make.env RESOURCE_GROUP=<name> AKS_NAME=<name> ACR_NAME=<name>' \
		'  NODE_VM_SIZE=Standard_D4s_v3 SYSTEM_NODE_COUNT=1 KATA_NODE_COUNT=1' \
		'' \
		'Current config:'
	@$(MAKE) --no-print-directory -f "$(MAKEFILE_PATH)" LOCAL_CONFIG="$(LOCAL_CONFIG)" _print-config

local-config:
	@set -euo pipefail; \
		file="$(LOCAL_CONFIG)"; \
		case "$$file" in *[!A-Za-z0-9_./-]*) echo "LOCAL_CONFIG contains unsupported characters; use letters, numbers, dot, slash, underscore, or dash"; exit 1 ;; esac; \
		if [ -L "$$file" ]; then echo "Refusing to use symlinked LOCAL_CONFIG $$file"; exit 1; fi; \
		repo_root=$$(git rev-parse --show-toplevel 2>/dev/null || true); \
		if [ -n "$$repo_root" ]; then \
			case "$$file" in /*) config_path="$$file" ;; *) config_path="$$PWD/$$file" ;; esac; \
			case "$$config_path" in "$$repo_root"/*) \
				rel_path="$${config_path#"$$repo_root"/}"; \
				if git -C "$$repo_root" ls-files --error-unmatch -- "$$rel_path" >/dev/null 2>&1; then \
					echo "Refusing to write local config to tracked file $$rel_path"; \
					exit 1; \
				fi; \
				if ! git -C "$$repo_root" check-ignore -q -- "$$rel_path"; then \
					echo "Refusing to write secrets to unignored repo path $$rel_path; add it to .gitignore or use LOCAL_CONFIG outside the repo"; \
					exit 1; \
				fi; \
			;; esac; \
		fi; \
		changed=0; \
		if [ ! -f "$$file" ]; then \
			umask 077; \
			{ \
				echo '# Local environment config generated by make local-config'; \
				echo '# This file is intentionally ignored by git.'; \
				echo '# Stable defaults live in Makefile; keep only environment identities and secrets here.'; \
			} > "$$file"; \
			changed=1; \
		fi; \
		chmod 600 "$$file"; \
		suffix=$$(date +%m%d%H%M | tr -d '\n'); \
		acr_suffix=$$(date +%m%d%H%M%S | tr -d '\n')$$(od -An -tx1 -N3 /dev/urandom | tr -d ' \n'); \
		api_key=$$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n'); \
		current_subscription=$$(az account show --query id -o tsv 2>/dev/null || true); \
		value_for() { \
			origin="$$1"; \
			current="$$2"; \
			fallback="$$3"; \
			case "$$origin" in environment|"command line") printf '%s' "$$current" ;; *) printf '%s' "$$fallback" ;; esac; \
		}; \
		add_if_missing() { \
			key="$$1"; \
			line="$$2"; \
			if ! grep -Eq "^(export[[:space:]]+)?$$key[[:space:]]*([?:+]?=|=)" "$$file"; then \
				printf '%s\n' "$$line" >> "$$file"; \
				changed=1; \
			fi; \
		}; \
		remove_generated_default() { \
			pattern="$$1"; \
			if grep -Eq "$$pattern" "$$file"; then \
				sed -i -E "\|$$pattern|d" "$$file"; \
				changed=1; \
			fi; \
		}; \
		remove_generated_default '^(export[[:space:]]+)?ASSIGN_ACR_PULL_ROLE[[:space:]]*\?=[[:space:]]*true$$'; \
		remove_generated_default '^(export[[:space:]]+)?ACR_ADMIN_USER_ENABLED[[:space:]]*\?=[[:space:]]*false$$'; \
		remove_generated_default '^(export[[:space:]]+)?ACR_ADMIN_USER_ENABLED[[:space:]]*\?=[[:space:]]*true$$'; \
		remove_generated_default '^(export[[:space:]]+)?OPEN_SANDBOX_CONTROLLER_VERSION[[:space:]]*\?=[[:space:]]*0\.1\.0$$'; \
		remove_generated_default '^(export[[:space:]]+)?OPEN_SANDBOX_CONTROLLER_VERSION[[:space:]]*\?=[[:space:]]*0\.2\.0$$'; \
		remove_generated_default '^(export[[:space:]]+)?OPEN_SANDBOX_CLI_VERSION[[:space:]]*\?=[[:space:]]*0\.1\.1$$'; \
		remove_generated_default '^(export[[:space:]]+)?ENABLE_SNAPSHOT_REGISTRY_SECRET[[:space:]]*\?=[[:space:]]*false$$'; \
		remove_generated_default '^(export[[:space:]]+)?ENABLE_SNAPSHOT_REGISTRY_SECRET[[:space:]]*\?=[[:space:]]*true$$'; \
		remove_generated_default '^(export[[:space:]]+)?OPEN_SANDBOX_SNAPSHOT_REGISTRY[[:space:]]*\?=[[:space:]]*\$$\(ACR_NAME\)\.azurecr\.io/opensandbox-snapshots$$'; \
		remove_generated_default '^(export[[:space:]]+)?OPEN_SANDBOX_SNAPSHOT_REGISTRY_INSECURE[[:space:]]*\?=[[:space:]]*false$$'; \
		remove_generated_default '^(export[[:space:]]+)?OPEN_SANDBOX_SNAPSHOT_SECRET[[:space:]]*\?=[[:space:]]*opensandbox-snapshot-registry$$'; \
		remove_generated_default '^(export[[:space:]]+)?OPEN_SANDBOX_IMAGE_COMMITTER_IMAGE[[:space:]]*\?=[[:space:]]*opensandbox/image-committer:v0\.1\.0$$'; \
		remove_generated_default '^(export[[:space:]]+)?ENABLE_INGRESS_GATEWAY[[:space:]]*\?=[[:space:]]*(false|true)$$'; \
		remove_generated_default '^(export[[:space:]]+)?INGRESS_GATEWAY_IMAGE[[:space:]]*\?=[[:space:]]*sandbox-registry\.cn-zhangjiakou\.cr\.aliyuncs\.com/opensandbox/ingress:v1\.0\.7$$'; \
		remove_generated_default '^(export[[:space:]]+)?INGRESS_GATEWAY_ROUTE_MODE[[:space:]]*\?=[[:space:]]*uri$$'; \
		remove_generated_default '^(export[[:space:]]+)?INGRESS_GATEWAY_ROUTE_MODE[[:space:]]*\?=[[:space:]]*header$$'; \
		remove_generated_default '^(export[[:space:]]+)?INGRESS_GATEWAY_LOCAL_PORT[[:space:]]*\?=[[:space:]]*8081$$'; \
		remove_generated_default '^(export[[:space:]]+)?INGRESS_GATEWAY_HOST[[:space:]]*\?=[[:space:]]*127\.0\.0\.1:\$$\(INGRESS_GATEWAY_LOCAL_PORT\)$$'; \
		remove_generated_default '^(export[[:space:]]+)?INGRESS_GATEWAY_REPLICAS[[:space:]]*\?=[[:space:]]*1$$'; \
		remove_generated_default '^(export[[:space:]]+)?VSCODE_GATEWAY_DOMAIN[[:space:]]*\?=[[:space:]]*127\.0\.0\.1\.nip\.io$$'; \
		remove_generated_default '^(export[[:space:]]+)?SERVER_IMAGE_NAME[[:space:]]*\?=[[:space:]]*opensandbox-kata-server$$'; \
		remove_generated_default '^(export[[:space:]]+)?SERVER_IMAGE_TAG[[:space:]]*\?=[[:space:]]*latest$$'; \
		remove_generated_default '^(export[[:space:]]+)?SANDBOX_IMAGE[[:space:]]*\?=[[:space:]]*python:3\.12-slim$$'; \
		remove_generated_default '^(export[[:space:]]+)?VSCODE_IMAGE_NAME[[:space:]]*\?=[[:space:]]*opensandbox-vscode$$'; \
		remove_generated_default '^(export[[:space:]]+)?VSCODE_IMAGE_TAG[[:space:]]*\?=[[:space:]]*latest$$'; \
		remove_generated_default '^(export[[:space:]]+)?COPILOT_CLI_IMAGE_NAME[[:space:]]*\?=[[:space:]]*opensandbox-copilot-cli$$'; \
		remove_generated_default '^(export[[:space:]]+)?COPILOT_CLI_IMAGE_TAG[[:space:]]*\?=[[:space:]]*latest$$'; \
		remove_generated_default '^(export[[:space:]]+)?SERVER_PORT[[:space:]]*\?=[[:space:]]*8080$$'; \
		remove_generated_default '^(export[[:space:]]+)?VSCODE_PORT[[:space:]]*\?=[[:space:]]*8443$$'; \
		remove_generated_default '^(export[[:space:]]+)?COPILOT_AUTH_HOSTS[[:space:]]*\?=[[:space:]]*api\.github\.com,github\.com,copilot-proxy\.githubusercontent\.com,api\.githubcopilot\.com$$'; \
		remove_generated_default '^(export[[:space:]]+)?COPILOT_CREDENTIAL_HOSTS[[:space:]]*\?=[[:space:]]*api\.github\.com,github\.com$$'; \
		remove_generated_default '^(export[[:space:]]+)?COPILOT_CREDENTIAL_HOSTS[[:space:]]*\?=[[:space:]]*api\.github\.com,github\.com,api\.enterprise\.githubcopilot\.com$$'; \
		remove_generated_default '^(export[[:space:]]+)?COPILOT_EGRESS_HOSTS[[:space:]]*\?=[[:space:]]*api\.github\.com,github\.com,copilot-proxy\.githubusercontent\.com,api\.githubcopilot\.com,copilot-telemetry\.githubusercontent\.com$$'; \
		remove_generated_default '^(export[[:space:]]+)?COPILOT_EGRESS_HOSTS[[:space:]]*\?=[[:space:]]*api\.github\.com,github\.com,copilot-proxy\.githubusercontent\.com,api\.githubcopilot\.com,api\.enterprise\.githubcopilot\.com,copilot-telemetry\.githubusercontent\.com,telemetry\.enterprise\.githubcopilot\.com$$'; \
		remove_generated_default '^(export[[:space:]]+)?COPILOT_INSTALL_HOSTS[[:space:]]*\?=[[:space:]]*gh\.io,github\.com,objects\.githubusercontent\.com,release-assets\.githubusercontent\.com$$'; \
		remove_generated_default '^(export[[:space:]]+)?COPILOT_INSTALL_HOSTS[[:space:]]*\?=[[:space:]]*gh\.io,deb\.debian\.org,security\.debian\.org,github\.com,objects\.githubusercontent\.com,release-assets\.githubusercontent\.com$$'; \
		remove_generated_default '^(export[[:space:]]+)?COPILOT_INSTALL_HOSTS[[:space:]]*\?=[[:space:]]*gh\.io,deb\.debian\.org,security\.debian\.org,github\.com,raw\.githubusercontent\.com,objects\.githubusercontent\.com,release-assets\.githubusercontent\.com$$'; \
		remove_generated_default '^(export[[:space:]]+)?NODE_VM_SIZE[[:space:]]*\?=[[:space:]]*Standard_D4s_v3$$'; \
		remove_generated_default '^(export[[:space:]]+)?SYSTEM_NODE_COUNT[[:space:]]*\?=[[:space:]]*1$$'; \
		remove_generated_default '^(export[[:space:]]+)?KATA_NODEPOOL_NAME[[:space:]]*\?=[[:space:]]*katapool$$'; \
		remove_generated_default '^(export[[:space:]]+)?KATA_NODEPOOL_NAME[[:space:]]*\?=[[:space:]]*katauser$$'; \
		remove_generated_default '^(export[[:space:]]+)?NODE_COUNT[[:space:]]*\?=[[:space:]]*3$$'; \
		remove_generated_default '^(export[[:space:]]+)?KATA_NODE_COUNT[[:space:]]*\?=[[:space:]]*3$$'; \
		remove_generated_default '^(export[[:space:]]+)?GVISOR_NODEPOOL_NAME[[:space:]]*\?=[[:space:]]*gvisorpool$$'; \
		remove_generated_default '^(export[[:space:]]+)?GVISOR_NODE_COUNT[[:space:]]*\?=[[:space:]]*1$$'; \
		remove_generated_default '^(export[[:space:]]+)?GVISOR_NODE_VM_SIZE[[:space:]]*\?=[[:space:]]*Standard_D2s_v3$$'; \
		remove_generated_default '^(export[[:space:]]+)?FIRECRACKER_NODEPOOL_NAME[[:space:]]*\?=[[:space:]]*fcpool$$'; \
		remove_generated_default '^(export[[:space:]]+)?FIRECRACKER_NODE_COUNT[[:space:]]*\?=[[:space:]]*1$$'; \
		remove_generated_default '^(export[[:space:]]+)?FIRECRACKER_NODE_VM_SIZE[[:space:]]*\?=[[:space:]]*Standard_D2s_v3$$'; \
		location=$$(value_for '$(origin LOCATION)' '$(LOCATION)' 'westus3'); \
		resource_group=$$(value_for '$(origin RESOURCE_GROUP)' '$(RESOURCE_GROUP)' "rg-opensandbox-kata-$$suffix"); \
		subscription_id=$$(value_for '$(origin SUBSCRIPTION_ID)' '$(SUBSCRIPTION_ID)' "$$current_subscription"); \
		aks_name=$$(value_for '$(origin AKS_NAME)' '$(AKS_NAME)' "osb-kata-$$suffix"); \
		acr_name=$$(value_for '$(origin ACR_NAME)' '$(ACR_NAME)' "osbkata$$acr_suffix"); \
		api_key=$$(value_for '$(origin OPEN_SANDBOX_API_KEY)' '$(OPEN_SANDBOX_API_KEY)' "$$api_key"); \
		add_if_missing LOCATION "LOCATION ?= $$location"; \
		add_if_missing RESOURCE_GROUP "RESOURCE_GROUP ?= $$resource_group"; \
		if [ -n "$$subscription_id" ]; then add_if_missing SUBSCRIPTION_ID "SUBSCRIPTION_ID ?= $$subscription_id"; fi; \
		add_if_missing AKS_NAME "AKS_NAME ?= $$aks_name"; \
		add_if_missing ACR_NAME "ACR_NAME ?= $$acr_name"; \
		add_if_missing OPEN_SANDBOX_NAMESPACE 'OPEN_SANDBOX_NAMESPACE ?= opensandbox'; \
		add_if_missing OPEN_SANDBOX_API_KEY "OPEN_SANDBOX_API_KEY ?= $$api_key"; \
		if ! grep -Eq '^export[[:space:]]+OPEN_SANDBOX_API_KEY([[:space:]]|$$)' "$$file"; then \
			echo 'export OPEN_SANDBOX_API_KEY' >> "$$file"; \
			changed=1; \
		fi; \
		if [ "$$changed" -eq 1 ]; then \
			echo "Updated $$file"; \
		else \
			echo "Using $$file"; \
		fi

_print-config:
	@echo "LOCAL_CONFIG=$(LOCAL_CONFIG)"
	@echo "RESOURCE_GROUP=$(RESOURCE_GROUP)"
	@echo "SUBSCRIPTION_ID=$(SUBSCRIPTION_ID)"
	@echo "LOCATION=$(LOCATION)"
	@echo "AKS_NAME=$(AKS_NAME)"
	@echo "ACR_NAME=$(ACR_NAME)"
	@echo "NODE_VM_SIZE=$(NODE_VM_SIZE)"
	@echo "SYSTEM_NODE_COUNT=$(SYSTEM_NODE_COUNT)"
	@echo "KATA_NODEPOOL_NAME=$(KATA_NODEPOOL_NAME)"
	@echo "KATA_NODE_COUNT=$(KATA_NODE_COUNT)"
	@echo "GVISOR_NODEPOOL_NAME=$(GVISOR_NODEPOOL_NAME)"
	@echo "GVISOR_NODE_COUNT=$(GVISOR_NODE_COUNT)"
	@echo "FIRECRACKER_NODEPOOL_NAME=$(FIRECRACKER_NODEPOOL_NAME)"
	@echo "FIRECRACKER_NODE_COUNT=$(FIRECRACKER_NODE_COUNT)"
	@echo "ASSIGN_ACR_PULL_ROLE=$(ASSIGN_ACR_PULL_ROLE)"
	@echo "ACR_ADMIN_USER_ENABLED=$(ACR_ADMIN_USER_ENABLED)"
	@echo "OPEN_SANDBOX_NAMESPACE=$(OPEN_SANDBOX_NAMESPACE)"
	@echo "OPEN_SANDBOX_CONTROLLER_VERSION=$(OPEN_SANDBOX_CONTROLLER_VERSION)"
	@echo "OPEN_SANDBOX_CLI_VERSION=$(OPEN_SANDBOX_CLI_VERSION)"
	@echo "KATA_DEPLOY_CHART=$(KATA_DEPLOY_CHART)"
	@echo "ENABLE_SNAPSHOT_REGISTRY_SECRET=$(ENABLE_SNAPSHOT_REGISTRY_SECRET)"
	@echo "OPEN_SANDBOX_SNAPSHOT_REGISTRY=$(OPEN_SANDBOX_SNAPSHOT_REGISTRY)"
	@echo "OPEN_SANDBOX_SNAPSHOT_REGISTRY_INSECURE=$(OPEN_SANDBOX_SNAPSHOT_REGISTRY_INSECURE)"
	@echo "OPEN_SANDBOX_SNAPSHOT_SECRET=$(OPEN_SANDBOX_SNAPSHOT_SECRET)"
	@echo "OPEN_SANDBOX_IMAGE_COMMITTER_IMAGE=$(OPEN_SANDBOX_IMAGE_COMMITTER_IMAGE)"
	@echo "ENABLE_INGRESS_GATEWAY=$(ENABLE_INGRESS_GATEWAY)"
	@echo "INGRESS_GATEWAY_IMAGE=$(INGRESS_GATEWAY_IMAGE)"
	@echo "INGRESS_GATEWAY_ROUTE_MODE=$(INGRESS_GATEWAY_ROUTE_MODE)"
	@echo "INGRESS_GATEWAY_LOCAL_PORT=$(INGRESS_GATEWAY_LOCAL_PORT)"
	@echo "INGRESS_GATEWAY_HOST=$(INGRESS_GATEWAY_HOST)"
	@echo "INGRESS_GATEWAY_REPLICAS=$(INGRESS_GATEWAY_REPLICAS)"
	@echo "VSCODE_GATEWAY_DOMAIN=$(VSCODE_GATEWAY_DOMAIN)"
	@echo "SERVER_IMAGE=$(SERVER_IMAGE)"
	@echo "VSCODE_IMAGE=$(VSCODE_IMAGE)"
	@echo "COPILOT_CLI_IMAGE=$(COPILOT_CLI_IMAGE)"
	@echo "VSCODE_PORT=$(VSCODE_PORT)"
	@echo "COPILOT_CREDENTIAL_HOSTS=$(COPILOT_CREDENTIAL_HOSTS)"
	@echo "COPILOT_EGRESS_HOSTS=$(COPILOT_EGRESS_HOSTS)"

check-tools:
	@command -v az >/dev/null || (echo "az is required"; exit 1)
	@command -v kubectl >/dev/null || (echo "kubectl is required"; exit 1)
	@command -v helm >/dev/null || (echo "helm is required"; exit 1)
	@command -v docker >/dev/null || (echo "docker is required"; exit 1)
	@command -v $(UV) >/dev/null || (echo "$(UV) is required"; exit 1)
	@command -v curl >/dev/null || (echo "curl is required"; exit 1)

check-example-tools:
	@command -v kubectl >/dev/null || (echo "kubectl is required"; exit 1)
	@command -v $(UV) >/dev/null || (echo "$(UV) is required"; exit 1)
	@command -v curl >/dev/null || (echo "curl is required"; exit 1)

check-acr-vars:
	@test -n "$(ACR_NAME)" || (echo "ACR_NAME is required and must be globally unique"; exit 1)
	@if [ "$(ASSIGN_ACR_PULL_ROLE)" = "false" ] && [ "$(ACR_ADMIN_USER_ENABLED)" != "true" ]; then \
		echo "ACR_ADMIN_USER_ENABLED=true is required when ASSIGN_ACR_PULL_ROLE=false"; \
		exit 1; \
	fi

check-api-key:
	@test -n "$${OPEN_SANDBOX_API_KEY}" || (echo "OPEN_SANDBOX_API_KEY is required"; exit 1)

check-ingress-gateway:
	@if [ "$(ENABLE_INGRESS_GATEWAY)" = "true" ] && [ "$(INGRESS_GATEWAY_ROUTE_MODE)" != "header" ] && [ "$(INGRESS_GATEWAY_ROUTE_MODE)" != "uri" ]; then \
		echo "INGRESS_GATEWAY_ROUTE_MODE must be header or uri"; \
		exit 1; \
	fi

check-client-ingress-gateway:
	@if [ "$(ENABLE_INGRESS_GATEWAY)" != "true" ]; then \
		echo "client examples require ENABLE_INGRESS_GATEWAY=true; redeploy with make k8s-deploy"; \
		exit 1; \
	fi
	@if [ "$(INGRESS_GATEWAY_ROUTE_MODE)" != "header" ]; then \
		echo "client examples require INGRESS_GATEWAY_ROUTE_MODE=header; redeploy with make k8s-deploy"; \
		exit 1; \
	fi

check-publication-safety:
	./scripts/check-publication-safety.sh

_infra-deploy:
	az group create --name "$(RESOURCE_GROUP)" --location "$(LOCATION)" $(AZ_SUBSCRIPTION_ARG)
	az deployment group create \
		--name infra-base \
		$(AZ_SUBSCRIPTION_ARG) \
		--resource-group "$(RESOURCE_GROUP)" \
		--template-file infra/cluster.bicep \
		--parameters aksName="$(AKS_NAME)" acrName="$(ACR_NAME)" location="$(LOCATION)" nodeVmSize="$(NODE_VM_SIZE)" systemNodeCount=$(SYSTEM_NODE_COUNT) acrAdminUserEnabled=$(ACR_ADMIN_USER_ENABLED)
	@$(WAIT_FOR_AKS_SUCCEEDED)
	az deployment group create \
		--name kata-nodepool \
		$(AZ_SUBSCRIPTION_ARG) \
		--resource-group "$(RESOURCE_GROUP)" \
		--template-file infra/runtime-pool.bicep \
		--parameters aksName="$(AKS_NAME)" poolName="$(KATA_NODEPOOL_NAME)" nodeVmSize="$(NODE_VM_SIZE)" nodeCount=$(KATA_NODE_COUNT) runtimeKind=kata
	@$(WAIT_FOR_AKS_SUCCEEDED)
	az aks get-credentials --resource-group "$(RESOURCE_GROUP)" --name "$(AKS_NAME)" $(AZ_SUBSCRIPTION_ARG) --overwrite-existing
	kubectl wait --for=condition=Ready node -l kubernetes.azure.com/agentpool=$(KATA_NODEPOOL_NAME) --timeout=600s
	@if [ "$(ASSIGN_ACR_PULL_ROLE)" = "true" ] && [ -n "$(ACR_NAME)" ]; then \
		az deployment group create \
			--name acr-pull-role \
			$(AZ_SUBSCRIPTION_ARG) \
			--resource-group "$(RESOURCE_GROUP)" \
			--template-file infra/registry-access.bicep \
			--parameters aksName="$(AKS_NAME)" acrName="$(ACR_NAME)"; \
	fi

_aks-credentials:
	az aks get-credentials --resource-group "$(RESOURCE_GROUP)" --name "$(AKS_NAME)" $(AZ_SUBSCRIPTION_ARG) --overwrite-existing

_acr-login: check-acr-vars
	@az acr show --name "$(ACR_NAME)" $(AZ_SUBSCRIPTION_ARG) --query loginServer -o tsv >/dev/null

_image-build: check-acr-vars
	docker build -t "$(SERVER_IMAGE)" -f $(SERVER_DEPLOY_DIR)/Dockerfile .

_image-push: check-acr-vars _image-build
	@set -euo pipefail; \
		login_server=$$(az acr show --name "$(ACR_NAME)" $(AZ_SUBSCRIPTION_ARG) --query loginServer -o tsv); \
		test -n "$$login_server"; \
		test "$(ACR_LOGIN_SERVER)" = "$$login_server"; \
		docker_config=$$(mktemp -d); \
		chmod 700 "$$docker_config"; \
		trap 'DOCKER_CONFIG="$$docker_config" docker logout "'"$$login_server"'" >/dev/null 2>&1 || true; rm -rf "$$docker_config"' EXIT; \
		token=$$(az acr login --name "$(ACR_NAME)" $(AZ_SUBSCRIPTION_ARG) --expose-token --query accessToken -o tsv); \
		test -n "$$token"; \
		DOCKER_CONFIG="$$docker_config" docker login "$$login_server" --username 00000000-0000-0000-0000-000000000000 --password-stdin <<< "$$token"; \
		DOCKER_CONFIG="$$docker_config" docker push "$(SERVER_IMAGE)"

_images-build: _image-build _vscode-image-build _github-copilot-cli-image-build

_images-push: _image-push _vscode-image-push _github-copilot-cli-image-push

_controller-install:
	helm upgrade --install opensandbox-controller \
		https://github.com/opensandbox-group/OpenSandbox/releases/download/helm/opensandbox-controller/$(OPEN_SANDBOX_CONTROLLER_VERSION)/opensandbox-controller-$(OPEN_SANDBOX_CONTROLLER_VERSION).tgz \
		--namespace opensandbox-system \
		--create-namespace \
		--set controller.snapshot.registry="$(OPEN_SANDBOX_SNAPSHOT_REGISTRY)" \
		--set controller.snapshot.registryInsecure="$(OPEN_SANDBOX_SNAPSHOT_REGISTRY_INSECURE)" \
		--set controller.snapshot.snapshotPushSecret="$(OPEN_SANDBOX_SNAPSHOT_SECRET)" \
		--set controller.snapshot.resumePullSecret="$(OPEN_SANDBOX_SNAPSHOT_SECRET)" \
		--set controller.snapshot.imageCommitterImage="$(OPEN_SANDBOX_IMAGE_COMMITTER_IMAGE)"
	kubectl wait --for=condition=Established crd/batchsandboxes.sandbox.opensandbox.io --timeout=180s
	kubectl wait --for=condition=Established crd/pools.sandbox.opensandbox.io --timeout=180s
	kubectl wait --for=condition=Established crd/sandboxsnapshots.sandbox.opensandbox.io --timeout=180s
	@pause_field=$$(kubectl get crd batchsandboxes.sandbox.opensandbox.io -o jsonpath='{.spec.versions[?(@.name=="v1alpha1")].schema.openAPIV3Schema.properties.spec.properties.pause.type}'); \
		test "$$pause_field" = "boolean" || (echo "Installed BatchSandbox CRD does not expose spec.pause; pause/resume requires OpenSandbox controller $(OPEN_SANDBOX_CONTROLLER_VERSION) CRDs"; exit 1)
	kubectl wait --for=condition=ready pod -l control-plane=controller-manager -n opensandbox-system --timeout=180s
	kubectl get runtimeclass kata-vm-isolation
	kubectl apply -f $(SERVER_DEPLOY_DIR)/k8s/kata-runtimeclass.yaml
	kubectl get runtimeclass kata-optimized

_k8s-deploy: check-acr-vars check-api-key check-ingress-gateway _image-push
	kubectl apply -f $(SERVER_DEPLOY_DIR)/k8s/kata-runtimeclass.yaml
	kubectl create namespace "$(OPEN_SANDBOX_NAMESPACE)" --dry-run=client -o yaml | kubectl apply -f -
	kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" create serviceaccount opensandbox-server --dry-run=client -o yaml | kubectl apply -f -
	kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" create secret generic opensandbox-server \
		--from-literal=api-key="$${OPEN_SANDBOX_API_KEY}" \
		--dry-run=client -o yaml | kubectl apply -f -
	@if [ "$(ENABLE_SNAPSHOT_REGISTRY_SECRET)" = "true" ] && [ -n "$(OPEN_SANDBOX_SNAPSHOT_REGISTRY)" ]; then \
		set -euo pipefail; \
		snapshot_registry="$(OPEN_SANDBOX_SNAPSHOT_REGISTRY)"; \
		snapshot_registry_server="$${snapshot_registry%%/*}"; \
		if [ "$(ACR_ADMIN_USER_ENABLED)" = "true" ] && [ "$$snapshot_registry_server" = "$(ACR_LOGIN_SERVER)" ]; then \
			set -euo pipefail; \
			password=$$(az acr credential show --name "$(ACR_NAME)" $(AZ_SUBSCRIPTION_ARG) --query 'passwords[0].value' -o tsv); \
			test -n "$$password"; \
			printf '%s' "$$password" | REGISTRY="$(ACR_LOGIN_SERVER)" USERNAME="$(ACR_NAME)" NAMESPACE="$(OPEN_SANDBOX_NAMESPACE)" SECRET_NAME="$(OPEN_SANDBOX_SNAPSHOT_SECRET)" $(UV) run --no-project python -c 'import base64,json,os,sys; u=os.environ["USERNAME"]; p=sys.stdin.read(); r=os.environ["REGISTRY"]; ns=os.environ["NAMESPACE"]; name=os.environ["SECRET_NAME"]; auth=base64.b64encode(f"{u}:{p}".encode()).decode(); cfg={"auths":{r:{"username":u,"password":p,"auth":auth}}}; data=base64.b64encode(json.dumps(cfg,separators=(",",":")).encode()).decode(); print(f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: {name}\n  namespace: {ns}\ntype: kubernetes.io/dockerconfigjson\ndata:\n  .dockerconfigjson: {data}\n")' | kubectl apply -f -; \
		else \
			secret_type=$$(kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" get secret "$(OPEN_SANDBOX_SNAPSHOT_SECRET)" -o jsonpath='{.type}' 2>/dev/null || true); \
			test "$$secret_type" = "kubernetes.io/dockerconfigjson" || (echo "Pause/resume snapshot registry $(OPEN_SANDBOX_SNAPSHOT_REGISTRY) requires a kubernetes.io/dockerconfigjson secret $(OPEN_SANDBOX_SNAPSHOT_SECRET) in namespace $(OPEN_SANDBOX_NAMESPACE), or set ACR_ADMIN_USER_ENABLED=true with OPEN_SANDBOX_SNAPSHOT_REGISTRY under $(ACR_LOGIN_SERVER)/"; exit 1); \
		fi; \
	fi
	@if [ "$(ASSIGN_ACR_PULL_ROLE)" = "false" ] && [ "$(ACR_ADMIN_USER_ENABLED)" = "true" ]; then \
		set -euo pipefail; \
		password=$$(az acr credential show --name "$(ACR_NAME)" $(AZ_SUBSCRIPTION_ARG) --query 'passwords[0].value' -o tsv); \
		test -n "$$password"; \
		kubectl delete secret acr-pull -n "$(OPEN_SANDBOX_NAMESPACE)" --ignore-not-found; \
		printf '%s' "$$password" | REGISTRY="$(ACR_LOGIN_SERVER)" USERNAME="$(ACR_NAME)" NAMESPACE="$(OPEN_SANDBOX_NAMESPACE)" $(UV) run --no-project python -c 'import base64,json,os,sys; u=os.environ["USERNAME"]; p=sys.stdin.read(); r=os.environ["REGISTRY"]; ns=os.environ["NAMESPACE"]; auth=base64.b64encode(f"{u}:{p}".encode()).decode(); cfg={"auths":{r:{"username":u,"password":p,"auth":auth}}}; data=base64.b64encode(json.dumps(cfg,separators=(",",":")).encode()).decode(); print(f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: acr-pull\n  namespace: {ns}\ntype: kubernetes.io/dockerconfigjson\ndata:\n  .dockerconfigjson: {data}\n")' | kubectl create -f -; \
		kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" patch serviceaccount opensandbox-server \
			--type merge \
			--patch '{"imagePullSecrets":[{"name":"acr-pull"}]}'; \
	fi
	sed \
		-e 's|__KATA_NODEPOOL_NAME__|$(KATA_NODEPOOL_NAME)|g' \
		$(SERVER_DEPLOY_DIR)/k8s/batchsandbox-template.yaml | kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" create configmap opensandbox-batchsandbox-template \
		--from-file=batchsandbox-template.yaml=/dev/stdin \
		--dry-run=client -o yaml | kubectl apply -f -
	sed \
		-e 's#__NAMESPACE__#$(OPEN_SANDBOX_NAMESPACE)#g' \
		-e 's#__INGRESS_MODE__#$(INGRESS_MODE)#g' \
		-e 's#__INGRESS_GATEWAY_ADDRESS__#$(INGRESS_GATEWAY_ADDRESS_LINE)#g' \
		-e 's#__INGRESS_GATEWAY_ROUTE_MODE__#$(INGRESS_GATEWAY_ROUTE_MODE_LINE)#g' \
		$(SERVER_DEPLOY_DIR)/config/sandbox.toml | kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" create configmap opensandbox-server-config \
		--from-file=sandbox.toml=/dev/stdin \
		--dry-run=client -o yaml | kubectl apply -f -
	@if [ "$(ENABLE_INGRESS_GATEWAY)" = "true" ]; then \
		sed \
			-e 's#__NAMESPACE__#$(OPEN_SANDBOX_NAMESPACE)#g' \
			-e 's#__GATEWAY_IMAGE__#$(INGRESS_GATEWAY_IMAGE)#g' \
			-e 's#__GATEWAY_ROUTE_MODE__#$(INGRESS_GATEWAY_ROUTE_MODE)#g' \
			-e 's#__GATEWAY_REPLICAS__#$(INGRESS_GATEWAY_REPLICAS)#g' \
			$(SERVER_DEPLOY_DIR)/k8s/opensandbox-ingress-gateway.yaml | kubectl apply -f -; \
		kubectl rollout status deployment/opensandbox-ingress-gateway -n "$(OPEN_SANDBOX_NAMESPACE)" --timeout=180s; \
	fi
	@set -euo pipefail; \
		server_image_ref=$$(./scripts/resolve-acr-image.sh "$(ACR_NAME)" "$(SERVER_IMAGE_NAME)" "$(SERVER_IMAGE_TAG)" "$(SUBSCRIPTION_ID)"); \
		./scripts/require-image-digest.sh "$$server_image_ref" SERVER_IMAGE >/dev/null; \
		echo "Deploying opensandbox-server as $$server_image_ref"; \
		sed \
			-e "s|__SERVER_IMAGE__|$$server_image_ref|g" \
			-e 's|__NAMESPACE__|$(OPEN_SANDBOX_NAMESPACE)|g' \
			$(SERVER_DEPLOY_DIR)/k8s/opensandbox-server.yaml | kubectl apply -f -
	kubectl rollout restart deployment/opensandbox-server -n "$(OPEN_SANDBOX_NAMESPACE)"
	kubectl rollout status deployment/opensandbox-server -n "$(OPEN_SANDBOX_NAMESPACE)" --timeout=180s

_python-client-example: check-example-tools check-client-ingress-gateway
	@set -euo pipefail; \
		port_forward_log=$$(mktemp); \
		kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" port-forward svc/opensandbox-server $(SERVER_PORT):8080 >"$$port_forward_log" 2>&1 & \
		port_forward_pid=$$!; \
		gateway_port_forward_pid=; \
		gateway_port_forward_log=; \
		trap 'kill $$port_forward_pid >/dev/null 2>&1 || true; if [ -n "$$gateway_port_forward_pid" ]; then kill $$gateway_port_forward_pid >/dev/null 2>&1 || true; fi; rm -f "$$port_forward_log" "$$gateway_port_forward_log"' EXIT; \
		for i in {1..30}; do \
			kill -0 $$port_forward_pid >/dev/null 2>&1 || (cat "$$port_forward_log"; exit 1); \
			curl -fsS http://localhost:$(SERVER_PORT)/health >/dev/null 2>&1 && break; \
			sleep 1; \
		done; \
		kill -0 $$port_forward_pid >/dev/null 2>&1 || (cat "$$port_forward_log"; exit 1); \
		curl -fsS http://localhost:$(SERVER_PORT)/health >/dev/null; \
		gateway_port_forward_log=$$(mktemp); \
		kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" port-forward svc/opensandbox-ingress-gateway $(INGRESS_GATEWAY_LOCAL_PORT):80 >"$$gateway_port_forward_log" 2>&1 & \
		gateway_port_forward_pid=$$!; \
		for i in {1..30}; do \
			kill -0 $$gateway_port_forward_pid >/dev/null 2>&1 || (cat "$$gateway_port_forward_log"; exit 1); \
			curl -fsS http://127.0.0.1:$(INGRESS_GATEWAY_LOCAL_PORT)/status.ok >/dev/null 2>&1 && break; \
			sleep 1; \
		done; \
		kill -0 $$gateway_port_forward_pid >/dev/null 2>&1 || (cat "$$gateway_port_forward_log"; exit 1); \
		curl -fsS http://127.0.0.1:$(INGRESS_GATEWAY_LOCAL_PORT)/status.ok >/dev/null; \
		example_api_key=$$(kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" get secret opensandbox-server -o jsonpath='{.data.api-key}' 2>/dev/null | base64 -d 2>/dev/null || true); \
		example_api_key="$${example_api_key:-$${OPEN_SANDBOX_API_KEY:-}}"; \
		test -n "$$example_api_key" || (echo "OPEN_SANDBOX_API_KEY is required, or deploy opensandbox-server with make k8s-deploy first"; exit 1); \
		$(UV) venv --allow-existing .venv; \
		$(UV) pip install -q --python .venv opensandbox==0.1.10; \
		OPEN_SANDBOX_DOMAIN=localhost:$(SERVER_PORT) OPEN_SANDBOX_API_KEY="$$example_api_key" SANDBOX_IMAGE="$(SANDBOX_IMAGE)" VERIFY_KATA_WITH_KUBECTL=1 OPEN_SANDBOX_NAMESPACE="$(OPEN_SANDBOX_NAMESPACE)" $(UV) run --no-project --python .venv/bin/python python $(PYTHON_CLIENT_DIR)/app.py

_cli-client-example: check-example-tools check-client-ingress-gateway
	@set -euo pipefail; \
		port_forward_log=$$(mktemp); \
		kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" port-forward svc/opensandbox-server $(SERVER_PORT):8080 >"$$port_forward_log" 2>&1 & \
		port_forward_pid=$$!; \
		gateway_port_forward_pid=; \
		gateway_port_forward_log=; \
		trap 'kill $$port_forward_pid >/dev/null 2>&1 || true; if [ -n "$$gateway_port_forward_pid" ]; then kill $$gateway_port_forward_pid >/dev/null 2>&1 || true; fi; rm -f "$$port_forward_log" "$$gateway_port_forward_log"' EXIT; \
		for i in {1..30}; do \
			kill -0 $$port_forward_pid >/dev/null 2>&1 || (cat "$$port_forward_log"; exit 1); \
			health=$$(curl -fsS http://localhost:$(SERVER_PORT)/health 2>/dev/null || true); \
			HEALTH="$$health" $(UV) run --no-project python -c 'import json, os, sys; sys.exit(0 if json.loads(os.environ["HEALTH"]).get("status") == "healthy" else 1)' >/dev/null 2>&1 && break; \
			sleep 1; \
		done; \
		kill -0 $$port_forward_pid >/dev/null 2>&1 || (cat "$$port_forward_log"; exit 1); \
		health=$$(curl -fsS http://localhost:$(SERVER_PORT)/health); \
		HEALTH="$$health" $(UV) run --no-project python -c 'import json, os, sys; sys.exit(0 if json.loads(os.environ["HEALTH"]).get("status") == "healthy" else 1)' || (echo "Unexpected opensandbox-server health response: $$health"; exit 1); \
		gateway_port_forward_log=$$(mktemp); \
		kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" port-forward svc/opensandbox-ingress-gateway $(INGRESS_GATEWAY_LOCAL_PORT):80 >"$$gateway_port_forward_log" 2>&1 & \
		gateway_port_forward_pid=$$!; \
		for i in {1..30}; do \
			kill -0 $$gateway_port_forward_pid >/dev/null 2>&1 || (cat "$$gateway_port_forward_log"; exit 1); \
			curl -fsS http://127.0.0.1:$(INGRESS_GATEWAY_LOCAL_PORT)/status.ok >/dev/null 2>&1 && break; \
			sleep 1; \
		done; \
		kill -0 $$gateway_port_forward_pid >/dev/null 2>&1 || (cat "$$gateway_port_forward_log"; exit 1); \
		curl -fsS http://127.0.0.1:$(INGRESS_GATEWAY_LOCAL_PORT)/status.ok >/dev/null; \
		cli_api_key=$$(kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" get secret opensandbox-server -o jsonpath='{.data.api-key}' 2>/dev/null | base64 -d 2>/dev/null || true); \
		cli_api_key="$${cli_api_key:-$${OPEN_SANDBOX_API_KEY:-}}"; \
		test -n "$$cli_api_key" || (echo "OPEN_SANDBOX_API_KEY is required, or deploy opensandbox-server with make k8s-deploy first"; exit 1); \
		$(UV) venv --allow-existing .venv; \
		$(UV) pip install -q --python .venv -r $(CLI_CLIENT_DIR)/requirements.txt opensandbox-cli==$(OPEN_SANDBOX_CLI_VERSION); \
		OPEN_SANDBOX_DOMAIN=localhost:$(SERVER_PORT) OPEN_SANDBOX_PROTOCOL=http OPEN_SANDBOX_API_KEY="$$cli_api_key" SANDBOX_IMAGE="$(SANDBOX_IMAGE)" VERIFY_KATA_WITH_KUBECTL=1 OPEN_SANDBOX_NAMESPACE="$(OPEN_SANDBOX_NAMESPACE)" OSB_BIN=".venv/bin/osb" UV="$(UV)" UV_PYTHON=".venv/bin/python" bash $(CLI_CLIENT_DIR)/osb-cli-smoke.sh

_pause-renew-example: check-example-tools check-client-ingress-gateway
	@set -euo pipefail; \
		port_forward_log=$$(mktemp); \
		kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" port-forward svc/opensandbox-server $(SERVER_PORT):8080 >"$$port_forward_log" 2>&1 & \
		port_forward_pid=$$!; \
		gateway_port_forward_pid=; \
		gateway_port_forward_log=; \
		trap 'kill $$port_forward_pid >/dev/null 2>&1 || true; if [ -n "$$gateway_port_forward_pid" ]; then kill $$gateway_port_forward_pid >/dev/null 2>&1 || true; fi; rm -f "$$port_forward_log" "$$gateway_port_forward_log"' EXIT; \
		for i in {1..30}; do \
			kill -0 $$port_forward_pid >/dev/null 2>&1 || (cat "$$port_forward_log"; exit 1); \
			health=$$(curl -fsS http://localhost:$(SERVER_PORT)/health 2>/dev/null || true); \
			HEALTH="$$health" $(UV) run --no-project python -c 'import json, os, sys; sys.exit(0 if json.loads(os.environ["HEALTH"]).get("status") == "healthy" else 1)' >/dev/null 2>&1 && break; \
			sleep 1; \
		done; \
		kill -0 $$port_forward_pid >/dev/null 2>&1 || (cat "$$port_forward_log"; exit 1); \
		health=$$(curl -fsS http://localhost:$(SERVER_PORT)/health); \
		HEALTH="$$health" $(UV) run --no-project python -c 'import json, os, sys; sys.exit(0 if json.loads(os.environ["HEALTH"]).get("status") == "healthy" else 1)' || (echo "Unexpected opensandbox-server health response: $$health"; exit 1); \
		gateway_port_forward_log=$$(mktemp); \
		kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" port-forward svc/opensandbox-ingress-gateway $(INGRESS_GATEWAY_LOCAL_PORT):80 >"$$gateway_port_forward_log" 2>&1 & \
		gateway_port_forward_pid=$$!; \
		for i in {1..30}; do \
			kill -0 $$gateway_port_forward_pid >/dev/null 2>&1 || (cat "$$gateway_port_forward_log"; exit 1); \
			curl -fsS http://127.0.0.1:$(INGRESS_GATEWAY_LOCAL_PORT)/status.ok >/dev/null 2>&1 && break; \
			sleep 1; \
		done; \
		kill -0 $$gateway_port_forward_pid >/dev/null 2>&1 || (cat "$$gateway_port_forward_log"; exit 1); \
		curl -fsS http://127.0.0.1:$(INGRESS_GATEWAY_LOCAL_PORT)/status.ok >/dev/null; \
		example_api_key=$$(kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" get secret opensandbox-server -o jsonpath='{.data.api-key}' 2>/dev/null | base64 -d 2>/dev/null || true); \
		example_api_key="$${example_api_key:-$${OPEN_SANDBOX_API_KEY:-}}"; \
		test -n "$$example_api_key" || (echo "OPEN_SANDBOX_API_KEY is required, or deploy opensandbox-server with make k8s-deploy first"; exit 1); \
		$(UV) venv --allow-existing .venv; \
		$(UV) pip install -q --python .venv -r $(PAUSE_RENEW_EXAMPLE_DIR)/requirements.txt; \
		OPEN_SANDBOX_DOMAIN=localhost:$(SERVER_PORT) OPEN_SANDBOX_API_KEY="$$example_api_key" SANDBOX_IMAGE="$(SANDBOX_IMAGE)" VERIFY_WITH_KUBECTL=1 OPEN_SANDBOX_NAMESPACE="$(OPEN_SANDBOX_NAMESPACE)" $(UV) run --no-project --python .venv/bin/python python $(PAUSE_RENEW_EXAMPLE_DIR)/app.py

_pause-renew-cli-example: check-example-tools check-client-ingress-gateway
	@set -euo pipefail; \
		port_forward_log=$$(mktemp); \
		kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" port-forward svc/opensandbox-server $(SERVER_PORT):8080 >"$$port_forward_log" 2>&1 & \
		port_forward_pid=$$!; \
		gateway_port_forward_pid=; \
		gateway_port_forward_log=; \
		trap 'kill $$port_forward_pid >/dev/null 2>&1 || true; if [ -n "$$gateway_port_forward_pid" ]; then kill $$gateway_port_forward_pid >/dev/null 2>&1 || true; fi; rm -f "$$port_forward_log" "$$gateway_port_forward_log"' EXIT; \
		for i in {1..30}; do \
			kill -0 $$port_forward_pid >/dev/null 2>&1 || (cat "$$port_forward_log"; exit 1); \
			health=$$(curl -fsS http://localhost:$(SERVER_PORT)/health 2>/dev/null || true); \
			HEALTH="$$health" $(UV) run --no-project python -c 'import json, os, sys; sys.exit(0 if json.loads(os.environ["HEALTH"]).get("status") == "healthy" else 1)' >/dev/null 2>&1 && break; \
			sleep 1; \
		done; \
		kill -0 $$port_forward_pid >/dev/null 2>&1 || (cat "$$port_forward_log"; exit 1); \
		health=$$(curl -fsS http://localhost:$(SERVER_PORT)/health); \
		HEALTH="$$health" $(UV) run --no-project python -c 'import json, os, sys; sys.exit(0 if json.loads(os.environ["HEALTH"]).get("status") == "healthy" else 1)' || (echo "Unexpected opensandbox-server health response: $$health"; exit 1); \
		gateway_port_forward_log=$$(mktemp); \
		kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" port-forward svc/opensandbox-ingress-gateway $(INGRESS_GATEWAY_LOCAL_PORT):80 >"$$gateway_port_forward_log" 2>&1 & \
		gateway_port_forward_pid=$$!; \
		for i in {1..30}; do \
			kill -0 $$gateway_port_forward_pid >/dev/null 2>&1 || (cat "$$gateway_port_forward_log"; exit 1); \
			curl -fsS http://127.0.0.1:$(INGRESS_GATEWAY_LOCAL_PORT)/status.ok >/dev/null 2>&1 && break; \
			sleep 1; \
		done; \
		kill -0 $$gateway_port_forward_pid >/dev/null 2>&1 || (cat "$$gateway_port_forward_log"; exit 1); \
		curl -fsS http://127.0.0.1:$(INGRESS_GATEWAY_LOCAL_PORT)/status.ok >/dev/null; \
		example_api_key=$$(kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" get secret opensandbox-server -o jsonpath='{.data.api-key}' 2>/dev/null | base64 -d 2>/dev/null || true); \
		example_api_key="$${example_api_key:-$${OPEN_SANDBOX_API_KEY:-}}"; \
		test -n "$$example_api_key" || (echo "OPEN_SANDBOX_API_KEY is required, or deploy opensandbox-server with make k8s-deploy first"; exit 1); \
		$(UV) venv --allow-existing .venv; \
		$(UV) pip install -q --python .venv -r $(PAUSE_RENEW_CLI_EXAMPLE_DIR)/requirements.txt opensandbox-cli==$(OPEN_SANDBOX_CLI_VERSION); \
		OPEN_SANDBOX_DOMAIN=localhost:$(SERVER_PORT) OPEN_SANDBOX_PROTOCOL=http OPEN_SANDBOX_API_KEY="$$example_api_key" SANDBOX_IMAGE="$(SANDBOX_IMAGE)" VERIFY_WITH_KUBECTL=1 OPEN_SANDBOX_NAMESPACE="$(OPEN_SANDBOX_NAMESPACE)" OSB_BIN=".venv/bin/osb" UV="$(UV)" UV_PYTHON=".venv/bin/python" bash $(PAUSE_RENEW_CLI_EXAMPLE_DIR)/osb-pause-renew.sh

_vscode-image-build: check-acr-vars
	docker build -t "$(VSCODE_IMAGE)" -f $(VSCODE_EXAMPLE_DIR)/Dockerfile $(VSCODE_EXAMPLE_DIR)

_vscode-image-push: check-acr-vars _vscode-image-build
	@set -euo pipefail; \
		login_server=$$(az acr show --name "$(ACR_NAME)" $(AZ_SUBSCRIPTION_ARG) --query loginServer -o tsv); \
		test -n "$$login_server"; \
		test "$(ACR_LOGIN_SERVER)" = "$$login_server"; \
		docker_config=$$(mktemp -d); \
		chmod 700 "$$docker_config"; \
		trap 'DOCKER_CONFIG="$$docker_config" docker logout "'"$$login_server"'" >/dev/null 2>&1 || true; rm -rf "$$docker_config"' EXIT; \
		token=$$(az acr login --name "$(ACR_NAME)" $(AZ_SUBSCRIPTION_ARG) --expose-token --query accessToken -o tsv); \
		test -n "$$token"; \
		DOCKER_CONFIG="$$docker_config" docker login "$$login_server" --username 00000000-0000-0000-0000-000000000000 --password-stdin <<< "$$token"; \
		DOCKER_CONFIG="$$docker_config" docker push "$(VSCODE_IMAGE)"

_github-copilot-cli-image-build: check-acr-vars
	docker build -t "$(COPILOT_CLI_IMAGE)" -f $(GITHUB_COPILOT_CLI_EXAMPLE_DIR)/Dockerfile $(GITHUB_COPILOT_CLI_EXAMPLE_DIR)

_github-copilot-cli-image-push: check-acr-vars _github-copilot-cli-image-build
	@set -euo pipefail; \
		login_server=$$(az acr show --name "$(ACR_NAME)" $(AZ_SUBSCRIPTION_ARG) --query loginServer -o tsv); \
		test -n "$$login_server"; \
		test "$(ACR_LOGIN_SERVER)" = "$$login_server"; \
		docker_config=$$(mktemp -d); \
		chmod 700 "$$docker_config"; \
		trap 'DOCKER_CONFIG="$$docker_config" docker logout "'"$$login_server"'" >/dev/null 2>&1 || true; rm -rf "$$docker_config"' EXIT; \
		token=$$(az acr login --name "$(ACR_NAME)" $(AZ_SUBSCRIPTION_ARG) --expose-token --query accessToken -o tsv); \
		test -n "$$token"; \
		DOCKER_CONFIG="$$docker_config" docker login "$$login_server" --username 00000000-0000-0000-0000-000000000000 --password-stdin <<< "$$token"; \
		DOCKER_CONFIG="$$docker_config" docker push "$(COPILOT_CLI_IMAGE)"

_vscode-example: check-example-tools check-acr-vars
	@set -euo pipefail; \
		command -v az >/dev/null || (echo "az is required"; exit 1); \
		if [ "$(ENABLE_INGRESS_GATEWAY)" != "true" ]; then \
			echo "vscode-example requires ENABLE_INGRESS_GATEWAY=true; redeploy with make k8s-deploy"; \
			exit 1; \
		fi; \
		if [ "$(INGRESS_GATEWAY_ROUTE_MODE)" != "header" ]; then \
			echo "vscode-example no-proxy browser access requires INGRESS_GATEWAY_ROUTE_MODE=header; redeploy with make k8s-deploy"; \
			exit 1; \
		fi; \
		az acr repository show-tags --name "$(ACR_NAME)" $(AZ_SUBSCRIPTION_ARG) --repository "$(VSCODE_IMAGE_NAME)" --query "[?@=='$(VSCODE_IMAGE_TAG)'] | [0]" -o tsv | grep -Fxq "$(VSCODE_IMAGE_TAG)" || (echo "$(VSCODE_IMAGE) is not pushed; run make vscode-image-push or make images-push first"; exit 1); \
		port_forward_log=$$(mktemp); \
		kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" port-forward svc/opensandbox-server $(SERVER_PORT):8080 >"$$port_forward_log" 2>&1 & \
		port_forward_pid=$$!; \
		gateway_port_forward_pid=; \
		gateway_port_forward_log=; \
		trap 'kill $$port_forward_pid >/dev/null 2>&1 || true; if [ -n "$$gateway_port_forward_pid" ]; then kill $$gateway_port_forward_pid >/dev/null 2>&1 || true; fi; rm -f "$$port_forward_log" "$$gateway_port_forward_log"' EXIT; \
		for i in {1..30}; do \
			kill -0 $$port_forward_pid >/dev/null 2>&1 || (cat "$$port_forward_log"; exit 1); \
			health=$$(curl -fsS http://localhost:$(SERVER_PORT)/health 2>/dev/null || true); \
			HEALTH="$$health" $(UV) run --no-project python -c 'import json, os, sys; sys.exit(0 if json.loads(os.environ["HEALTH"]).get("status") == "healthy" else 1)' >/dev/null 2>&1 && break; \
			sleep 1; \
		done; \
		kill -0 $$port_forward_pid >/dev/null 2>&1 || (cat "$$port_forward_log"; exit 1); \
		health=$$(curl -fsS http://localhost:$(SERVER_PORT)/health); \
		HEALTH="$$health" $(UV) run --no-project python -c 'import json, os, sys; sys.exit(0 if json.loads(os.environ["HEALTH"]).get("status") == "healthy" else 1)' || (echo "Unexpected opensandbox-server health response: $$health"; exit 1); \
		gateway_port_forward_log=$$(mktemp); \
		kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" port-forward svc/opensandbox-ingress-gateway $(INGRESS_GATEWAY_LOCAL_PORT):80 >"$$gateway_port_forward_log" 2>&1 & \
		gateway_port_forward_pid=$$!; \
		for i in {1..30}; do \
			kill -0 $$gateway_port_forward_pid >/dev/null 2>&1 || (cat "$$gateway_port_forward_log"; exit 1); \
			curl -fsS http://127.0.0.1:$(INGRESS_GATEWAY_LOCAL_PORT)/status.ok >/dev/null 2>&1 && break; \
			sleep 1; \
		done; \
		kill -0 $$gateway_port_forward_pid >/dev/null 2>&1 || (cat "$$gateway_port_forward_log"; exit 1); \
		curl -fsS http://127.0.0.1:$(INGRESS_GATEWAY_LOCAL_PORT)/status.ok >/dev/null; \
		example_api_key=$$(kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" get secret opensandbox-server -o jsonpath='{.data.api-key}' 2>/dev/null | base64 -d 2>/dev/null || true); \
		example_api_key="$${example_api_key:-$${OPEN_SANDBOX_API_KEY:-}}"; \
		test -n "$$example_api_key" || (echo "OPEN_SANDBOX_API_KEY is required, or deploy opensandbox-server with make k8s-deploy first"; exit 1); \
		$(UV) venv --allow-existing .venv; \
		$(UV) pip install -q --python .venv -r $(VSCODE_EXAMPLE_DIR)/requirements.txt; \
		OPEN_SANDBOX_DOMAIN=localhost:$(SERVER_PORT) OPEN_SANDBOX_API_KEY="$$example_api_key" SANDBOX_IMAGE="$(VSCODE_IMAGE)" OPEN_SANDBOX_NAMESPACE="$(OPEN_SANDBOX_NAMESPACE)" CODE_PORT="$(VSCODE_PORT)" INGRESS_GATEWAY_LOCAL_PORT="$(INGRESS_GATEWAY_LOCAL_PORT)" VSCODE_GATEWAY_DOMAIN="$(VSCODE_GATEWAY_DOMAIN)" VERIFY_KATA_WITH_KUBECTL=1 $(UV) run --no-project --python .venv/bin/python python -u $(VSCODE_EXAMPLE_DIR)/main.py

_github-copilot-cli-example: check-example-tools check-acr-vars
	@set -euo pipefail; \
		command -v az >/dev/null || (echo "az is required"; exit 1); \
		if [ "$(ENABLE_INGRESS_GATEWAY)" != "true" ]; then \
			echo "github-copilot-cli-example requires ENABLE_INGRESS_GATEWAY=true; redeploy with make k8s-deploy"; \
			exit 1; \
		fi; \
		if [ "$(INGRESS_GATEWAY_ROUTE_MODE)" != "header" ]; then \
			echo "github-copilot-cli-example requires INGRESS_GATEWAY_ROUTE_MODE=header; redeploy with make k8s-deploy"; \
			exit 1; \
		fi; \
		github_token="$${COPILOT_GITHUB_TOKEN:-}"; \
		test -n "$$github_token" || (echo "COPILOT_GITHUB_TOKEN is required"; exit 1); \
		az acr repository show-tags --name "$(ACR_NAME)" $(AZ_SUBSCRIPTION_ARG) --repository "$(COPILOT_CLI_IMAGE_NAME)" --query "[?@=='$(COPILOT_CLI_IMAGE_TAG)'] | [0]" -o tsv | grep -Fxq "$(COPILOT_CLI_IMAGE_TAG)" || (echo "$(COPILOT_CLI_IMAGE) is not pushed; run make github-copilot-cli-image-push or make images-push first"; exit 1); \
		port_forward_log=$$(mktemp); \
		kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" port-forward svc/opensandbox-server $(SERVER_PORT):8080 >"$$port_forward_log" 2>&1 & \
		port_forward_pid=$$!; \
		gateway_port_forward_pid=; \
		gateway_port_forward_log=; \
		trap 'kill $$port_forward_pid >/dev/null 2>&1 || true; if [ -n "$$gateway_port_forward_pid" ]; then kill $$gateway_port_forward_pid >/dev/null 2>&1 || true; fi; rm -f "$$port_forward_log" "$$gateway_port_forward_log"' EXIT; \
		for i in {1..30}; do \
			kill -0 $$port_forward_pid >/dev/null 2>&1 || (cat "$$port_forward_log"; exit 1); \
			health=$$(curl -fsS http://localhost:$(SERVER_PORT)/health 2>/dev/null || true); \
			HEALTH="$$health" $(UV) run --no-project python -c 'import json, os, sys; sys.exit(0 if json.loads(os.environ["HEALTH"]).get("status") == "healthy" else 1)' >/dev/null 2>&1 && break; \
			sleep 1; \
		done; \
		kill -0 $$port_forward_pid >/dev/null 2>&1 || (cat "$$port_forward_log"; exit 1); \
		health=$$(curl -fsS http://localhost:$(SERVER_PORT)/health); \
		HEALTH="$$health" $(UV) run --no-project python -c 'import json, os, sys; sys.exit(0 if json.loads(os.environ["HEALTH"]).get("status") == "healthy" else 1)' || (echo "Unexpected opensandbox-server health response: $$health"; exit 1); \
		gateway_port_forward_log=$$(mktemp); \
		kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" port-forward svc/opensandbox-ingress-gateway $(INGRESS_GATEWAY_LOCAL_PORT):80 >"$$gateway_port_forward_log" 2>&1 & \
		gateway_port_forward_pid=$$!; \
		for i in {1..30}; do \
			kill -0 $$gateway_port_forward_pid >/dev/null 2>&1 || (cat "$$gateway_port_forward_log"; exit 1); \
			curl -fsS http://127.0.0.1:$(INGRESS_GATEWAY_LOCAL_PORT)/status.ok >/dev/null 2>&1 && break; \
			sleep 1; \
		done; \
		kill -0 $$gateway_port_forward_pid >/dev/null 2>&1 || (cat "$$gateway_port_forward_log"; exit 1); \
		curl -fsS http://127.0.0.1:$(INGRESS_GATEWAY_LOCAL_PORT)/status.ok >/dev/null; \
		example_api_key=$$(kubectl -n "$(OPEN_SANDBOX_NAMESPACE)" get secret opensandbox-server -o jsonpath='{.data.api-key}' 2>/dev/null | base64 -d 2>/dev/null || true); \
		example_api_key="$${example_api_key:-$${OPEN_SANDBOX_API_KEY:-}}"; \
		test -n "$$example_api_key" || (echo "OPEN_SANDBOX_API_KEY is required, or deploy opensandbox-server with make k8s-deploy first"; exit 1); \
		$(UV) venv --allow-existing .venv; \
		$(UV) pip install -q --python .venv -r $(GITHUB_COPILOT_CLI_EXAMPLE_DIR)/requirements.txt; \
		OPEN_SANDBOX_DOMAIN=localhost:$(SERVER_PORT) OPEN_SANDBOX_API_KEY="$$example_api_key" COPILOT_GITHUB_TOKEN="$$github_token" SANDBOX_IMAGE="$(COPILOT_CLI_IMAGE)" OPEN_SANDBOX_NAMESPACE="$(OPEN_SANDBOX_NAMESPACE)" COPILOT_CREDENTIAL_HOSTS="$(COPILOT_CREDENTIAL_HOSTS)" COPILOT_EGRESS_HOSTS="$(COPILOT_EGRESS_HOSTS)" VERIFY_KATA_WITH_KUBECTL=1 $(UV) run --no-project --python .venv/bin/python python -u $(GITHUB_COPILOT_CLI_EXAMPLE_DIR)/main.py

status:
	kubectl get runtimeclass
	kubectl get pods -n opensandbox-system
	kubectl get pods -n "$(OPEN_SANDBOX_NAMESPACE)" -o wide
	kubectl get batchsandboxes -n "$(OPEN_SANDBOX_NAMESPACE)" || true
	kubectl get sandboxsnapshots -n "$(OPEN_SANDBOX_NAMESPACE)" || true

gvisor-nodepool-add:
	@$(WAIT_FOR_AKS_SUCCEEDED)
	az deployment group create \
		--name gvisor-nodepool \
		$(AZ_SUBSCRIPTION_ARG) \
		--resource-group "$(RESOURCE_GROUP)" \
		--template-file infra/runtime-pool.bicep \
		--parameters aksName="$(AKS_NAME)" poolName="$(GVISOR_NODEPOOL_NAME)" nodeVmSize="$(NODE_VM_SIZE)" nodeCount=$(GVISOR_NODE_COUNT) runtimeKind=gvisor
	@$(WAIT_FOR_AKS_SUCCEEDED)
	az aks get-credentials --resource-group "$(RESOURCE_GROUP)" --name "$(AKS_NAME)" $(AZ_SUBSCRIPTION_ARG) --overwrite-existing
	kubectl wait --for=condition=Ready node -l kubernetes.azure.com/agentpool=$(GVISOR_NODEPOOL_NAME) --timeout=600s

gvisor-install:
	sed -e 's|__GVISOR_NODEPOOL_NAME__|$(GVISOR_NODEPOOL_NAME)|g' deploy/gvisor-runtime/gvisor-installer.yaml | kubectl apply -f -
	kubectl rollout status daemonset/gvisor-installer -n gvisor-install --timeout=300s
	kubectl logs -n gvisor-install daemonset/gvisor-installer --tail=-1
	sleep 10
	kubectl wait --for=condition=Ready node -l kubernetes.azure.com/agentpool=$(GVISOR_NODEPOOL_NAME) --timeout=300s
	kubectl get runtimeclass gvisor

gvisor-example:
	sed -e 's|__GVISOR_NODEPOOL_NAME__|$(GVISOR_NODEPOOL_NAME)|g' deploy/gvisor-runtime/gvisor-smoke-pod.yaml | kubectl apply -f -
	kubectl wait --for=condition=Ready pod/gvisor-smoke -n gvisor-install --timeout=240s
	kubectl get pod gvisor-smoke -n gvisor-install -o jsonpath='{.metadata.name}{"\t"}{.spec.runtimeClassName}{"\t"}{.spec.nodeName}{"\t"}{.status.phase}{"\n"}'
	kubectl exec -n gvisor-install gvisor-smoke -- uname -a
	sed -e 's|__GVISOR_NODEPOOL_NAME__|$(GVISOR_NODEPOOL_NAME)|g' deploy/gvisor-runtime/gvisor-smoke-pod.yaml | kubectl delete -f - --wait=false

gvisor-clean:
	sed -e 's|__GVISOR_NODEPOOL_NAME__|$(GVISOR_NODEPOOL_NAME)|g' deploy/gvisor-runtime/gvisor-smoke-pod.yaml | kubectl delete -f - --ignore-not-found
	kubectl delete daemonset gvisor-installer -n gvisor-install --ignore-not-found
	kubectl delete configmap gvisor-installer-script -n gvisor-install --ignore-not-found
	kubectl delete namespace gvisor-install --ignore-not-found

firecracker-nodepool-add:
	@$(WAIT_FOR_AKS_SUCCEEDED)
	az deployment group create \
		--name firecracker-nodepool \
		$(AZ_SUBSCRIPTION_ARG) \
		--resource-group "$(RESOURCE_GROUP)" \
		--template-file infra/runtime-pool.bicep \
		--parameters aksName="$(AKS_NAME)" poolName="$(FIRECRACKER_NODEPOOL_NAME)" nodeVmSize="$(NODE_VM_SIZE)" nodeCount=$(FIRECRACKER_NODE_COUNT) runtimeKind=firecracker
	@$(WAIT_FOR_AKS_SUCCEEDED)
	az aks get-credentials --resource-group "$(RESOURCE_GROUP)" --name "$(AKS_NAME)" $(AZ_SUBSCRIPTION_ARG) --overwrite-existing
	kubectl wait --for=condition=Ready node -l kubernetes.azure.com/agentpool=$(FIRECRACKER_NODEPOOL_NAME) --timeout=600s

firecracker-install:
	tmp_values=$$(mktemp); \
		sed -e 's|__FIRECRACKER_NODEPOOL_NAME__|$(FIRECRACKER_NODEPOOL_NAME)|g' deploy/firecracker-runtime/kata-fc-values.yaml > "$$tmp_values"; \
		trap 'rm -f "$$tmp_values"' EXIT; \
		"$${HELM:-helm}" upgrade --install kata-fc "$(KATA_DEPLOY_CHART)" \
			-n kube-system \
			-f "$$tmp_values" \
			--wait \
			--timeout 20m
	sed -e 's|__FIRECRACKER_NODEPOOL_NAME__|$(FIRECRACKER_NODEPOOL_NAME)|g' deploy/firecracker-runtime/devmapper-installer.yaml | kubectl apply -f -
	kubectl rollout status daemonset/devmapper-installer -n firecracker-install --timeout=240s
	sleep 20
	kubectl wait --for=condition=Ready node -l kubernetes.azure.com/agentpool=$(FIRECRACKER_NODEPOOL_NAME) --timeout=300s
	sed -e 's|__FIRECRACKER_NODEPOOL_NAME__|$(FIRECRACKER_NODEPOOL_NAME)|g' deploy/firecracker-runtime/prepull.yaml | kubectl apply -f -
	kubectl rollout status daemonset/firecracker-prepull -n firecracker-install --timeout=240s
	sleep 20
	kubectl get runtimeclass kata-fc

firecracker-example:
	kubectl delete pod -n firecracker-smoke kata-fc-smoke --ignore-not-found
	sed -e 's|__FIRECRACKER_NODEPOOL_NAME__|$(FIRECRACKER_NODEPOOL_NAME)|g' deploy/firecracker-runtime/kata-fc-smoke-pod.yaml | kubectl apply -f -
	kubectl wait --for=condition=Ready pod/kata-fc-smoke -n firecracker-smoke --timeout=360s
	kubectl get pod kata-fc-smoke -n firecracker-smoke -o jsonpath='{.metadata.name}{"\t"}{.spec.runtimeClassName}{"\t"}{.spec.nodeName}{"\t"}{.status.phase}{"\n"}'
	kubectl exec -n firecracker-smoke kata-fc-smoke -- uname -a

firecracker-clean:
	kubectl delete namespace firecracker-smoke --ignore-not-found
	kubectl delete namespace firecracker-install --ignore-not-found
	"$${HELM:-helm}" uninstall kata-fc -n kube-system || true

clean-k8s:
	$(call reject_env_var,AKS_NAME,cleanup)
	$(call reject_env_var,RESOURCE_GROUP,cleanup)
	$(call reject_env_var,SUBSCRIPTION_ID,cleanup)
	$(call reject_env_var,OPEN_SANDBOX_NAMESPACE,cleanup)
	$(call require_cli_or_config,AKS_NAME)
	$(call require_cli_or_config,RESOURCE_GROUP)
	$(call require_cli_or_config,SUBSCRIPTION_ID)
	$(call require_cli_or_config,OPEN_SANDBOX_NAMESPACE)
	$(call confirm_var,AKS_NAME,clean Kubernetes resources)
	$(call confirm_var,RESOURCE_GROUP,clean Kubernetes resources)
	$(call confirm_var,SUBSCRIPTION_ID,clean Kubernetes resources)
	$(call confirm_var,OPEN_SANDBOX_NAMESPACE,clean Kubernetes resources)
	@set -euo pipefail; \
		expected_kubeconfig=$$(mktemp); \
		trap 'rm -f "$$expected_kubeconfig"' EXIT; \
		az aks get-credentials --resource-group "$(RESOURCE_GROUP)" --name "$(AKS_NAME)" --subscription "$(SUBSCRIPTION_ID)" --file "$$expected_kubeconfig" --overwrite-existing >/dev/null; \
		expected_server=$$(KUBECONFIG="$$expected_kubeconfig" kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'); \
		current_context=$$(kubectl config current-context); \
		current_server=$$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'); \
		if [ -z "$$expected_server" ] || [ "$$current_server" != "$$expected_server" ]; then echo "Current kubectl context '$$current_context' does not point to $(AKS_NAME) in $(RESOURCE_GROUP) / $(SUBSCRIPTION_ID)"; exit 1; fi
	kubectl delete namespace "$(OPEN_SANDBOX_NAMESPACE)" --ignore-not-found
	helm uninstall opensandbox-controller -n opensandbox-system || true
	kubectl delete namespace opensandbox-system --ignore-not-found

clean-opensandbox-crds:
	$(call reject_env_var,AKS_NAME,cluster-scoped CRD cleanup)
	$(call reject_env_var,RESOURCE_GROUP,cluster-scoped CRD cleanup)
	$(call reject_env_var,SUBSCRIPTION_ID,cluster-scoped CRD cleanup)
	$(call require_cli_or_config,AKS_NAME)
	$(call require_cli_or_config,RESOURCE_GROUP)
	$(call require_cli_or_config,SUBSCRIPTION_ID)
	$(call confirm_var,AKS_NAME,delete OpenSandbox CRDs and all OpenSandbox custom resources cluster-wide)
	$(call confirm_var,RESOURCE_GROUP,delete OpenSandbox CRDs and all OpenSandbox custom resources cluster-wide)
	$(call confirm_var,SUBSCRIPTION_ID,delete OpenSandbox CRDs and all OpenSandbox custom resources cluster-wide)
	@if [ "$(CONFIRM_DELETE_OPEN_SANDBOX_CRDS)" != "delete-cluster-wide-opensandbox-crds" ]; then echo "Set CONFIRM_DELETE_OPEN_SANDBOX_CRDS=delete-cluster-wide-opensandbox-crds to delete OpenSandbox CRDs and all matching custom resources cluster-wide"; exit 1; fi
	@set -euo pipefail; \
		expected_kubeconfig=$$(mktemp); \
		trap 'rm -f "$$expected_kubeconfig"' EXIT; \
		az aks get-credentials --resource-group "$(RESOURCE_GROUP)" --name "$(AKS_NAME)" --subscription "$(SUBSCRIPTION_ID)" --file "$$expected_kubeconfig" --overwrite-existing >/dev/null; \
		expected_server=$$(KUBECONFIG="$$expected_kubeconfig" kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'); \
		current_context=$$(kubectl config current-context); \
		current_server=$$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'); \
		if [ -z "$$expected_server" ] || [ "$$current_server" != "$$expected_server" ]; then echo "Current kubectl context '$$current_context' does not point to $(AKS_NAME) in $(RESOURCE_GROUP) / $(SUBSCRIPTION_ID)"; exit 1; fi
	kubectl delete crd batchsandboxes.sandbox.opensandbox.io pools.sandbox.opensandbox.io sandboxsnapshots.sandbox.opensandbox.io --ignore-not-found

infra-delete:
	$(call reject_env_var,RESOURCE_GROUP,deletion)
	$(call reject_env_var,SUBSCRIPTION_ID,deletion)
	$(call require_cli_or_config,RESOURCE_GROUP)
	$(call require_cli_or_config,SUBSCRIPTION_ID)
	@current_subscription=$$(az account show --query id -o tsv); \
		if [ "$$current_subscription" != "$(SUBSCRIPTION_ID)" ]; then echo "Current Azure subscription '$$current_subscription' does not match $(SUBSCRIPTION_ID)"; exit 1; fi
	az group delete --name "$(RESOURCE_GROUP)" --subscription "$(SUBSCRIPTION_ID)" --yes
