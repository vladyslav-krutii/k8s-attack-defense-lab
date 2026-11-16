# k8s-attack-defense-lab - Phase 0 targets (more are added in later phases).
SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c

CLUSTER_NAME   := k8s-lab
KUBE_CONTEXT   := kind-$(CLUSTER_NAME)
CALICO_VERSION := v3.33.0
CALICO_URL     := https://raw.githubusercontent.com/projectcalico/calico/$(CALICO_VERSION)/manifests

# Every kubectl call names the context explicitly, so a lab command can never
# hit another cluster that happens to be the current context.
KUBECTL := kubectl --context $(KUBE_CONTEXT)

API_IMAGE := k8s-lab/api:0.1.0
NAMESPACE := demo

.PHONY: help tools cluster calico verify-netpol status cluster-delete \
        build load base smoke port-forward undeploy

help: ## Show available targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-16s %s\n", $$1, $$2}'

tools: ## Check that required tools are installed
	@for t in docker kind kubectl; do \
	  command -v $$t >/dev/null || { echo "missing: $$t"; exit 1; }; \
	done
	@docker info >/dev/null 2>&1 || { echo "Docker daemon is not running"; exit 1; }
	@kind version
	@kubectl version --client | head -1

cluster: tools ## Create the kind cluster and install Calico
	kind create cluster --config cluster/kind-config.yaml
	$(MAKE) calico

calico: ## Install Calico via the Tigera operator
	@# 1. CRDs. --server-side because the bundle is too large for the
	@#    last-applied annotation that client-side apply writes.
	$(KUBECTL) apply --server-side -f $(CALICO_URL)/v3_projectcalico_org.yaml
	@# 2. The operator that installs and reconciles Calico.
	$(KUBECTL) apply --server-side -f $(CALICO_URL)/tigera-operator.yaml
	$(KUBECTL) wait --for=condition=Established crd/installations.operator.tigera.io --timeout=60s
	@# 3. Our configuration (pod CIDR matching kind-config.yaml).
	$(KUBECTL) apply -f cluster/calico/custom-resources.yaml
	@echo "Waiting for Calico to become available (first run pulls images, can take a few minutes)..."
	@until $(KUBECTL) get tigerastatus calico >/dev/null 2>&1; do sleep 3; done
	$(KUBECTL) wait --for=condition=Available tigerastatus/calico --timeout=600s
	$(KUBECTL) wait --for=condition=Ready nodes --all --timeout=180s

verify-netpol: ## Prove NetworkPolicy is enforced (allow -> deny -> allow)
	KUBE_CONTEXT=$(KUBE_CONTEXT) bash scripts/verify-netpol.sh

status: ## Show nodes, Calico status and system pods
	$(KUBECTL) get nodes -o wide
	$(KUBECTL) get tigerastatus
	$(KUBECTL) get pods -A

build: ## Build the API image
	docker build -t $(API_IMAGE) app/api

load: build ## Copy the API image into the kind nodes (no registry needed)
	kind load docker-image $(API_IMAGE) --name $(CLUSTER_NAME)

base: load ## Deploy the plain base app (no misconfigs, no defenses)
	$(KUBECTL) apply -k k8s/base
	$(KUBECTL) -n $(NAMESPACE) rollout status deploy/db deploy/api deploy/web --timeout=180s

smoke: ## End-to-end check: web -> api -> db
	KUBE_CONTEXT=$(KUBE_CONTEXT) NAMESPACE=$(NAMESPACE) bash scripts/smoke.sh

port-forward: ## Open the app at http://localhost:8080 (Ctrl+C to stop)
	$(KUBECTL) -n $(NAMESPACE) port-forward svc/web 8080:8080

undeploy: ## Remove the app (deleting the namespace removes everything in it)
	$(KUBECTL) delete namespace $(NAMESPACE) --ignore-not-found

cluster-delete: ## Delete the kind cluster
	kind delete cluster --name $(CLUSTER_NAME)
