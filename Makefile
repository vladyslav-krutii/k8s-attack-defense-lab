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

KYVERNO_CHART_VERSION := 3.10.0
FALCO_CHART_VERSION   := 9.2.2
HELM := helm --kube-context $(KUBE_CONTEXT)

API_IMAGE := k8s-lab/api:0.2.0
API_IMAGE_LATEST := k8s-lab/api:latest
NAMESPACE := demo

.PHONY: help tools cluster calico verify-netpol status cluster-delete \
        build load base vulnerable hardened verify-all smoke port-forward undeploy \
        helm kubectl kyverno-cli kyverno policy-test policies verify-admission reports \
        falco falco-logs verify-detection

help: ## Show available targets
	@grep -E '^[a-z0-9%-]+:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-16s %s\n", $$1, $$2}'

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

helm: ## Install pinned Helm into ~/.local/bin (checksum-verified)
	bash scripts/install-helm.sh

kubectl: ## Install pinned kubectl v1.36.4 into ~/.local/bin (checksum-verified)
	bash scripts/install-kubectl.sh

kyverno-cli: ## Install pinned Kyverno CLI into ~/.local/bin (checksum-verified)
	bash scripts/install-kyverno-cli.sh

policy-test: ## Offline Kyverno policy tests (no cluster needed)
	kyverno test policies/kyverno/tests --require-tests

policies: ## Apply Kyverno policies (audit + enforce variants, chosen by ns label)
	@# RBAC first: ClusterRole aggregation is asynchronous, and Kyverno
	@# computes a policy's readiness when the policy is created. Policies
	@# created before the permission lands stay READY=false until changed.
	$(KUBECTL) apply -f policies/kyverno/rbac-reports-ephemeralcontainers.yaml
	@for i in $$(seq 1 30); do \
	  [ "$$($(KUBECTL) auth can-i list pods --subresource=ephemeralcontainers \
	    --as=system:serviceaccount:kyverno:kyverno-reports-controller)" = yes ] && break; \
	  sleep 1; \
	done
	$(KUBECTL) apply -k policies/kyverno
	@# A policy enforces only once Kyverno has configured its webhook; wait
	@# for READY so a check run right after this target is not a false result.
	$(KUBECTL) wait validatingpolicy --all --timeout=90s \
	  --for=jsonpath='{.status.conditionStatus.ready}'=true
	$(KUBECTL) get validatingpolicies

reports: ## Wait for Kyverno PolicyReports in demo and summarize them (async!)
	KUBE_CONTEXT=$(KUBE_CONTEXT) NAMESPACE=$(NAMESPACE) bash scripts/policy-reports.sh

verify-admission: ## Prove Kyverno alone blocks bad pods (namespace without PSA)
	KUBE_CONTEXT=$(KUBE_CONTEXT) bash scripts/verify-admission.sh

kyverno: ## Install/upgrade Kyverno (admission policy engine) via Helm
	$(HELM) repo add kyverno https://kyverno.github.io/kyverno/ --force-update >/dev/null
	@# upgrade --install: the same command installs or upgrades (idempotent).
	@# --version pins the chart; without it Helm takes whatever is newest.
	$(HELM) upgrade --install kyverno kyverno/kyverno \
	  --version $(KYVERNO_CHART_VERSION) \
	  --namespace kyverno --create-namespace \
	  --values cluster/kyverno/values.yaml \
	  --wait --timeout 5m
	$(KUBECTL) -n kyverno get deploy

falco: ## Install/upgrade Falco (runtime detection, modern eBPF) via Helm
	$(HELM) repo add falcosecurity https://falcosecurity.github.io/charts --force-update >/dev/null
	$(HELM) upgrade --install falco falcosecurity/falco \
	  --version $(FALCO_CHART_VERSION) \
	  --namespace falco --create-namespace \
	  --values cluster/falco/values.yaml \
	  --set-file 'customRules.lab-rules\.yaml=detection/falco/lab-rules.yaml' \
	  --wait --timeout 10m
	@# Guard: leastPrivileged is false in values, so an empty
	@# containerSecurityContext would silently make Falco privileged.
	@sc=$$($(KUBECTL) -n falco get ds falco \
	  -o jsonpath='{.spec.template.spec.containers[?(@.name=="falco")].securityContext}'); \
	  echo "falco securityContext: $$sc"; \
	  case "$$sc" in *'"privileged":true'*) echo "ERROR: Falco runs privileged" >&2; exit 1;; esac
	$(KUBECTL) -n falco get pods -o wide

verify-detection: ## Trigger scenarios 1-5 and check the custom Falco rules fire (or stay silent)
	KUBE_CONTEXT=$(KUBE_CONTEXT) NAMESPACE=$(NAMESPACE) bash scripts/verify-detection.sh

falco-logs: ## Follow Falco alerts from all nodes (Ctrl+C to stop)
	$(KUBECTL) -n falco logs -f -l app.kubernetes.io/name=falco -c falco --max-log-requests 5 --prefix

build: ## Build the API image
	@# --provenance=false: BuildKit would attach a provenance attestation with
	@# timestamps, so even a fully cached rebuild got a new index digest. kind
	@# has no registry to keep attestations in; without them an unchanged
	@# build keeps its digest, and the digest pinned by "make hardened" is
	@# stable. (A CI build that pushes to a registry should keep them - Phase 6.)
	docker build --provenance=false -t $(API_IMAGE) app/api

load: build ## Copy the API image into the kind nodes (no registry needed)
	kind load docker-image $(API_IMAGE) --name $(CLUSTER_NAME)

base: load ## Deploy the plain base app (no misconfigs, no defenses)
	$(KUBECTL) apply -k k8s/base
	$(KUBECTL) -n $(NAMESPACE) rollout status deploy/db deploy/api deploy/web --timeout=180s

# Each overlay is deployed into a FRESH namespace. "kubectl apply" never deletes
# objects that disappeared from the manifests, so switching overlays in place
# would leave e.g. a vulnerable RoleBinding behind (or a hardened
# NetworkPolicy), and the scenario results would lie.
vulnerable: load undeploy ## Deploy the VULNERABLE overlay (clean namespace)
	@# Scenario 6: the vulnerable overlay runs the api by the mutable tag
	@# "latest". Point it at the image just built, on every node.
	docker tag $(API_IMAGE) $(API_IMAGE_LATEST)
	kind load docker-image $(API_IMAGE_LATEST) --name $(CLUSTER_NAME)
	$(KUBECTL) apply -k k8s/overlays/vulnerable
	$(KUBECTL) -n $(NAMESPACE) rollout status deploy/db deploy/api deploy/web --timeout=180s

hardened: load undeploy ## Deploy the HARDENED overlay (clean namespace)
	@# Scenario 6: every image pinned by digest. The api digest is only
	@# known after the build, so it is filled in at render time.
	KUBE_CONTEXT=$(KUBE_CONTEXT) CLUSTER_NAME=$(CLUSTER_NAME) API_IMAGE=$(API_IMAGE) \
	  bash scripts/render-pinned.sh k8s/overlays/hardened | $(KUBECTL) apply -f -
	$(KUBECTL) -n $(NAMESPACE) rollout status deploy/db deploy/api deploy/web --timeout=180s

scenario-%: ## Run attack demo N, e.g. make scenario-1
	KUBE_CONTEXT=$(KUBE_CONTEXT) NAMESPACE=$(NAMESPACE) bash scenarios/0$*-*/run.sh

verify-%: ## Check scenario N: exit 0 exploitable, 1 blocked, 2 inconclusive
	KUBE_CONTEXT=$(KUBE_CONTEXT) NAMESPACE=$(NAMESPACE) bash scenarios/0$*-*/verify.sh

verify-all: ## Table of all scenario results for the deployed overlay
	KUBE_CONTEXT=$(KUBE_CONTEXT) NAMESPACE=$(NAMESPACE) bash scripts/verify-all.sh

smoke: ## End-to-end check: web -> api -> db
	KUBE_CONTEXT=$(KUBE_CONTEXT) NAMESPACE=$(NAMESPACE) bash scripts/smoke.sh

port-forward: ## Open the app at http://localhost:8080 (Ctrl+C to stop)
	$(KUBECTL) -n $(NAMESPACE) port-forward svc/web 8080:8080

undeploy: ## Remove the app (deleting the namespace removes everything in it)
	$(KUBECTL) delete namespace $(NAMESPACE) --ignore-not-found --wait=true

cluster-delete: ## Delete the kind cluster
	kind delete cluster --name $(CLUSTER_NAME)
