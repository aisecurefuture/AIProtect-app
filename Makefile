PY ?= python3

.PHONY: help test verify-seams verify-consumer-scope verify-consumer-scope-selftest \
        verify-artifact-imports projection up down check

help:
	@echo "AIProtect"
	@echo ""
	@echo "  make check                  everything below, in order"
	@echo "  make test                   detection test suite"
	@echo "  make verify-seams           prove the two library seams still hold"
	@echo "  make verify-consumer-scope  no tenant_id in apps/"
	@echo "  make projection             what the consumer profile costs and saves"
	@echo "  make up / make down         run the detection stack"

# Everything a change should have to survive.
check: verify-consumer-scope-selftest verify-consumer-scope verify-seams test

test:
	$(PY) -m pytest services/detection/tests/ -q

# The two seams this product is built on. Standalone -- no services, no
# network, no docker. If either stops holding, the architecture changed and
# somebody should know before the next feature lands on top of it.
verify-seams:
	$(PY) spikes/spike_policy_engine.py
	$(PY) spikes/spike_core_tenant_free.py

# AIProtect has accounts and devices, not tenants.
verify-consumer-scope:
	$(PY) scripts/ci/check_consumer_scope.py

# A checker nobody has seen fail has not been shown to be able to fail.
verify-consumer-scope-selftest:
	$(PY) scripts/ci/check_consumer_scope.py --self-test

# What the consumer profile costs and saves. Every figure is labelled
# [MEASURED] or [PROJECTED]; pass --url to measure a running service.
projection:
	$(PY) scripts/diagnostics/what_the_consumer_profile_saves.py

up:
	docker compose -f infra/docker-compose.yml up -d

down:
	docker compose -f infra/docker-compose.yml down
