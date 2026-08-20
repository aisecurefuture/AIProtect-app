PY ?= python3

.PHONY: help test test-web test-extension test-agent test-schema verify-seams \
        verify-consumer-scope verify-consumer-scope-selftest verify-prices \
        projection up down check

help:
	@echo "AIProtect"
	@echo ""
	@echo "  make check                  everything below, in order"
	@echo "  make test                   detection test suite"
	@echo "  make test-agent             the desktop agent carries no B2B names"
	@echo "  make test-schema            models.py and the migrations agree"
	@echo "  make verify-prices          Stripe charges what tiers.json promises"
	@echo "  make verify-seams           prove the two library seams still hold"
	@echo "  make verify-consumer-scope  no tenant_id in apps/"
	@echo "  make projection             what the consumer profile costs and saves"
	@echo "  make up / make down         run the detection stack"

# Everything a change should have to survive.
check: verify-consumer-scope-selftest verify-consumer-scope verify-seams test-schema test test-web test-extension test-agent

# EVERY service, not just detection. The first version of this target ran
# `services/detection/tests/` only, which is the same defect the product code
# is held to: a green result from a check that never covered what it claimed.
# The repo-root conftest.py is what makes a combined run safe -- without it the
# first suite to `import main` wins the name for the whole process and every
# later suite silently asserts against another service's module.
test:
	$(PY) -m pytest services/ apps/api/tests/ tests/ -q

# The two seams this product is built on. Standalone -- no services, no
# network, no docker. If either stops holding, the architecture changed and
# somebody should know before the next feature lands on top of it.
# The portal's job is to render what the services said WITHOUT flattening it.
# Every "checked and fine" vs "did not check" distinction the backend protects
# dies at one careless ternary in a component, and the backend cannot defend
# itself from the frontend -- so the mapping is tested.
test-web:
	cd apps/web && node --test --experimental-strip-types lib/*.test.ts

# The extension's two features fail in OPPOSITE directions on an outage --
# Safe Links open so browsing keeps working, Privacy Guard toward a warning so
# a password is not pasted in silence. Both are easy to ship backwards and
# neither shows up in manual testing, because manual testing has the API up.
test-extension:
	cd apps/extension && node --test tests/*.test.mjs

# The desktop agent is a fork of a ~49k-line B2B agent whose product name is
# written into service names, bundle ids, install paths and notification
# titles as string literals. Renaming by hand gets MOST of them; the ones it
# misses ship "/var/log/cyberarmor" to a consumer's Mac. The guard is
# mechanical so the port cannot regress it one module at a time.
test-agent:
	$(PY) apps/agent/tests/test_the_agent_carries_no_cyberarmor_identifiers.py

# models.py and the migrations must describe the same schema. Every other test
# builds its database straight from the models with create_all, so a model
# changed without a revision passes the entire suite -- and then a fresh deploy
# migrates to a table WITHOUT the column, starts, reports healthy, and fails on
# the first request that touches it.
test-schema:
	$(PY) apps/api/tests/test_the_schema_matches_the_migrations.py

# Does each configured Stripe price charge what its tier promises? The API
# already stops a CLIENT mismatching tier and price; this stops the six
# near-identical env vars doing it. Needs STRIPE_SECRET_KEY to check amounts;
# without one it still catches missing and duplicated ids, and says plainly
# that the amounts went unchecked. NOT in `make check` -- it is a deploy-time
# check against a live Stripe account, not a source-tree property.
verify-prices:
	$(PY) scripts/deployment/verify_stripe_prices.py

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
