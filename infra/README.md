# aiprotect/infra — B2C deployment

**Status:** not built. Populated by Prompts 1–2.

## The isolation guarantee lives here

Consumer traffic must **never** share instances with the paying B2B pilot. This
is the whole reason a monorepo is safe: isolation comes from separate
deployments, not from separate repositories.

Deploy from here:
- `services/detection` running the **consumer profile**
  (`docker-compose.consumer.yml`) — bart-large-mnli and `obi/deid_roberta_i2b2`
  dropped, `OLLAMA_ENABLED=false`, `CYBERARMOR_PROMPTWARE_SESSION_ENABLED=false`,
  cache on, rate limit on. Projected **~2.2 GiB and ~0.89 s/scan** versus the
  B2B profile's measured 5.24 GiB and ~3.58 s/scan — 2.3× memory, 4.1× latency.
  Reproduce with `scripts/diagnostics/what_the_consumer_profile_saves.py`.
- `services/url-trust-gate` with the consumer verdict mapping.
- `aiprotect/api`, `aiprotect/web`.

Any container running the policy engine must `COPY shared/policy-fields.json` —
`policy_fields.py` reads it off disk at import time and the import fails
without it.

## Why the consumer profile is mandatory, not an optimization
The B2B detection config costs roughly 14 core-seconds per scan with no result
caching and no rate limiting. A free consumer tier on that config is both
financially unviable and trivially DoS-able. Content-hash result caching is the
single highest-leverage change — scans are pure functions of their input text.
