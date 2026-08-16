# CyberArmor Detection Service

Content inspection service used by proxy, dashboard scan tools, and extensions.
ML-based edition: all models run fully locally in-process (no external LLM/API
dependency). Model downloads are cached; set `TRANSFORMERS_OFFLINE=1` after
initial download to prevent any Hugging Face network access.

Detection pipeline (in priority order):
1. Adversarial text normalisation (Unicode, zero-width chars, homoglyphs, base64/hex decode)
2. Prompt injection — ML primary (`protectai/deberta-v3-base-prompt-injection-v2`) + heuristic ensemble + optional legacy regex compat mode
3. Promptware session tracker (multi-turn attack-chain correlation)
4. Sensitive data / DLP — NER primary (`dslim/bert-base-NER`) + regex catalog + semantic vector DLP
5. Output safety — zero-shot classifier (`facebook/bart-large-mnli`) + regex for known dangerous patterns
6. Toxicity — `unitary/toxic-bert`
7. Ollama LLM judge — optional second-pass for high-ambiguity / high-risk inputs

## Endpoints
- `GET /health`
- `GET /ready`
- `GET /metrics`
- `GET /pki/public-key`
- `POST /scan` (proxy-compatible full scan)
- `POST /scan/prompt-injection`
- `POST /scan/promptware`
- `POST /scan/sensitive-data`
- `POST /scan/output-safety`
- `POST /scan/toxicity`
- `POST /scan/redact` (redact requested DLP classes from text)
- `GET /scan/redact/targets` (client-facing redact class catalog for the Policy Builder)
- `POST /scan/all`

## Auth
All scan endpoints require header `x-api-key` matching `DETECTION_API_SECRET`.

## Run locally
```bash
pip install fastapi uvicorn[standard] pydantic
uvicorn main:app --host 0.0.0.0 --port 8002
```

## Environment
- `DETECTION_API_SECRET` (default `change-me-detection`)
- `PROMPT_INJECTION_MODEL_THRESHOLD` (default `0.62`)
- `PROMPT_INJECTION_ENSEMBLE_THRESHOLD` (default `0.66`)
- `PROMPT_INJECTION_RISK_BASE` (default `0.32`)
- `PROMPT_INJECTION_RISK_MULTIPLIER` (default `0.85`)
- `PROMPT_INJECTION_RISK_CAP` (default `0.85`)
- `SEMANTIC_DLP_THRESHOLD` (default `0.62`)
- `CYBERARMOR_PROMPTWARE_SESSION_ENABLED` (default `true`)
- `PROMPTWARE_SESSION_WINDOW_SECONDS` (default `1800`)
- `PROMPTWARE_SESSION_MAX_EVENTS` (default `20`)
- `PROMPTWARE_CHAIN_WARN_THRESHOLD` (default `0.55`)
- `PROMPTWARE_CHAIN_BLOCK_THRESHOLD` (default `0.85`)
- `CYBERARMOR_ENABLE_LEGACY_PROMPT_REGEX` (default `false`; optional compatibility mode)
- `OLLAMA_ENABLED` / `OLLAMA_BASE_URL` / `OLLAMA_MODEL` / `OLLAMA_TIMEOUT_SECONDS` / `OLLAMA_JUDGE_RISK_TRIGGER` (optional local LLM judge)
- `ML_PROMPT_INJECTION_THRESHOLD`, `ML_NER_PII_MODEL`, `ML_NER_CONFIDENCE_THRESHOLD`, `ML_TOXICITY_MODEL`, `ML_TOXICITY_THRESHOLD`, `ML_ZERO_SHOT_MODEL`, `ML_ZERO_SHOT_THRESHOLD` (model overrides; see `ml_models.py`)
- `CYBERARMOR_DETECTION_DL_STATES` (default empty)
  - Opt-in list of US state driver's license formats to detect as structured
    patterns. Comma-separated. Recognised: `CA` (1 letter + 7 digits — letter
    prefix gives moderate signal), `TX` (8 bare digits — collides with order
    numbers / account IDs), `NY` (9 bare digits — collides with SSN / EIN /
    routing candidates).
  - Default (empty) keeps DL detection contextual-only plus the always-on
    MD/FL `L#### #### ####` form. Enable per-state when a known regional
    customer base needs bare-format detection; expect higher false-positive
    volume for `TX`/`NY`. `TX`/`NY` findings are emitted at severity `low`,
    `CA` at `medium`.

## Prompt-injection detection model
- Prompt-injection detection uses a local transformer classifier
  (`protectai/deberta-v3-base-prompt-injection-v2`) instead of regex-only matching.
- The model runs fully in-process with no external LLM/API dependency.
- Input is adversarially normalized before scoring (Unicode normalization, homoglyph folding, zero-width stripping, encoded-segment expansion).
- Ensemble detection combines model confidence with heuristic attack signals (override/exfil/indirect/tool-injection cues).
- Legacy regex matching can be enabled only as optional compatibility fallback.
- Session-aware promptware correlation detects multi-turn attack chains and emits `promptware_attack_chain` findings.
- Provide `session_id` on scan requests for best correlation fidelity.
- `POST /scan/promptware` returns:
- current detections for the request
- per-session chain state (`event_count`, `chain_confidence`, indicator mix)
- whether a chain detection was triggered on the current turn

## Output safety coverage
- Zero-shot ML classifier primary, regex fallback.
- Detects command-execution patterns (`rm -rf`, `curl | bash`, `powershell -enc`).
- Detects script/XSS-style payload patterns (`<script>...</script>`, event handlers like `onerror=`, `javascript:` URLs, common browser data exfil sinks such as `document.cookie` / storage reads).
- Detects dangerous generated-code combinations (`dangerous_code_generation`), specifically the ransomware pattern of file-walk + encrypt + delete-original behavior that generic harmful-content classifiers miss.

## Sensitive data coverage
- NER model (`dslim/bert-base-NER`) is the primary PII detector; 6 NER classes (person name, location, organization, IP address, URL, crypto address).
- Structured regex catalog as complementary/fallback signal: SSN, EIN, driver's license, passport, ABA routing number, date of birth, credit card, AWS key, GCP API key, GitHub token, OpenAI/Anthropic/Slack/Stripe keys, generic API key, password field, private key — plus contextual (label-aware) matchers for SSN/EIN/DL/passport/routing/DOB.
- Semantic DLP detections using local embedding similarity against sensitive concept prototypes.
- Entity-aware DLP detection for common high-risk entities (email, phone, IBAN, JWT/token-like values, API-key-like patterns).
- Exfil-intent detection for semantic patterns indicating data export/leak behavior.
- Client-facing redact class vocabulary (`pii.*` / `secret.*`, see `GET /scan/redact/targets`) maps these detectors to the `redact_classes` field policies use for the first-class redact action.

_Last verified against code: 2026-07-27._
