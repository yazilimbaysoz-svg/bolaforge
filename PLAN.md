# Plan — bolaforge 1.0.0

**Baysöz Labs** <baysozlabs@proton.me>

## Phase 0 — Selection (done)

- Inspected `existing-repos.json` and excluded redundant domains (JOSE, Terraform IAM, OTel config,
  detection-rule parity, Actions lockfiles, cardinality, ReDoS, env drift, log masking).
- Mined live GitHub repositories/issues with `gh search` (see `docs/MARKET_RESEARCH.md`).
- Selected OWASP API Security BOLA/IDOR planning + independent oracle; Python 3.13, `uv`, stdlib only.

## Phase 1 — Contract & models (done)

- OpenAPI 3.1 ingestion: JSON and bounded safe-YAML subset; local `$ref` resolution with cycle containment.
- Frozen slotted domain models and canonical SHA-256 digests.

## Phase 2 — Analysis & oracle (done)

- Operation normalization, object-reference heuristics, `x-bola-resource` override, 7 finding rules.
- RBAC/ABAC policy engine with scopes, conditions, deny-overrides and deterministic tie-breaking.
- Strict actor/object fixture validation.

## Phase 3 — Adversarial compiler (done)

- 14 deterministic techniques mapped to OWASP API1/API3/API5/API6.
- Stable SHA-256 case ids, case budget, SARIF 2.1.0 emission, text/JSON renderers.
- `audit`, `verify`, `oracle`, `--version`, `--help` CLI surfaces with attribution.

## Phase 4 — Quality gates (done)

- `uv venv && uv pip install -e . && uv pip install pytest && uv run pytest -q` → 43 passed.
- `ruff check --select E,F,W,S,B .` → 0 findings.
- `semgrep --config p/default --error .` → 0 findings.

## Phase 5 — Supreme Grand Jury Tribunal (done)

- 169 live adversarial requests executed against a policy-enforcing HTTP server.
- Enforced run PASS; falsification run detected 72 BOLA confirmations.
- UNANIMOUS PASS recorded in `docs/TRIBUNAL.md`.

## Phase 6 — Release (done)

- Public repository under `yazilimbaysoz-svg`, MIT license, CI workflow, factory result artifact.

## Future work (not in 1.0.0)

- GraphQL operation extraction, gRPC reflection ingestion, differential WAF/proxy framing cases.
- Pluggable executors for Burp/ZAP session replay while keeping the offline oracle unchanged.

*Baysöz Labs <baysozlabs@proton.me>*
