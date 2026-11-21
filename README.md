# bolaforge

**Deterministic BOLA/IDOR adversarial test-plan compiler and offline authorization oracle for OpenAPI 3.1.**

Built by **Baysöz Labs** — <baysozlabs@proton.me>

[![CI](https://img.shields.io/badge/CI-passing-2E7D32?label=ci)](https://github.com/yazilimbaysoz-svg/bolaforge/actions)
[![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-3776AB)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-7C3AED)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-43%20passing-1B7F4B)](tests/)
[![Baysöz Labs](https://img.shields.io/badge/by-Bays%C3%B6z%20Labs-111827)](https://github.com/yazilimbaysoz-svg)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-0B7285)](docs/ARCHITECTURE.md)

`bolaforge` turns an OpenAPI 3.1 document plus an explicit authorization policy and ownership fixtures
into a stable, replayable matrix of broken-object-level-authorization (BOLA/IDOR) test requests. It then
verifies executed HTTP outcomes against an independent offline oracle — no services, no databases, no
local LLMs, no network access during analysis.

## Why it exists

API1:2023 (BOLA) remains the most exploited API weakness, but existing tooling is either interactive and
non-deterministic (proxies, AI pentesters) or needs a heavy stack. `bolaforge` is a pure Python 3.13
library/CLI that is deterministic enough for CI and explicit enough for a red-team engagement plan.
See [docs/MARKET_RESEARCH.md](docs/MARKET_RESEARCH.md) for the live ecosystem evidence.

## Install

```bash
uv venv
uv pip install -e .
uv pip install pytest        # development only
bolaforge --version
```

Runtime dependencies: **none** (Python 3.13 standard library only).

## Architecture

```text
OpenAPI 3.1 JSON/safe-YAML
        │  spec.load_spec → resolve_refs (local refs, cycle-safe)
        ▼
analyze.extract_operations  → normalized operations, object refs, security metadata
        │
        ├── build_findings  → BOLA001…BOLA007 → SARIF 2.1.0 + CI gate
        │
        └── generate_cases  → 14 adversarial techniques × actors × objects
                                      │
                                      ▼
                              policy.AuthorizationPolicy.decide
                              (RBAC + ABAC, deny-overrides, deterministic)
                                      │
                                      ▼
                                 plan.json ──► verify ──► PASS / BOLA_CONFIRMED
```

Module map: `spec.py` (ingestion), `_yaml.py` (safe YAML subset), `analyze.py` (extraction + rules),
`policy.py` (oracle + fixtures), `generate.py` (attack matrix), `sarif.py` (SARIF 2.1.0),
`render.py` (text/JSON), `verify.py` (independent verdicts), `cli.py` (commands).
Details in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Real CLI output

```console
$ bolaforge --version
bolaforge 1.0.0 — Baysöz Labs <baysozlabs@proton.me>

$ bolaforge audit examples/openapi.json \
    --policy examples/policy.json \
    --fixtures examples/fixtures.json --fail-on none
bolaforge 1.0.0 — Baysöz Labs <baysozlabs@proton.me>
Specification : examples/openapi.json
Digest        : a3cf46da0be6d70d
Operations    : 6
Object refs   : 9
Adversarial cases : 169
Findings      : CRITICAL 1 | HIGH 4 | MEDIUM 3 | LOW 1 | INFO 0

SPECIFICATION FINDINGS
  [HIGH    ] BOLA001 GET /v1/accounts/{account_id}: GET /v1/accounts/{account_id} accepts an object identifier but declares no security requirement.
  [HIGH    ] BOLA001 GET /v1/accounts/{account_id}/transactions: GET /v1/accounts/{account_id}/transactions accepts an object identifier but declares no security requirement.
  [HIGH    ] BOLA001 GET /v1/users/{user_id}/documents/{document_id}: GET /v1/users/{user_id}/documents/{document_id} accepts an object identifier but declares no security requirement.
  [HIGH    ] BOLA001 POST /v1/accounts/{account_id}/transactions: POST /v1/accounts/{account_id}/transactions accepts an object identifier but declares no security requirement.
  [CRITICAL] BOLA002 PATCH /v1/accounts/{account_id}: PATCH /v1/accounts/{account_id} sets security: [] while accepting an object identifier.
  [MEDIUM  ] BOLA003 GET /v1/users/{user_id}/documents/{document_id}: GET /v1/users/{user_id}/documents/{document_id} accepts unconstrained identifiers: document_id.
  [LOW     ] BOLA004 GET /v1/accounts/{account_id}/transactions: GET /v1/accounts/{account_id}/transactions filters by an object identifier without an x-ratelimit extension.
  [MEDIUM  ] BOLA005 PATCH /v1/accounts/{account_id}: PATCH /v1/accounts/{account_id} accepts ownership fields in its request body: owner_id.
  [MEDIUM  ] BOLA005 POST /v1/accounts/{account_id}/transactions: POST /v1/accounts/{account_id}/transactions accepts ownership fields in its request body: account_id, owner_id.

$ bolaforge oracle --policy examples/policy.json --fixtures examples/fixtures.json \
    --actor user-carol --object acct-alice --action read --resource accounts
{
  "action": "read",
  "actor": "user-carol",
  "attribution": "Baysöz Labs <baysozlabs@proton.me>",
  "effect": "DENY",
  "object": "acct-alice",
  "reason": "no rule matched; default is DENY",
  "rule_id": "POLICY-DEFAULT"
}

$ bolaforge verify plan.json --results results.json --format text
bolaforge verification — Baysöz Labs <baysozlabs@proton.me>
Verdicts: ALLOWED_AS_EXPECTED=97, ENFORCED=72
Result: PASS
```

## Commands

| Command | Purpose |
| --- | --- |
| `bolaforge audit SPEC --policy P --fixtures F [--out DIR] [--format text\|json\|sarif] [--fail-on LEVEL] [--max-cases N]` | Produce findings, SARIF and a deterministic test plan. |
| `bolaforge verify PLAN --results R [--format text\|json] [--out FILE]` | Independently grade executed HTTP outcomes against the oracle. |
| `bolaforge oracle --policy P --fixtures F --actor ID --object REF --action ACTION [--resource NAME]` | Explain one offline authorization decision. |
| `bolaforge --version`, `bolaforge --help` | Attribution-bearing version and help output. |

`--fail-on` accepts `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` or `none`; the audit exits `1` when a
finding meets or exceeds the threshold, `2` on invalid input, and `0` otherwise.

## Adversarial coverage

UNAUTHENTICATED_ACCESS, CROSS_TENANT_REFERENCE, HORIZONTAL_IDOR, VERTICAL_PRIVILEGE_ESCALATION,
SEQUENTIAL_ID_ENUMERATION, DUPLICATE_PARAMETER_POLLUTION, METHOD_OVERRIDE_BYPASS, PATH_CASE_VARIATION,
TRAILING_SLASH_BYPASS, MASS_ASSIGNMENT_OWNERSHIP, CONTENT_TYPE_CONFUSION, PROXY_HEADER_SPOOFING,
BULK_ID_SCRAPE and NESTED_PARENT_CONFUSION. Each case carries OWASP mapping, rationale, expected
decision and the originating policy rule.

## Quality gates

```bash
uv venv && uv pip install -e . && uv pip install pytest && uv run pytest -q
ruff check --select E,F,W,S,B .
semgrep --config p/default --error .
```

## Documentation

- [Market research](docs/MARKET_RESEARCH.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Supreme Grand Jury Tribunal record](docs/TRIBUNAL.md)
- [Plan](PLAN.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

## License & attribution

MIT. Copyright (c) 2026 **Baysöz Labs** <baysozlabs@proton.me>.
All files, artifacts and CLI output explicitly attribute Baysöz Labs.
