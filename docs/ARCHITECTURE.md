# Architecture — bolaforge

**Baysöz Labs** <baysozlabs@proton.me>

## Pipeline

```text
          ┌─────────────────────────── offline, deterministic ───────────────────────────┐
          │                                                                              │
spec ──► spec.load_spec ──► resolve_refs ──► analyze.extract_operations ──┬──► build_findings ──► sarif.build_sarif
(JSON /                    (local only,      (method, path, resource,      │      (BOLA001-007)       (SARIF 2.1.0)
 safe YAML)                 cycle-safe)       refs, security, body)        │
                                                                          └──► generate_cases ──► policy.decide ──► plan.json
policy ──► AuthorizationPolicy.load ─────────────────────────────────────────────────────────────┘
fixtures ─► load_fixtures (actors + owned objects)

plan.json + executed HTTP results ──► verify.verify_plan ──► verdicts + PASS/FAIL exit code
```

## Modules

| Module | Responsibility | Key entry points |
| --- | --- | --- |
| `attribution.py` | Canonical attribution constants used by every artifact and CLI surface. | `ATTRIBUTION`, `EMAIL`, `REPOSITORY` |
| `_yaml.py` | Bounded safe-YAML subset: block maps/sequences, flow collections, quoted/plain scalars, comments, block scalars. Rejects anchors, aliases, tags, directives, tabs, duplicate keys, multiple documents. | `loads` |
| `spec.py` | JSON/YAML detection, 4 MiB input cap, canonical SHA-256 digest, local `$ref` resolution with depth 32 and cycle containment, external-ref rejection. | `load_spec`, `resolve_refs`, `canonical_digest` |
| `models.py` | Frozen slotted dataclasses: `Operation`, `ObjectRef`, `Actor`, `ResourceObject`, `Decision`, `TestCase`, `Finding`, `AttackPlan`, `Severity`, `Effect`. | — |
| `analyze.py` | OpenAPI 3.1 operation normalization, object-reference heuristics, resource mapping (`x-bola-resource` override), 7 deterministic finding rules. | `extract_operations`, `build_findings`, `canonical_resource` |
| `policy.py` | Validated RBAC/ABAC oracle: scopes (`any`, `own`, `tenant`, `public`), conditions (`eq`, `ne`, `in`, `not_in`, `startswith`, `exists`), deny-overrides, priority then declaration order, fixtures loader. | `AuthorizationPolicy.decide`, `load_fixtures` |
| `generate.py` | 14 adversarial techniques, deterministic stable case IDs (SHA-256 prefix), OWASP mapping, case-budget cap, no randomness or clock. | `generate_cases`, `ActorPool` |
| `sarif.py` | SARIF 2.1.0 rules/results with logical locations, partial fingerprints and attribution. | `build_sarif` |
| `render.py` | Text renderer, strict plan/result deserialization, deterministic JSON writer. | `render_text`, `load_plan`, `load_results`, `write_json` |
| `verify.py` | Grading of real HTTP statuses against oracle expectations; includes coverage enforcement (`NOT_EXECUTED`). | `verify_plan`, `verify_files` |
| `cli.py` | `audit`, `verify`, `oracle`, `--version`, `--help`; exit codes 0/1/2. | `main` |

## Data contracts

`plan.json` is the portable hand-off between red-team planning and execution. Every case contains:

```json
{
  "id": "sha256-prefix",
  "technique": "CROSS_TENANT_REFERENCE",
  "operation_key": "GET /v1/accounts/{account_id}",
  "actor_id": "user-carol",
  "object_ref": "acct-alice",
  "action": "read",
  "expected": "DENY",
  "decision_rule": "POLICY-DEFAULT",
  "owasp": "API1:2023 Broken Object Level Authorization",
  "severity": "CRITICAL",
  "request": {"method": "GET", "path": "...", "headers": {}, "query": {}, "body": null}
}
```

Verification results are `{ "results": [ { "case_id": "...", "status": 403, "evidence": "..." } ] }`.
Every planned case must have a result; missing cases are reported as `NOT_EXECUTED` and fail the gate.

## Determinism

- Operations sorted by `METHOD path`; findings sorted by `(rule, operation, fingerprint)`; cases sorted by id.
- Case ids are SHA-256 seeds of operation + technique + actor + object + parameter.
- Digests use canonical JSON (sorted keys, compact separators, UTF-8, SHA-256).
- No `random`, no `datetime`, no environment-dependent paths, no network calls.

## Security boundaries

- Untrusted specs cannot cause network/file access via `$ref`; external references are rejected.
- Untrusted YAML cannot use anchors/aliases/tags (entity expansion / object construction); size and depth
  are capped.
- Policies are data, not code: no expression evaluation, no imports, no dynamic dispatch.
- Output writes require an existing directory; no path is derived from untrusted spec content.
- No credentials are read, stored or logged; only actor *identifiers* appear in plans.

## Extending

Add a technique in `generate.generate_cases` using the `emit(...)` helper, add an OWASP constant, a test in
`tests/test_generate.py`, and a rule description in `docs/MARKET_RESEARCH.md`. Add a spec finding by
extending `build_findings` and the `_RULE_METADATA` map in `sarif.py`.

*Baysöz Labs <baysozlabs@proton.me>*
