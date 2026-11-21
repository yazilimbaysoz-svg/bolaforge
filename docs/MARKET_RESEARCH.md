# Market research — why bolaforge exists

**Baysöz Labs** <baysozlabs@proton.me> · research snapshot: 2026-11-21 (UTC)

## 1. Method

Evidence was mined live from GitHub with the CLI, not from memory:

```bash
gh search repos --topic appsec --topic security --sort stars --limit 20 \
  --json fullName,stargazersCount,description,updatedAt
gh search repos "api security testing" --sort stars --limit 20 \
  --json fullName,stargazersCount,description,updatedAt
gh search issues "BOLA authorization testing" --state open --sort reactions \
  --limit 20 --json title,repository,url,updatedAt
gh search repos --topic sbom --sort stars --limit 20 \
  --json fullName,stargazersCount,description,updatedAt
gh repo view KeygraphHQ/shannon --json stargazerCount,forkCount,description,updatedAt
gh repo view blst-security/cherrybomb --json stargazerCount,forkCount,description,updatedAt
```

Also inspected `/home/runner/work/_temp/existing-repos.json` to ensure the new project is not a
clone of an already-published Baysöz Labs tool.

## 2. Live signals (2026-11-21)

| Repository / issue | Observed signal | Interpretation |
| --- | --- | --- |
| `KeygraphHQ/shannon` | 52,166 stars, 6,109 forks, updated 2026-11-21 | Enormous demand for *proof-producing* automated web/API pentesting. It is an AI pentester: source analysis + real exploit execution. Requires models/infrastructure; unsuitable for a zero-service, deterministic CI gate. |
| `blst-security/cherrybomb` | 1,235 stars, 85 forks, updated 2026-11-20 | "Audit API specifications, validate them and run API security tests" — confirms spec-driven API security is a real category. It is a live-testing CLI with validation, not an offline deterministic authorization oracle with SARIF gating. |
| `Teycir/BurpAPISecuritySuite` | 381 stars, updated 2026-11-19 | Burp-only extension, 15 attack types, 108+ payloads, BOLA/IDOR detection, OWASP API Top 10. Interactive GUI workflow; cannot be a deterministic library/CI artifact and is coupled to a proxy. |
| `praetorian-inc/hadrian` | 78 stars, updated 2026-11-20 | REST/GraphQL/gRPC authorization testing via role-based YAML templates. Validates the role-based authorization testing niche but needs a live framework envelope. |
| `OWASP/www-project-api-security-testing-framework` | 161 stars, updated 2026-11-19 | OWASP is actively standardizing API security testing — strong tailwind for a tooling project that maps cases to API1/API3/API5/API6. |
| `OWASP/wstg` | 10,362 stars | Authoritative testing guide; BOLA/IDOR testing is a core chapter. Tooling that turns guidance into reproducible cases is useful. |
| `zaproxy/zaproxy` | 16,241 stars | DAST incumbents are heavyweight and session-oriented; they do not output a deterministic authorization oracle trace. |
| `Abraham12611/highcastle` issue 13 | "**Deterministic BOLA test pack and independent verification oracle**", open, updated 2026-11-06 | Direct market articulation of the exact gap: a *deterministic* pack plus an *independent verification oracle*. This is the product thesis. |
| SBOM/search cohort: `anchore/syft` 9,945, `DependencyTrack/dependency-track` 4,498, `owasp-dep-scan/dep-scan` 1,464 | updated 2026-11-21 | Supply-chain tooling is mature and crowded; adding another SBOM utility would be redundant, especially given the existing `baysoz-actionlock` repo. |

## 3. Gap analysis

1. **Determinism is absent.** Proxy extensions and AI pentesters are interactive, stochastic or dependent on
   live state. No stable artifact means no regression testing, no diffable CI gate, no reproducible evidence.
2. **The oracle is missing.** Most tools declare a finding but do not compute the *expected* authorization
   decision independently; a 200 response cannot be graded without a policy model.
3. **Spec-level and runtime-level checks are split.** Findings such as `security: []` on an object-scoped
   PATCH are cheap to detect from the contract, while cross-tenant access needs fixtures. Doing both in one
   deterministic pipeline is uncommon.
4. **Heavy runtime envelopes.** Go/Rust scanners exist, but the requested environment forbids heavy services
   and local LLMs. A zero-dependency Python 3.13 library/CLI is the correct fit.
5. **SARIF is table stakes for enterprise adoption.** Incumbent API tools mostly emit HTML/PDF; a SARIF
   2.1.0 stream with stable fingerprints plugs directly into GitHub code scanning.

## 4. Non-redundancy against existing Baysöz Labs repositories

`existing-repos.json` already contains `baysoz-josegate` (JOSE/JWT confusion), `planradius` (Terraform/IAM
SARIF gate), `baysoz-otelgate` (OTel Collector config), `atr-parity-gate` (detection-rule conformance),
`baysoz-actionlock` (Actions lockfile drift), `baysoz-cardinalis` (telemetry cardinality), `redos-lint`
(ReDoS), `envpair`/`envlens` (env drift), `baysoz-logmask` (log PII masking), `baysoz-zero-trust-engine`
(crypto/PII) and others. None models **object-level authorization decisions over an API contract with
ownership fixtures and executable adversarial request generation**. `bolaforge` occupies a distinct,
high-demand OWASP API Security niche.

## 5. Product decision

Build **`bolaforge` 1.0.0** in Python 3.13 (stdlib only, installed with `uv`):

- OpenAPI 3.1 ingestion with a safe YAML subset and local-`$ref` resolution (no network, no anchors/tags).
- 7 specification-level authorization rules → SARIF 2.1.0 with stable fingerprints and CI severity gating.
- 14 adversarial techniques derived deterministically from the contract, actors and object ownership.
- Independent RBAC/ABAC oracle (`deny` overrides `allow`, priority + declaration-order tie-break) that
  grades real HTTP outcomes into `ENFORCED`, `BOLA_CONFIRMED`, `POLICY_MISMATCH` or `INCONCLUSIVE`.
- No services, no agents, no local LLM, no randomness, no clock: identical inputs → identical outputs.

## 6. Success criteria

43 passing tests, `ruff check --select E,F,W,S,B .` clean, `semgrep --config p/default --error .` at zero
findings, and a live Tribunal run where 169 generated cases are executed against a policy-enforcing HTTP
server (PASS) and against a deliberately broken server (BOLA detected). See
[docs/TRIBUNAL.md](TRIBUNAL.md).

*Baysöz Labs <baysozlabs@proton.me>*
