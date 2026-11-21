# Changelog

All notable changes to bolaforge are documented here.

**Baysöz Labs** <baysozlabs@proton.me>

## [1.0.0] — 2026-11-21

### Added

- OpenAPI 3.1 JSON and safe-YAML ingestion with local `$ref` resolution and cycle containment.
- `analyze` module with 7 specification-level BOLA findings (BOLA001–BOLA007).
- Deterministic RBAC/ABAC authorization oracle with scopes, conditions, deny-overrides and priorities.
- 14 adversarial techniques (cross-tenant, horizontal/vertical IDOR, enumeration, parameter pollution,
  method override, path variance, mass assignment, content-type confusion, proxy spoofing, bulk scrape,
  nested parent confusion).
- SARIF 2.1.0 output with stable partial fingerprints and CI severity gating (`--fail-on`).
- `audit`, `verify` and `oracle` CLI commands; attribution in `--version`, `--help` and all artifacts.
- Strict fixture, policy, plan and result validation; 4 MiB input cap; no network or dynamic evaluation.
- CI workflow, market research, architecture, security policy and Tribunal record.

### Verified

- 43 tests passing; `ruff check --select E,F,W,S,B .` clean; `semgrep --config p/default --error .` clean.
- Tribunal: 169 live adversarial cases, honest run PASS, falsification run detected 72 BOLA confirmations.

*Baysöz Labs <baysozlabs@proton.me>*
