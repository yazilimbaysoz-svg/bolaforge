# Security policy — bolaforge

**Baysöz Labs** <baysozlabs@proton.me>

## Supported use

`bolaforge` is an authorized security-testing tool for APIs you own or are contractually permitted to test.
The generated cases are adversarial by design; obtain written authorization before executing them against
any target.

## Threat model and mitigations

| Threat | Mitigation |
| --- | --- |
| Malicious OpenAPI `$ref` to external URL or file | Only local `#/...` pointers are resolved; external refs are rejected. |
| Recursive `$ref` entity expansion | Depth cap (32) and per-chain cycle containment with a `$refCycle` marker. |
| YAML alias/tag/anchor attacks | Safe subset parser rejects anchors, aliases, custom tags, directives, tabs, duplicate keys and multiple documents. |
| Oversized input (memory exhaustion) | 4 MiB document and 200,000 line limits. |
| Policy as code execution | Policies are pure data; condition operators are a fixed allowlist; no evaluation of expressions. |
| Secret leakage | No credential values are read or emitted; plans contain actor *ids* only. Error messages do not include file contents. |
| Output path confusion | Output directories must already exist; no output path is derived from untrusted spec fields. |
| Non-reproducible evidence | Deterministic ordering, canonical digests, stable case ids, no clock or randomness. |

## Reporting vulnerabilities

Email **baysozlabs@proton.me** with a description, reproduction steps and impact. Please do not open a
public issue for an unpatched vulnerability. Include the `bolaforge --version` output and the SHA-256
spec/policy digests from the plan.

## Hardening checklist for operators

- Run audits on untrusted specs in a sandbox with no network egress.
- Treat `plan.json` as sensitive: it describes authorization structure and ownership identifiers.
- Use `--fail-on` in CI and commit the SARIF artifact; fingerprints are stable across runs.
- Verify executed results with `bolaforge verify` before claiming a finding is confirmed.

*Baysöz Labs <baysozlabs@proton.me>*
