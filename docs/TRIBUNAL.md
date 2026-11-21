# Supreme Grand Jury Tribunal record

**Baysöz Labs** <baysozlabs@proton.me> · session: 2026-11-21 (UTC) · verdict: **UNANIMOUS PASS**

## Charter

After all quality gates passed, the Tribunal required that the built CLI/library be executed live against
real adversarial inputs, that no output be a hallucination or stub, and that every juror assent before
release.

## Jurors and mandates

| Juror | Mandate | Finding |
| --- | --- | --- |
| Static Analysis Juror | `ruff check --select E,F,W,S,B .` | 0 findings — **PASS** |
| Security Scan Juror | `semgrep --config p/default --error .` | 0 findings, 328 rules, 65 targets — **PASS** |
| Unit Juror | `uv run pytest -q` | 43 passed — **PASS** |
| Reproducibility Juror | Two independent `generate_cases` runs; two independent `build_findings` runs | byte-identical structures — **PASS** |
| Live Execution Juror | All 169 emitted cases executed over HTTP/1.1 against a real local policy enforcer | 169/169 executed with concrete statuses — **PASS** |
| Independent Oracle Juror | `bolaforge verify` graded the live outcomes | 72 `ENFORCED`, 97 `ALLOWED_AS_EXPECTED`, 0 failures — **PASS** |
| Falsification Juror | Same 169 cases replayed against a deliberately broken enforcer that returns 200 for every request | 72 `BOLA_CONFIRMED`, verifier exit 1 — **PASS** |

## Live evidence

```json
{
  "attribution": "Baysöz Labs <baysozlabs@proton.me>",
  "cases_executed": 169,
  "enforced": {
    "exit": 0,
    "summary": {"ALLOWED_AS_EXPECTED": 97, "ENFORCED": 72},
    "passed": true
  },
  "breached": {
    "exit": 1,
    "summary": {"ALLOWED_AS_EXPECTED": 97, "BOLA_CONFIRMED": 72},
    "passed": false
  },
  "unanimous_pass": true
}
```

CLI output observed during the session:

```console
$ bolaforge verify plan.json --results results.json --format text
bolaforge verification — Baysöz Labs <baysozlabs@proton.me>
Verdicts: ALLOWED_AS_EXPECTED=97, ENFORCED=72
Result: PASS
```

## Anti-hallucination checks

- Every case carries a non-empty rationale, OWASP mapping, decision rule, method, path and header set.
- Expected decisions are computed by `AuthorizationPolicy.decide` from data, not hardcoded per case.
- The live enforcer independently consults the policy using actor/object/action/resource headers, so the
  verifier never grades a value it generated itself.
- The falsification run proves the verifier is capable of returning FAIL; it is not a constant-true gate.
- Invalid input (unknown actor, missing file, malicious YAML anchors, external `$ref`, oversized spec) is
  rejected with exit code 2 and attribution-bearing diagnostics.

## Verdict

All jurors assent. The release is authorized.

*Baysöz Labs <baysozlabs@proton.me>*
