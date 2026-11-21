"""Independent verification of executed adversarial cases against the oracle.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from typing import Any

from .attribution import ATTRIBUTION
from .models import AttackPlan, Effect
from .render import load_results

_ENFORCED_STATUSES = frozenset({401, 403})
_SUCCESS_STATUSES = frozenset(range(200, 300))
_FAILING_VERDICTS = frozenset({"BOLA_CONFIRMED", "POLICY_MISMATCH", "NOT_EXECUTED", "UNKNOWN_CASE"})


def verify_plan(plan: AttackPlan, results: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare real HTTP outcomes with the expected offline authorization decision."""

    by_id = {case.id: case for case in plan.cases}
    seen: set[str] = set()
    verdicts: list[dict[str, Any]] = []
    for result in results:
        case_id = result["case_id"]
        status = result["status"]
        if case_id not in by_id:
            verdict = "UNKNOWN_CASE"
            detail = "result refers to a case that is not present in the plan"
        else:
            seen.add(case_id)
            case = by_id[case_id]
            if case.expected is Effect.DENY:
                if status in _ENFORCED_STATUSES:
                    verdict = "ENFORCED"
                    detail = "authorization correctly rejected the adversarial request"
                elif status in _SUCCESS_STATUSES:
                    verdict = "BOLA_CONFIRMED"
                    detail = "oracle expected DENY but the target returned a success status"
                else:
                    verdict = "INCONCLUSIVE"
                    detail = "status code is neither a clear rejection nor a success"
            else:
                if status in _SUCCESS_STATUSES:
                    verdict = "ALLOWED_AS_EXPECTED"
                    detail = "target response matches the expected ALLOW decision"
                elif status in _ENFORCED_STATUSES:
                    verdict = "POLICY_MISMATCH"
                    detail = "oracle expected ALLOW but the target rejected the request"
                else:
                    verdict = "INCONCLUSIVE"
                    detail = "status code is neither a clear rejection nor a success"
        verdicts.append(
            {
                "case_id": case_id,
                "technique": by_id[case_id].technique if case_id in by_id else "UNKNOWN",
                "status": status,
                "verdict": verdict,
                "detail": detail,
                "evidence": result["evidence"],
            }
        )
    for case in plan.cases:
        if case.id not in seen:
            verdicts.append(
                {
                    "case_id": case.id,
                    "technique": case.technique,
                    "status": None,
                    "verdict": "NOT_EXECUTED",
                    "detail": "planned adversarial case has no executed result",
                    "evidence": "",
                }
            )
    verdicts.sort(key=lambda item: (item["verdict"], item["case_id"]))
    summary: dict[str, int] = {}
    for verdict in verdicts:
        summary[verdict["verdict"]] = summary.get(verdict["verdict"], 0) + 1
    passed = not any(item["verdict"] in _FAILING_VERDICTS for item in verdicts)
    return {
        "attribution": ATTRIBUTION,
        "schema_version": "1.0.0",
        "plan_digest": f"{plan.spec_digest}:{plan.policy_digest}",
        "summary": summary,
        "passed": passed,
        "verdicts": verdicts,
    }


def verify_files(plan_path: str, results_path: str) -> dict[str, Any]:
    """Load a plan and results from disk and verify them."""

    from .render import load_plan

    return verify_plan(load_plan(plan_path), load_results(results_path))
