"""SARIF emission, plan round-trip and verification tests.

Baysöz Labs <baysozlabs@proton.me>
"""

from bolaforge.analyze import build_findings, extract_operations
from bolaforge.attribution import ATTRIBUTION
from bolaforge.generate import generate_cases
from bolaforge.models import AttackPlan
from bolaforge.policy import AuthorizationPolicy, load_fixtures
from bolaforge.render import PLAN_SCHEMA_VERSION, load_plan, render_text, write_json
from bolaforge.sarif import build_sarif
from bolaforge.spec import load_spec
from bolaforge.verify import verify_plan


def _plan(tmp_path):
    spec = load_spec("examples/openapi.json")
    policy = AuthorizationPolicy.load("examples/policy.json")
    actors, objects = load_fixtures("examples/fixtures.json")
    operations = extract_operations(spec.document)
    findings = build_findings(operations, policy, actors, objects)
    cases, truncated = generate_cases(operations, actors, objects, policy)
    return AttackPlan(
        schema_version=PLAN_SCHEMA_VERSION,
        attribution=ATTRIBUTION,
        spec=spec.source,
        spec_digest=spec.digest,
        policy_digest=policy.digest,
        operations=operations,
        actors=actors,
        objects=objects,
        cases=cases,
        findings=findings,
        truncated=truncated,
    ), tmp_path


def test_sarif_structure() -> None:
    plan, _ = _plan(None)
    sarif = build_sarif(plan, plan.spec)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "bolaforge"
    assert ATTRIBUTION in run["tool"]["driver"]["fullName"]
    assert len(run["results"]) == len(plan.findings)
    assert {item["ruleId"] for item in run["results"]} == {item.rule_id for item in plan.findings}
    assert all(item["partialFingerprints"]["bolaforge/v1"] for item in run["results"])


def test_plan_round_trip(tmp_path) -> None:
    plan, folder = _plan(tmp_path)
    path = folder / "plan.json"
    write_json(path, plan.to_dict())
    loaded = load_plan(path)
    assert loaded.to_dict() == plan.to_dict()
    text = render_text(loaded, loaded.spec)
    assert ATTRIBUTION in text
    assert "Adversarial cases" in text


def test_verify_verdicts(tmp_path) -> None:
    plan, _ = _plan(tmp_path)
    deny_case = next(case for case in plan.cases if case.expected.value == "DENY")
    allow_case = next(case for case in plan.cases if case.expected.value == "ALLOW")
    results = [
        {"case_id": deny_case.id, "status": 403, "evidence": "denied"},
        {"case_id": allow_case.id, "status": 200, "evidence": "allowed"},
        {"case_id": "unknown", "status": 200, "evidence": ""},
    ]
    report = verify_plan(plan, results)
    assert report["passed"] is False
    assert report["summary"]["UNKNOWN_CASE"] == 1
    assert report["summary"]["NOT_EXECUTED"] == len(plan.cases) - 2
    assert report["summary"]["ENFORCED"] >= 1
    assert ATTRIBUTION == report["attribution"]

    full = [
        {
            "case_id": case.id,
            "status": 403 if case.expected.value == "DENY" else 200,
            "evidence": "live",
        }
        for case in plan.cases
    ]
    assert verify_plan(plan, full)["passed"] is True
    compromised = [*full[:-1], {**full[-1], "status": 200}]
    breached = verify_plan(plan, compromised)
    assert breached["passed"] is False
    assert "BOLA_CONFIRMED" in breached["summary"] or "POLICY_MISMATCH" in breached["summary"]
