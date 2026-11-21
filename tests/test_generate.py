"""Adversarial case generation tests.

Baysöz Labs <baysozlabs@proton.me>
"""

from bolaforge.analyze import extract_operations
from bolaforge.generate import generate_cases
from bolaforge.models import Effect, Severity
from bolaforge.policy import AuthorizationPolicy, load_fixtures
from bolaforge.spec import load_spec


def _context():
    spec = load_spec("examples/openapi.json")
    policy = AuthorizationPolicy.load("examples/policy.json")
    actors, objects = load_fixtures("examples/fixtures.json")
    operations = extract_operations(spec.document)
    return operations, actors, objects, policy


def test_generation_is_deterministic_and_complete() -> None:
    operations, actors, objects, policy = _context()
    first, first_truncated = generate_cases(operations, actors, objects, policy)
    second, second_truncated = generate_cases(operations, actors, objects, policy)
    assert first == second
    assert first_truncated is second_truncated is False
    assert len(first) > 100
    assert len({case.id for case in first}) == len(first)
    techniques = {case.technique for case in first}
    assert {
        "UNAUTHENTICATED_ACCESS",
        "CROSS_TENANT_REFERENCE",
        "HORIZONTAL_IDOR",
        "VERTICAL_PRIVILEGE_ESCALATION",
        "SEQUENTIAL_ID_ENUMERATION",
        "DUPLICATE_PARAMETER_POLLUTION",
        "METHOD_OVERRIDE_BYPASS",
        "PATH_CASE_VARIATION",
        "TRAILING_SLASH_BYPASS",
        "MASS_ASSIGNMENT_OWNERSHIP",
        "CONTENT_TYPE_CONFUSION",
        "PROXY_HEADER_SPOOFING",
        "BULK_ID_SCRAPE",
        "NESTED_PARENT_CONFUSION",
    } <= techniques
    for case in first:
        assert case.rationale and case.owasp and case.decision_rule
        assert case.request["method"] == case.method
        assert case.request["path"]
        assert isinstance(case.request["headers"], dict)
        assert case.id and case.expected in {Effect.ALLOW, Effect.DENY}


def test_cross_tenant_and_horizontal_cases_are_realistic() -> None:
    operations, actors, objects, policy = _context()
    cases, _ = generate_cases(operations, actors, objects, policy)
    cross = next(case for case in cases if case.technique == "CROSS_TENANT_REFERENCE")
    assert cross.actor_id != cross.object_ref
    assert cross.expected is Effect.DENY
    peer = next(
        case
        for case in cases
        if case.technique == "HORIZONTAL_IDOR"
        and case.object_ref == "acct-alice"
        and case.operation_key == "GET /v1/accounts/{account_id}"
    )
    assert peer.decision_rule == "accounts-tenant-read"
    assert peer.severity is Severity.CRITICAL


def test_case_budget_is_enforced() -> None:
    operations, actors, objects, policy = _context()
    cases, truncated = generate_cases(operations, actors, objects, policy, max_cases=5)
    assert len(cases) == 5 and truncated is True
    assert cases == generate_cases(operations, actors, objects, policy, max_cases=5)[0]
