"""OpenAPI operation analysis and finding-rule tests.

Baysöz Labs <baysozlabs@proton.me>
"""

from bolaforge.analyze import build_findings, canonical_resource, extract_operations
from bolaforge.models import Severity
from bolaforge.policy import AuthorizationPolicy, load_fixtures
from bolaforge.spec import load_spec


def test_canonical_resource() -> None:
    assert canonical_resource("Orders") == "order"
    assert canonical_resource("categories") == "category"
    assert canonical_resource("classes") == "class"
    assert canonical_resource("status") == "status"


def test_extract_operations_and_object_refs() -> None:
    spec = load_spec("examples/openapi.json")
    operations = extract_operations(spec.document)
    assert len(operations) == 6
    by_key = {item.key: item for item in operations}
    assert by_key["GET /v1/accounts/{account_id}"].resource == "accounts"
    assert by_key["GET /v1/users/{user_id}/documents/{document_id}"].resource == "documents"
    assert by_key["PATCH /v1/accounts/{account_id}"].security == ()
    assert by_key["PATCH /v1/accounts/{account_id}"].security_declared is True
    assert "owner_id" in by_key["POST /v1/accounts/{account_id}/transactions"].body_fields
    assert by_key["GET /v1/health"].has_object_ref is False
    assert all(
        item.schema_format == "uuid" for item in by_key["GET /v1/accounts/{account_id}"].object_refs
    )


def test_findings_cover_documented_rules() -> None:
    spec = load_spec("examples/openapi.json")
    operations = extract_operations(spec.document)
    policy = AuthorizationPolicy.load("examples/policy.json")
    actors, objects = load_fixtures("examples/fixtures.json")
    findings = build_findings(operations, policy, actors, objects)
    rules = {item.rule_id for item in findings}
    assert {"BOLA001", "BOLA002", "BOLA003", "BOLA004", "BOLA005"} <= rules
    assert any(item.severity is Severity.CRITICAL for item in findings)
    assert all(item.fingerprint for item in findings)
    assert findings == build_findings(operations, policy, actors, objects)


def test_anonymous_finding_appears_when_policy_allows_it() -> None:
    spec = load_spec("examples/openapi.json")
    operations = extract_operations(spec.document)
    policy = AuthorizationPolicy(
        {
            "version": "1.0",
            "resources": {
                "accounts": {
                    "rules": [{"effect": "allow", "roles": ["*"], "actions": ["*"], "scope": "any"}]
                }
            },
        }
    )
    actors, objects = load_fixtures("examples/fixtures.json")
    findings = build_findings(operations, policy, actors, objects)
    assert "BOLA006" in {item.rule_id for item in findings}
