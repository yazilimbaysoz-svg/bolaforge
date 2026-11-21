"""SARIF 2.1.0 emission for specification-level authorization findings.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from typing import Any

from .attribution import ATTRIBUTION, REPOSITORY
from .models import AttackPlan, Severity

_RULE_METADATA: dict[str, tuple[str, str]] = {
    "BOLA001": (
        "ObjectScopedOperationLacksSecurity",
        "An object-scoped operation declares no security requirement.",
    ),
    "BOLA002": (
        "ObjectScopedOperationExplicitlyPublic",
        "An object-scoped operation explicitly disables security.",
    ),
    "BOLA003": (
        "UnconstrainedObjectIdentifier",
        "An object identifier has no format or pattern constraint.",
    ),
    "BOLA004": (
        "EnumeratableObjectQuery",
        "An object query lacks a documented rate limit.",
    ),
    "BOLA005": (
        "OwnershipFieldInRequestBody",
        "A writable operation accepts client-controlled ownership fields.",
    ),
    "BOLA006": (
        "AnonymousObjectAccessAllowed",
        "The policy allows anonymous access to an object-scoped action.",
    ),
    "BOLA007": (
        "UnmappedAuthorizationResource",
        "No policy resource mapping exists for an object-scoped operation.",
    ),
}

_LEVELS = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def build_sarif(plan: AttackPlan, spec_uri: str) -> dict[str, Any]:
    """Render findings as a deterministic, tool-readable SARIF document."""

    used_rules = sorted({finding.rule_id for finding in plan.findings})
    rules = []
    for rule_id in used_rules:
        name, description = _RULE_METADATA.get(
            rule_id, ("AuthorizationFinding", "An authorization weakness was detected.")
        )
        rules.append(
            {
                "id": rule_id,
                "name": name,
                "shortDescription": {"text": description},
                "helpUri": f"{REPOSITORY}#rule-{rule_id.lower()}",
                "defaultConfiguration": {"level": "warning"},
                "properties": {"attribution": ATTRIBUTION},
            }
        )
    results = []
    for finding in sorted(plan.findings, key=lambda item: (item.rule_id, item.operation_key)):
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _LEVELS[finding.severity],
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": spec_uri},
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [
                            {"fullyQualifiedName": finding.operation_key, "kind": "operation"}
                        ],
                    }
                ],
                "partialFingerprints": {"bolaforge/v1": finding.fingerprint},
                "properties": {
                    "severity": finding.severity.value,
                    "recommendation": finding.recommendation,
                    "attribution": ATTRIBUTION,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "bolaforge",
                        "version": plan.schema_version,
                        "fullName": f"bolaforge by {ATTRIBUTION}",
                        "informationUri": REPOSITORY,
                        "rules": rules,
                        "properties": {"attribution": ATTRIBUTION},
                    }
                },
                "results": results,
                "properties": {
                    "attribution": ATTRIBUTION,
                    "spec_digest": plan.spec_digest,
                    "policy_digest": plan.policy_digest,
                    "test_cases": len(plan.cases),
                },
            }
        ],
    }
