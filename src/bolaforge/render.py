"""Human-readable rendering, plan persistence and strict plan deserialization.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .attribution import ATTRIBUTION
from .errors import PlanError
from .models import (
    Actor,
    AttackPlan,
    Decision,
    Effect,
    Finding,
    ObjectRef,
    Operation,
    ResourceObject,
    Severity,
    TestCase,
)
from .spec import load_document, load_json_object

PLAN_SCHEMA_VERSION = "1.0.0"


def write_json(path: str | Path, payload: Any) -> None:
    """Write deterministic UTF-8 JSON with stable key ordering."""

    destination = Path(path)
    parent = destination.parent
    if parent and not parent.exists():
        raise PlanError(f"output directory {parent} does not exist")
    try:
        destination.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise PlanError(f"cannot write {destination}: {exc}") from exc


def _required(mapping: dict[str, Any], key: str, where: str) -> Any:
    if key not in mapping:
        raise PlanError(f"{where} is missing required field {key!r}")
    return mapping[key]


def _string(mapping: dict[str, Any], key: str, where: str) -> str:
    value = _required(mapping, key, where)
    if not isinstance(value, str):
        raise PlanError(f"{where}.{key} must be a string")
    return value


def _string_tuple(mapping: dict[str, Any], key: str, where: str) -> tuple[str, ...]:
    value = mapping.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PlanError(f"{where}.{key} must be a list of strings")
    return tuple(value)


def _actor_from(raw: Any, index: int) -> Actor:
    where = f"actors[{index}]"
    if not isinstance(raw, dict):
        raise PlanError(f"{where} must be a mapping")
    attributes = raw.get("attributes", {})
    if not isinstance(attributes, dict):
        raise PlanError(f"{where}.attributes must be a mapping")
    return Actor(
        id=_string(raw, "id", where),
        roles=_string_tuple(raw, "roles", where),
        tenant=str(raw.get("tenant", "")),
        attributes=attributes,
    )


def _object_from(raw: Any, index: int) -> ResourceObject:
    where = f"objects[{index}]"
    if not isinstance(raw, dict):
        raise PlanError(f"{where} must be a mapping")
    attributes = raw.get("attributes", {})
    if not isinstance(attributes, dict):
        raise PlanError(f"{where}.attributes must be a mapping")
    return ResourceObject(
        ref=_string(raw, "ref", where),
        resource=_string(raw, "resource", where),
        owner_id=str(raw.get("owner_id", "")),
        tenant_id=str(raw.get("tenant_id", "")),
        sensitivity=str(raw.get("sensitivity", "normal")),
        attributes=attributes,
    )


def _ref_from(raw: Any, where: str) -> ObjectRef:
    if not isinstance(raw, dict):
        raise PlanError(f"{where} must be a mapping")
    return ObjectRef(
        name=_string(raw, "name", where),
        location=_string(raw, "location", where),
        schema_type=str(raw.get("schema_type", "string")),
        schema_format=str(raw.get("schema_format", "")),
        pattern=str(raw.get("pattern", "")),
        source=str(raw.get("source", "parameter")),
    )


def _operation_from(raw: Any, index: int) -> Operation:
    where = f"operations[{index}]"
    if not isinstance(raw, dict):
        raise PlanError(f"{where} must be a mapping")
    hints = raw.get("extension_hints", {})
    if not isinstance(hints, dict):
        raise PlanError(f"{where}.extension_hints must be a mapping")
    refs = raw.get("object_refs", [])
    if not isinstance(refs, list):
        raise PlanError(f"{where}.object_refs must be a list")
    return Operation(
        key=_string(raw, "key", where),
        method=_string(raw, "method", where),
        path=_string(raw, "path", where),
        resource=_string(raw, "resource", where),
        action=_string(raw, "action", where),
        object_refs=tuple(
            _ref_from(item, f"{where}.object_refs[{pos}]") for pos, item in enumerate(refs)
        ),
        security=_string_tuple(raw, "security", where),
        tags=_string_tuple(raw, "tags", where),
        security_declared=bool(raw.get("security_declared", False)),
        body_fields=_string_tuple(raw, "body_fields", where),
        extension_hints=hints,
    )


def _case_from(raw: Any, index: int) -> TestCase:
    where = f"cases[{index}]"
    if not isinstance(raw, dict):
        raise PlanError(f"{where} must be a mapping")
    expected_raw = _string(raw, "expected", where)
    severity_raw = _string(raw, "severity", where)
    request = _required(raw, "request", where)
    if not isinstance(request, dict):
        raise PlanError(f"{where}.request must be a mapping")
    try:
        expected = Effect(expected_raw.upper())
    except ValueError as exc:
        raise PlanError(f"{where}.expected is not a valid effect") from exc
    return TestCase(
        id=_string(raw, "id", where),
        technique=_string(raw, "technique", where),
        operation_key=_string(raw, "operation_key", where),
        method=_string(raw, "method", where),
        path=_string(raw, "path", where),
        actor_id=_string(raw, "actor_id", where),
        object_ref=_string(raw, "object_ref", where),
        action=_string(raw, "action", where),
        expected=expected,
        decision_rule=str(raw.get("decision_rule", "")),
        rationale=str(raw.get("rationale", "")),
        owasp=str(raw.get("owasp", "")),
        severity=Severity.parse(severity_raw),
        request=request,
    )


def _finding_from(raw: Any, index: int) -> Finding:
    where = f"findings[{index}]"
    if not isinstance(raw, dict):
        raise PlanError(f"{where} must be a mapping")
    return Finding(
        rule_id=_string(raw, "rule_id", where),
        title=_string(raw, "title", where),
        severity=Severity.parse(_string(raw, "severity", where)),
        operation_key=_string(raw, "operation_key", where),
        message=_string(raw, "message", where),
        recommendation=str(raw.get("recommendation", "")),
        fingerprint=str(raw.get("fingerprint", "")),
    )


def load_plan(path: str | Path) -> AttackPlan:
    """Load a plan with strict shape validation."""

    document, _ = load_document(path, "attack plan")
    if not isinstance(document, dict):
        raise PlanError("attack plan must contain a mapping at the top level")
    collections: dict[str, tuple[Any, ...]] = {}
    for key, parser in (
        ("operations", _operation_from),
        ("actors", _actor_from),
        ("objects", _object_from),
        ("cases", _case_from),
        ("findings", _finding_from),
    ):
        value = _required(document, key, "attack plan")
        if not isinstance(value, list):
            raise PlanError(f"attack plan.{key} must be a list")
        collections[key] = tuple(parser(item, index) for index, item in enumerate(value))
    return AttackPlan(
        schema_version=_string(document, "schema_version", "attack plan"),
        attribution=_string(document, "attribution", "attack plan"),
        spec=_string(document, "spec", "attack plan"),
        spec_digest=_string(document, "spec_digest", "attack plan"),
        policy_digest=_string(document, "policy_digest", "attack plan"),
        operations=collections["operations"],
        actors=collections["actors"],
        objects=collections["objects"],
        cases=collections["cases"],
        findings=collections["findings"],
        truncated=bool(document.get("truncated", False)),
    )


def load_results(path: str | Path) -> list[dict[str, Any]]:
    """Load executed-case results with strict shape validation."""

    document, _ = load_json_object(path, "verification results")
    results = _required(document, "results", "verification results")
    if not isinstance(results, list):
        raise PlanError("verification results.results must be a list")
    validated: list[dict[str, Any]] = []
    for index, item in enumerate(results):
        where = f"results[{index}]"
        if not isinstance(item, dict):
            raise PlanError(f"{where} must be a mapping")
        case_id = _string(item, "case_id", where)
        status = _required(item, "status", where)
        if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
            raise PlanError(f"{where}.status must be an HTTP status code between 100 and 599")
        validated.append(
            {"case_id": case_id, "status": status, "evidence": str(item.get("evidence", ""))}
        )
    return validated


def render_text(plan: AttackPlan, spec_uri: str) -> str:
    """Render the audit summary as deterministic plain text."""

    counts = {level.value: 0 for level in Severity}
    for finding in plan.findings:
        counts[finding.severity.value] += 1
    lines = [
        f"bolaforge {PLAN_SCHEMA_VERSION} — {ATTRIBUTION}",
        f"Specification : {spec_uri}",
        f"Digest        : {plan.spec_digest[:16]}",
        f"Operations    : {len(plan.operations)}",
        f"Object refs   : {sum(len(item.object_refs) for item in plan.operations)}",
        f"Adversarial cases : {len(plan.cases)}",
        (
            "Findings      : "
            + " | ".join(
                f"{name} {counts[name]}" for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            )
        ),
        "",
    ]
    if plan.findings:
        lines.append("SPECIFICATION FINDINGS")
        for finding in plan.findings:
            lines.append(
                f"  [{finding.severity.value:8}] {finding.rule_id} {finding.operation_key}: "
                f"{finding.message}"
            )
        lines.append("")
    lines.append("SAMPLE ADVERSARIAL CASES")
    for case in plan.cases[:5]:
        lines.append(
            f"  {case.id[:12]} {case.technique:34} {case.method:6} {case.path:40} "
            f"actor={case.actor_id:14} expected={case.expected.value}"
        )
    if not plan.cases:
        lines.append("  (none: no object-scoped operations with matching policy fixtures)")
    lines.append("")
    lines.append(f"Generated by {ATTRIBUTION}")
    return "\n".join(lines)


def decision_from_dict(raw: Any) -> Decision:
    """Deserialize a single oracle decision for the ``oracle`` subcommand."""

    if not isinstance(raw, dict):
        raise PlanError("oracle input must be a mapping")
    effect_raw = _string(raw, "expected_effect", "oracle input")
    try:
        effect = Effect(effect_raw.upper())
    except ValueError as exc:
        raise PlanError("oracle input.expected_effect must be ALLOW or DENY") from exc
    return Decision(effect, str(raw.get("rule_id", "")), str(raw.get("reason", "")))
