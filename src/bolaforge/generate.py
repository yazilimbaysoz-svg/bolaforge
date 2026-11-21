"""Deterministic adversarial BOLA/IDOR test-case compiler.

Every emitted request is derived from the specification and validated against
the offline policy oracle. No randomness, clocks or external services are
used, so the same inputs always produce byte-identical plans.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Callable

from .analyze import canonical_resource
from .models import (
    Actor,
    Decision,
    Effect,
    ObjectRef,
    Operation,
    ResourceObject,
    Severity,
    TestCase,
)
from .policy import AuthorizationPolicy

DEFAULT_MAX_CASES = 2000
MAX_OBJECTS_PER_OPERATION = 4

OWASP_BOLA = "API1:2023 Broken Object Level Authorization"
OWASP_BFLA = "API5:2023 Broken Function Level Authorization"
OWASP_MASS = "API3:2023 Broken Object Property Level Authorization"
OWASP_FLOW = "API6:2023 Unrestricted Access to Sensitive Business Flows"

_HIGH_IMPACT = frozenset({"UNAUTHENTICATED_ACCESS", "CROSS_TENANT_REFERENCE", "HORIZONTAL_IDOR"})


def _case_id(
    operation: Operation, technique: str, actor: Actor, obj: ResourceObject, ref: ObjectRef
) -> str:
    seed = f"{operation.key}|{technique}|{actor.id}|{obj.ref}|{ref.name}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20]


def _placeholder_value(name: str, actor: Actor, obj: ResourceObject) -> str:
    lowered = name.lower()
    if "tenant" in lowered:
        return actor.tenant or obj.tenant_id
    if "user" in lowered or "owner" in lowered or "account" in lowered:
        return actor.id or obj.owner_id
    return obj.ref


def _render_path(operation: Operation, obj: ResourceObject, actor: Actor) -> str:
    path = operation.path
    for name in re.findall(r"\{([^}]+)\}", path):
        path = path.replace(f"{{{name}}}", _placeholder_value(name, actor, obj))
    return path


def _base_request(
    operation: Operation, obj: ResourceObject, actor: Actor, ref: ObjectRef
) -> dict[str, Any]:
    request: dict[str, Any] = {
        "method": operation.method,
        "path": _render_path(operation, obj, actor),
        "headers": {"Accept": "application/json"},
        "query": {},
        "body": None,
        "target_parameter": ref.name,
    }
    if ref.location == "query":
        request["query"][ref.name] = obj.ref
    elif ref.location == "header":
        request["headers"][ref.name] = obj.ref
    if operation.method in {"POST", "PUT", "PATCH"}:
        request["headers"]["Content-Type"] = "application/json"
        request["body"] = {ref.name: obj.ref}
    return request


def _severity(technique: str, decision: Decision) -> Severity:
    if decision.effect is Effect.ALLOW:
        return Severity.CRITICAL if technique in _HIGH_IMPACT else Severity.HIGH
    return Severity.LOW


def _pick(actors: tuple[Actor, ...], predicate: Callable[[Actor], bool]) -> Actor | None:
    return next((actor for actor in actors if predicate(actor)), None)


class ActorPool:
    """Deterministically selected actors used by the adversarial matrix."""

    def __init__(self, actors: tuple[Actor, ...]) -> None:
        self.actors = actors
        self.anonymous = _pick(actors, lambda actor: not actor.roles) or Actor("anonymous", ())
        self.admin = _pick(actors, lambda actor: "admin" in actor.roles)
        self.privileged = _pick(
            actors, lambda actor: bool(actor.roles) and "admin" not in actor.roles
        )

    def owner_actor(self, obj: ResourceObject) -> Actor:
        return (
            _pick(self.actors, lambda item: item.id == obj.owner_id)
            or self.privileged
            or self.anonymous
        )

    def same_tenant_peer(self, obj: ResourceObject) -> Actor | None:
        return _pick(
            self.actors,
            lambda item: (
                item.id != obj.owner_id
                and bool(item.roles)
                and bool(item.tenant)
                and item.tenant == obj.tenant_id
            ),
        )

    def cross_tenant(self, obj: ResourceObject) -> Actor | None:
        return _pick(
            self.actors,
            lambda item: (
                item.id != obj.owner_id
                and bool(item.roles)
                and bool(item.tenant)
                and item.tenant != obj.tenant_id
            ),
        )


def generate_cases(
    operations: tuple[Operation, ...],
    actors: tuple[Actor, ...],
    objects: tuple[ResourceObject, ...],
    policy: AuthorizationPolicy,
    max_cases: int = DEFAULT_MAX_CASES,
) -> tuple[tuple[TestCase, ...], bool]:
    """Compile all supported adversarial techniques into a stable case list."""

    if max_cases < 1:
        raise ValueError("max_cases must be at least 1")
    pool = ActorPool(actors)
    cases: list[TestCase] = []
    seen: set[str] = set()

    def emit(
        operation: Operation,
        ref: ObjectRef,
        obj: ResourceObject,
        actor: Actor,
        technique: str,
        rationale: str,
        owasp: str,
        request: dict[str, Any],
    ) -> None:
        decision = policy.decide(actor, obj, operation.action, operation.resource)
        case = TestCase(
            id=_case_id(operation, technique, actor, obj, ref),
            technique=technique,
            operation_key=operation.key,
            method=operation.method,
            path=request["path"],
            actor_id=actor.id,
            object_ref=obj.ref,
            action=operation.action,
            expected=decision.effect,
            decision_rule=decision.rule_id,
            rationale=rationale,
            owasp=owasp,
            severity=_severity(technique, decision),
            request=request,
        )
        if case.id not in seen:
            seen.add(case.id)
            cases.append(case)

    for operation in operations:
        if not operation.object_refs:
            continue
        resource_key = canonical_resource(operation.resource)
        candidates = [obj for obj in objects if canonical_resource(obj.resource) == resource_key][
            :MAX_OBJECTS_PER_OPERATION
        ]
        for obj in candidates:
            for ref in operation.object_refs:
                base_actor = pool.owner_actor(obj)
                base = _base_request(operation, obj, base_actor, ref)
                emit(
                    operation,
                    ref,
                    obj,
                    pool.anonymous,
                    "UNAUTHENTICATED_ACCESS",
                    "Replay the object-scoped operation without any credentials.",
                    OWASP_BOLA,
                    base,
                )
                cross = pool.cross_tenant(obj)
                if cross is not None:
                    request = _base_request(operation, obj, cross, ref)
                    emit(
                        operation,
                        ref,
                        obj,
                        cross,
                        "CROSS_TENANT_REFERENCE",
                        "Access an object owned by a different tenant using a valid low-privilege actor.",
                        OWASP_BOLA,
                        request,
                    )
                peer = pool.same_tenant_peer(obj)
                if peer is not None:
                    request = _base_request(operation, obj, peer, ref)
                    emit(
                        operation,
                        ref,
                        obj,
                        peer,
                        "HORIZONTAL_IDOR",
                        "Use a same-tenant peer identity to access another user's object reference.",
                        OWASP_BOLA,
                        request,
                    )
                if obj.sensitivity == "admin":
                    low = base_actor
                    request = _base_request(operation, obj, low, ref)
                    emit(
                        operation,
                        ref,
                        obj,
                        low,
                        "VERTICAL_PRIVILEGE_ESCALATION",
                        "Request a sensitive object with a low-privilege actor to test function-level checks.",
                        OWASP_BFLA,
                        request,
                    )
                if ref.schema_type in {"integer", "number"} or obj.attributes.get("sequence"):
                    sequence = obj.attributes.get("sequence")
                    next_value = str(int(sequence) + 1) if isinstance(sequence, int) else "1"
                    request = _base_request(operation, obj, base_actor, ref)
                    request["path"] = re.sub(r"\{[^}]+\}", next_value, operation.path)
                    request["query"] = {ref.name: next_value}
                    emit(
                        operation,
                        ref,
                        obj,
                        base_actor,
                        "SEQUENTIAL_ID_ENUMERATION",
                        "Probe the next predictable identifier to expose enumerable object access.",
                        OWASP_FLOW,
                        request,
                    )
                if ref.location == "query":
                    request = _base_request(operation, obj, base_actor, ref)
                    request["query"] = {ref.name: [obj.ref, f"{obj.ref}-alternate"]}
                    emit(
                        operation,
                        ref,
                        obj,
                        base_actor,
                        "DUPLICATE_PARAMETER_POLLUTION",
                        "Submit a duplicated identifier to exploit parser/authorization disagreement.",
                        OWASP_BOLA,
                        request,
                    )
                override = "DELETE" if operation.method != "DELETE" else "PATCH"
                request = _base_request(operation, obj, base_actor, ref)
                request["headers"]["X-HTTP-Method-Override"] = override
                emit(
                    operation,
                    ref,
                    obj,
                    base_actor,
                    "METHOD_OVERRIDE_BYPASS",
                    "Override the effective HTTP method to bypass method-specific authorization rules.",
                    OWASP_BFLA,
                    request,
                )
                static_segments = [
                    part for part in operation.path.split("/") if part and not part.startswith("{")
                ]
                if static_segments:
                    request = _base_request(operation, obj, base_actor, ref)
                    request["path"] = request["path"].replace(
                        static_segments[-1], static_segments[-1].upper(), 1
                    )
                    emit(
                        operation,
                        ref,
                        obj,
                        base_actor,
                        "PATH_CASE_VARIATION",
                        "Change route casing to test case-sensitive authorization middleware gaps.",
                        OWASP_BFLA,
                        request,
                    )
                request = _base_request(operation, obj, base_actor, ref)
                request["path"] = f"{request['path'].rstrip('/')}/"
                emit(
                    operation,
                    ref,
                    obj,
                    base_actor,
                    "TRAILING_SLASH_BYPASS",
                    "Append a trailing slash to test route-normalization and policy-matching differences.",
                    OWASP_BFLA,
                    request,
                )
                if operation.method in {"POST", "PUT", "PATCH"}:
                    request = _base_request(operation, obj, base_actor, ref)
                    body = request["body"] if isinstance(request["body"], dict) else {}
                    body.update({"owner_id": base_actor.id, "tenant_id": base_actor.tenant})
                    request["body"] = body
                    emit(
                        operation,
                        ref,
                        obj,
                        base_actor,
                        "MASS_ASSIGNMENT_OWNERSHIP",
                        "Inject ownership fields into the body to test property-level authorization.",
                        OWASP_MASS,
                        request,
                    )
                request = _base_request(operation, obj, base_actor, ref)
                request["headers"]["Content-Type"] = "application/x-www-form-urlencoded"
                emit(
                    operation,
                    ref,
                    obj,
                    base_actor,
                    "CONTENT_TYPE_CONFUSION",
                    "Switch media type to test schema validation and authorization parser divergence.",
                    OWASP_BOLA,
                    request,
                )
                request = _base_request(operation, obj, base_actor, ref)
                request["headers"]["X-Original-URL"] = request["path"]
                request["headers"]["X-Rewrite-URL"] = request["path"]
                emit(
                    operation,
                    ref,
                    obj,
                    base_actor,
                    "PROXY_HEADER_SPOOFING",
                    "Supply proxy rewrite headers to test path-based policy enforcement.",
                    OWASP_BFLA,
                    request,
                )
                if ref.location == "query":
                    request = _base_request(operation, obj, base_actor, ref)
                    request["query"] = {ref.name: f"{obj.ref},{obj.ref}-next"}
                    emit(
                        operation,
                        ref,
                        obj,
                        base_actor,
                        "BULK_ID_SCRAPE",
                        "Request multiple object identifiers in one parameter to test bulk authorization.",
                        OWASP_FLOW,
                        request,
                    )
                placeholders = re.findall(r"\{([^}]+)\}", operation.path)
                values = [_placeholder_value(name, base_actor, obj) for name in placeholders]
                if len(placeholders) > 1 and len(set(values[:2])) == 2:
                    request = _base_request(operation, obj, base_actor, ref)
                    first, second = values[0], values[1]
                    swapped = request["path"]
                    swapped = swapped.replace(f"/{first}/", "/__bola_swap__/", 1)
                    swapped = swapped.replace(f"/{second}/", f"/{first}/", 1)
                    swapped = swapped.replace("/__bola_swap__/", f"/{second}/", 1)
                    request["path"] = swapped
                    emit(
                        operation,
                        ref,
                        obj,
                        base_actor,
                        "NESTED_PARENT_CONFUSION",
                        "Swap parent and child identifiers to test nested resource ownership checks.",
                        OWASP_BOLA,
                        request,
                    )
    ordered = tuple(sorted(cases, key=lambda item: (item.id, item.technique)))
    truncated = len(ordered) > max_cases
    return ordered[:max_cases], truncated
