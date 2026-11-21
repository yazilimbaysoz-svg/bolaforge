"""OpenAPI 3.1 operation analysis and specification-level authorization checks.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .models import Actor, Finding, ObjectRef, Operation, ResourceObject, Severity
from .policy import AuthorizationPolicy
from .spec import resolve_refs

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")
ACTION_BY_METHOD = {
    "get": "read",
    "head": "read",
    "options": "read",
    "post": "create",
    "put": "update",
    "patch": "update",
    "delete": "delete",
    "trace": "read",
}
OWNERSHIP_FIELDS = frozenset(
    {"owner", "owner_id", "ownerid", "tenant", "tenant_id", "tenantid", "user_id", "account_id"}
)
_ID_TOKEN_RE = re.compile(r"(?:^|_)(?:id|ids|uuid|guid|key|slug|ref)(?:$|_)", re.IGNORECASE)
_CAMEL_ID_RE = re.compile(r"(?:Id|Uuid|Guid|Key|Slug)$")


def canonical_resource(name: str) -> str:
    """Normalize resource names so singular/plural policy mappings can match."""

    cleaned = re.sub(r"[^a-z0-9]", "", name.lower())
    if cleaned.endswith(("ss", "us", "is")):
        return cleaned
    if cleaned.endswith("ies") and len(cleaned) > 4:
        return f"{cleaned[:-3]}y"
    if cleaned.endswith("sses") and len(cleaned) > 5:
        return cleaned[:-2]
    if cleaned.endswith("s") and len(cleaned) > 3:
        return cleaned[:-1]
    return cleaned


def _is_object_ref(name: str, schema: dict[str, Any]) -> bool:
    normalized = name.lower().replace("-", "_")
    schema_format = str(schema.get("format", "")).lower()
    if schema_format in {"uuid", "ulid", "int64", "objectid"}:
        return True
    if normalized in {"id", "identifier", "uuid", "guid", "slug", "key"}:
        return True
    if normalized.endswith("_id") or normalized.endswith("_ids"):
        return True
    return bool(_ID_TOKEN_RE.search(normalized) or _CAMEL_ID_RE.search(name))


def _object_ref(name: str, location: str, schema: Any, source: str) -> ObjectRef:
    definition = schema if isinstance(schema, dict) else {}
    return ObjectRef(
        name=name,
        location=location,
        schema_type=str(definition.get("type", "string")),
        schema_format=str(definition.get("format", "")),
        pattern=str(definition.get("pattern", "")),
        source=source,
    )


_VERSION_SEGMENTS = frozenset({"v1", "v2", "v3", "api", "rest", "internal"})


def _resource_segment(path: str) -> str:
    for part in path.split("/"):
        if part and not part.startswith("{") and part.lower() not in _VERSION_SEGMENTS:
            return part
    return "resource"


def _body_schema(operation: dict[str, Any]) -> dict[str, Any]:
    body = operation.get("requestBody")
    if not isinstance(body, dict):
        return {}
    content = body.get("content")
    if not isinstance(content, dict):
        return {}
    for media_type in ("application/json", "application/*+json", "*/*"):
        entry = content.get(media_type)
        if isinstance(entry, dict) and isinstance(entry.get("schema"), dict):
            return entry["schema"]
    return {}


def _operation_object_refs(
    parameters: list[Any], body_fields: tuple[str, ...], body_schema: dict[str, Any]
) -> tuple[ObjectRef, ...]:
    refs: list[ObjectRef] = []
    seen: set[tuple[str, str]] = set()
    for parameter in parameters:
        if not isinstance(parameter, dict):
            continue
        name = parameter.get("name")
        location = parameter.get("in")
        if not isinstance(name, str) or location not in {"path", "query", "header", "cookie"}:
            continue
        schema = parameter.get("schema", {})
        if _is_object_ref(name, schema if isinstance(schema, dict) else {}):
            marker = (name, str(location))
            if marker not in seen:
                seen.add(marker)
                refs.append(_object_ref(name, str(location), schema, "parameter"))
    properties = body_schema.get("properties")
    if isinstance(properties, dict):
        for name in body_fields:
            if _is_object_ref(name, properties.get(name, {})):
                marker = (name, "body")
                if marker not in seen:
                    seen.add(marker)
                    refs.append(_object_ref(name, "body", properties.get(name, {}), "body"))
    return tuple(refs)


def extract_operations(document: dict[str, Any]) -> tuple[Operation, ...]:
    """Turn a resolved OpenAPI document into deterministic operation records."""

    resolved = resolve_refs(document)
    global_security = resolved.get("security", [])
    operations: list[Operation] = []
    for raw_path in sorted(resolved["paths"]):
        path = str(raw_path)
        if path.startswith("x-"):
            continue
        path_item = resolved["paths"][raw_path]
        if not isinstance(path_item, dict):
            continue
        shared_parameters = path_item.get("parameters", [])
        if not isinstance(shared_parameters, list):
            shared_parameters = []
        for method in HTTP_METHODS:
            definition = path_item.get(method)
            if not isinstance(definition, dict):
                continue
            local_parameters = definition.get("parameters", [])
            if not isinstance(local_parameters, list):
                local_parameters = []
            parameters = [
                item for item in [*shared_parameters, *local_parameters] if isinstance(item, dict)
            ]
            schema = _body_schema(definition)
            properties = schema.get("properties", {})
            body_fields = (
                tuple(str(key) for key in properties) if isinstance(properties, dict) else ()
            )
            security_raw = definition.get("security", global_security)
            security_declared = "security" in definition or "security" in resolved
            security_names: list[str] = []
            if isinstance(security_raw, list):
                for requirement in security_raw:
                    if isinstance(requirement, dict):
                        security_names.extend(str(key) for key in requirement)
            security_names = tuple(sorted(dict.fromkeys(security_names)))
            tags = definition.get("tags", [])
            tag_tuple = tuple(str(tag) for tag in tags) if isinstance(tags, list) else ()
            resource = str(definition.get("x-bola-resource", _resource_segment(path)))
            operations.append(
                Operation(
                    key=f"{method.upper()} {path}",
                    method=method.upper(),
                    path=path,
                    resource=resource,
                    action=ACTION_BY_METHOD[method],
                    object_refs=_operation_object_refs(parameters, body_fields, schema),
                    security=security_names,
                    tags=tag_tuple,
                    security_declared=security_declared,
                    body_fields=body_fields,
                    extension_hints={
                        str(key): value
                        for key, value in definition.items()
                        if str(key).startswith("x-")
                    },
                )
            )
    return tuple(sorted(operations, key=lambda item: item.key))


def _fingerprint(rule_id: str, operation_key: str, message: str) -> str:
    payload = f"{rule_id}|{operation_key}|{message}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def _finding(
    rule_id: str,
    title: str,
    severity: Severity,
    operation: Operation,
    message: str,
    recommendation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        operation_key=operation.key,
        message=message,
        recommendation=recommendation,
        fingerprint=_fingerprint(rule_id, operation.key, message),
    )


def anonymous_actor(actors: tuple[Actor, ...]) -> Actor:
    """Return the fixture actor with no roles, or a synthetic anonymous actor."""

    for actor in actors:
        if not actor.roles:
            return actor
    return Actor(id="anonymous", roles=())


def build_findings(
    operations: tuple[Operation, ...],
    policy: AuthorizationPolicy,
    actors: tuple[Actor, ...],
    objects: tuple[ResourceObject, ...],
) -> tuple[Finding, ...]:
    """Derive specification-level authorization findings deterministically."""

    findings: list[Finding] = []
    policy_resources = {canonical_resource(name) for name in policy.resources()}
    anonymous = anonymous_actor(actors)
    for operation in operations:
        if not operation.has_object_ref:
            continue
        key = operation.key
        if not operation.security and not operation.security_declared:
            findings.append(
                _finding(
                    "BOLA001",
                    "Object-scoped operation has no declared security requirement",
                    Severity.HIGH,
                    operation,
                    f"{key} accepts an object identifier but declares no security requirement.",
                    "Declare an explicit global or operation-level security requirement.",
                )
            )
        elif not operation.security and operation.security_declared:
            findings.append(
                _finding(
                    "BOLA002",
                    "Object-scoped operation is explicitly public",
                    Severity.CRITICAL,
                    operation,
                    f"{key} sets security: [] while accepting an object identifier.",
                    "Remove the empty security override or enforce an authorization scheme.",
                )
            )
        unconstrained = [
            ref.name
            for ref in operation.object_refs
            if ref.schema_type == "string" and not ref.schema_format and not ref.pattern
        ]
        if unconstrained:
            findings.append(
                _finding(
                    "BOLA003",
                    "Object identifier has no format or pattern constraint",
                    Severity.MEDIUM,
                    operation,
                    f"{key} accepts unconstrained identifiers: {', '.join(unconstrained)}.",
                    "Declare format: uuid (or a strict pattern) to reduce enumeration and parsing ambiguity.",
                )
            )
        if (
            operation.method == "GET"
            and any(ref.location == "query" for ref in operation.object_refs)
            and "x-ratelimit" not in operation.extension_hints
        ):
            findings.append(
                _finding(
                    "BOLA004",
                    "Enumeratable object query lacks a documented rate limit",
                    Severity.LOW,
                    operation,
                    f"{key} filters by an object identifier without an x-ratelimit extension.",
                    "Document an x-ratelimit policy or require a non-enumerable identifier.",
                )
            )
        if operation.method in {"POST", "PUT", "PATCH"}:
            writable = sorted(
                {field for field in operation.body_fields if field.lower() in OWNERSHIP_FIELDS}
            )
            if writable:
                findings.append(
                    _finding(
                        "BOLA005",
                        "Writable operation exposes ownership fields",
                        Severity.MEDIUM,
                        operation,
                        f"{key} accepts ownership fields in its request body: {', '.join(writable)}.",
                        "Derive ownership from the authenticated principal instead of client input.",
                    )
                )
        resource_key = canonical_resource(operation.resource)
        if resource_key not in policy_resources:
            findings.append(
                _finding(
                    "BOLA007",
                    "No authorization policy mapping for object-scoped resource",
                    Severity.MEDIUM,
                    operation,
                    f"{key} maps to resource {operation.resource!r} with no policy definition.",
                    "Add a policy entry or an x-bola-resource mapping for this operation.",
                )
            )
        else:
            candidates = [
                obj for obj in objects if canonical_resource(obj.resource) == resource_key
            ]
            for obj in candidates:
                decision = policy.decide(anonymous, obj, operation.action, operation.resource)
                if decision.effect.value == "ALLOW":
                    findings.append(
                        _finding(
                            "BOLA006",
                            "Policy allows anonymous access to an object-scoped action",
                            Severity.CRITICAL,
                            operation,
                            f"{key}: anonymous actor is allowed on object {obj.ref!r} via {decision.rule_id}.",
                            "Restrict the matching rule to authenticated roles and re-run the audit.",
                        )
                    )
                    break
    return tuple(
        sorted(findings, key=lambda item: (item.rule_id, item.operation_key, item.fingerprint))
    )
