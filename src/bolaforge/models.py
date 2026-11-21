"""Immutable domain models shared by the analyzer, oracle and emitters.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Ordered finding severities used for SARIF levels and CI gating."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls(value.upper())
        except ValueError as exc:
            choices = ", ".join(item.value for item in cls)
            raise ValueError(f"unknown severity {value!r}; expected one of: {choices}") from exc


class Effect(str, Enum):
    """Outcome of an offline authorization decision."""

    ALLOW = "ALLOW"
    DENY = "DENY"


@dataclass(frozen=True, slots=True)
class Actor:
    """An adversarial actor used by the offline authorization oracle."""

    id: str
    roles: tuple[str, ...]
    tenant: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ResourceObject:
    """A concrete object instance with ownership metadata for oracle evaluation."""

    ref: str
    resource: str
    owner_id: str = ""
    tenant_id: str = ""
    sensitivity: str = "normal"
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ObjectRef:
    """An object identifier discovered in an OpenAPI operation."""

    name: str
    location: str
    schema_type: str = "string"
    schema_format: str = ""
    pattern: str = ""
    source: str = "parameter"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Operation:
    """A normalized OpenAPI operation with its authorization metadata."""

    key: str
    method: str
    path: str
    resource: str
    action: str
    object_refs: tuple[ObjectRef, ...]
    security: tuple[str, ...]
    tags: tuple[str, ...]
    security_declared: bool = False
    body_fields: tuple[str, ...] = ()
    extension_hints: dict[str, Any] = field(default_factory=dict)

    @property
    def has_object_ref(self) -> bool:
        return bool(self.object_refs)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Decision:
    """Result of applying a policy to an actor/object/action triple."""

    effect: Effect
    rule_id: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"effect": self.effect.value, "rule_id": self.rule_id, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class TestCase:
    """A deterministic adversarial request derived from one operation."""

    id: str
    technique: str
    operation_key: str
    method: str
    path: str
    actor_id: str
    object_ref: str
    action: str
    expected: Effect
    decision_rule: str
    rationale: str
    owasp: str
    severity: Severity
    request: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["expected"] = self.expected.value
        payload["severity"] = self.severity.value
        return payload


@dataclass(frozen=True, slots=True)
class Finding:
    """A specification-level authorization weakness reported as SARIF."""

    rule_id: str
    title: str
    severity: Severity
    operation_key: str
    message: str
    recommendation: str
    fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["severity"] = self.severity.value
        return payload


@dataclass(frozen=True, slots=True)
class AttackPlan:
    """Complete deterministic output of one audit run."""

    schema_version: str
    attribution: str
    spec: str
    spec_digest: str
    policy_digest: str
    operations: tuple[Operation, ...]
    actors: tuple[Actor, ...]
    objects: tuple[ResourceObject, ...]
    cases: tuple[TestCase, ...]
    findings: tuple[Finding, ...]
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "attribution": self.attribution,
            "spec": self.spec,
            "spec_digest": self.spec_digest,
            "policy_digest": self.policy_digest,
            "operations": [item.to_dict() for item in self.operations],
            "actors": [item.to_dict() for item in self.actors],
            "objects": [item.to_dict() for item in self.objects],
            "cases": [item.to_dict() for item in self.cases],
            "findings": [item.to_dict() for item in self.findings],
            "truncated": self.truncated,
        }
