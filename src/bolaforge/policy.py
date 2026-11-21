"""Offline authorization policy engine and fixture validation.

The oracle is a deterministic RBAC/ABAC evaluator: it never calls a network
service and never executes expressions from input documents. Deny rules take
precedence over allow rules, and ties are broken by explicit priority followed
by declaration order.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from typing import Any

from .errors import FixtureError, PolicyError
from .models import Actor, Decision, Effect, ResourceObject
from .spec import canonical_digest, load_document

VALID_SCOPES = frozenset({"any", "own", "tenant", "public"})
VALID_OPERATORS = frozenset({"eq", "ne", "in", "not_in", "startswith", "exists"})
DEFAULT_EFFECT = Effect.DENY


class AuthorizationPolicy:
    """A validated policy that can decide object-level authorization queries."""

    def __init__(self, document: dict[str, Any], source: str = "<memory>") -> None:
        self.source = source
        self.document = document
        self.digest = canonical_digest(document)
        self.default_effect = self._validate(document)

    @classmethod
    def load(cls, path: str) -> AuthorizationPolicy:
        document, _ = load_document(path, "authorization policy")
        if not isinstance(document, dict):
            raise PolicyError("authorization policy must contain a mapping at the top level")
        return cls(document, path)

    def _validate(self, document: dict[str, Any]) -> Effect:
        if str(document.get("version", "")) != "1.0":
            raise PolicyError("authorization policy requires version '1.0'")
        default_raw = document.get("default_effect", "deny")
        if default_raw not in {"allow", "deny"}:
            raise PolicyError("default_effect must be 'allow' or 'deny'")
        resources = document.get("resources")
        if not isinstance(resources, dict) or not resources:
            raise PolicyError("authorization policy requires a non-empty 'resources' mapping")
        for resource_name, resource in resources.items():
            if not isinstance(resource_name, str) or not resource_name:
                raise PolicyError("resource names must be non-empty strings")
            if not isinstance(resource, dict):
                raise PolicyError(f"resource {resource_name!r} must be a mapping")
            rules = resource.get("rules")
            if not isinstance(rules, list) or not rules:
                raise PolicyError(f"resource {resource_name!r} requires a non-empty 'rules' list")
            for index, rule in enumerate(rules):
                self._validate_rule(resource_name, rule, index)
        return Effect(default_raw.upper())

    @staticmethod
    def _validate_rule(resource: str, rule: Any, index: int) -> None:
        where = f"resource {resource!r} rule {index}"
        if not isinstance(rule, dict):
            raise PolicyError(f"{where} must be a mapping")
        if rule.get("effect") not in {"allow", "deny"}:
            raise PolicyError(f"{where} effect must be 'allow' or 'deny'")
        for field in ("roles", "actions"):
            values = rule.get(field)
            if (
                not isinstance(values, list)
                or not values
                or not all(isinstance(item, str) and item for item in values)
            ):
                raise PolicyError(f"{where} {field} must be a non-empty list of strings")
        scope = rule.get("scope", "any")
        if scope not in VALID_SCOPES:
            raise PolicyError(f"{where} scope must be one of {sorted(VALID_SCOPES)}")
        priority = rule.get("priority", 100)
        if isinstance(priority, bool) or not isinstance(priority, int) or not 0 <= priority <= 1000:
            raise PolicyError(f"{where} priority must be an integer between 0 and 1000")
        conditions = rule.get("conditions")
        if conditions is not None:
            if not isinstance(conditions, dict):
                raise PolicyError(f"{where} conditions must be a mapping")
            unknown = set(conditions) - {"all", "any"}
            if unknown:
                raise PolicyError(f"{where} conditions has unknown keys: {sorted(unknown)}")
            for group in ("all", "any"):
                items = conditions.get(group, [])
                if not isinstance(items, list):
                    raise PolicyError(f"{where} conditions.{group} must be a list")
                for condition in items:
                    AuthorizationPolicy._validate_condition(where, condition)

    @staticmethod
    def _validate_condition(where: str, condition: Any) -> None:
        if not isinstance(condition, dict):
            raise PolicyError(f"{where} condition must be a mapping")
        if not isinstance(condition.get("field"), str) or not condition["field"]:
            raise PolicyError(f"{where} condition requires a non-empty 'field'")
        if condition.get("op") not in VALID_OPERATORS:
            raise PolicyError(f"{where} condition op must be one of {sorted(VALID_OPERATORS)}")
        if "value" not in condition:
            raise PolicyError(f"{where} condition requires a 'value'")

    def resources(self) -> tuple[str, ...]:
        return tuple(self.document["resources"])

    def decide(
        self,
        actor: Actor,
        obj: ResourceObject,
        action: str,
        resource: str | None = None,
    ) -> Decision:
        """Evaluate one authorization query without side effects."""

        resource_name = resource or obj.resource
        resources = self.document["resources"]
        if resource_name not in resources:
            return Decision(
                Effect.DENY,
                "POLICY-NO-RESOURCE",
                f"no policy rules defined for resource {resource_name!r}",
            )
        definition = resources[resource_name]
        owner_field = str(definition.get("owner_field", "owner_id"))
        tenant_field = str(definition.get("tenant_field", "tenant_id"))
        actor_roles = set(actor.roles) or {"anonymous"}
        actor_roles.add("authenticated")
        candidates: list[tuple[int, int, str, Effect, str]] = []
        for index, rule in enumerate(definition["rules"]):
            if not self._roles_match(rule["roles"], actor_roles):
                continue
            if not self._actions_match(rule["actions"], action):
                continue
            if not self._scope_matches(
                rule.get("scope", "any"), actor, obj, owner_field, tenant_field
            ):
                continue
            if not self._conditions_match(rule.get("conditions"), actor, obj):
                continue
            rule_id = str(rule.get("id", f"{resource_name}-{index}"))
            effect = Effect(rule["effect"].upper())
            reason = str(rule.get("reason", f"{effect.value} via rule {rule_id}"))
            candidates.append((int(rule.get("priority", 100)), index, rule_id, effect, reason))
        if not candidates:
            return Decision(
                self.default_effect,
                "POLICY-DEFAULT",
                f"no rule matched; default is {self.default_effect.value}",
            )
        candidates.sort(key=lambda item: (item[0], item[1]))
        deny = next((item for item in candidates if item[3] is Effect.DENY), None)
        chosen = deny or candidates[0]
        return Decision(chosen[3], chosen[2], chosen[4])

    @staticmethod
    def _roles_match(rule_roles: list[str], actor_roles: set[str]) -> bool:
        return "*" in rule_roles or bool(set(rule_roles) & actor_roles)

    @staticmethod
    def _actions_match(rule_actions: list[str], action: str) -> bool:
        return "*" in rule_actions or action in rule_actions

    @staticmethod
    def _scope_matches(
        scope: str, actor: Actor, obj: ResourceObject, owner_field: str, tenant_field: str
    ) -> bool:
        if scope == "any":
            return True
        if scope == "public":
            return obj.attributes.get("public") is True
        object_values = {"owner_id": obj.owner_id, "tenant_id": obj.tenant_id, **obj.attributes}
        if scope == "own":
            return bool(actor.id) and actor.id == object_values.get(owner_field)
        if scope == "tenant":
            return bool(actor.tenant) and actor.tenant == object_values.get(tenant_field)
        return False

    @classmethod
    def _conditions_match(
        cls, conditions: dict[str, Any] | None, actor: Actor, obj: ResourceObject
    ) -> bool:
        if not conditions:
            return True
        resolved = {
            "all": [cls._condition_match(item, actor, obj) for item in conditions.get("all", [])],
            "any": [cls._condition_match(item, actor, obj) for item in conditions.get("any", [])],
        }
        if resolved["all"] and not all(resolved["all"]):
            return False
        if resolved["any"] and not any(resolved["any"]):
            return False
        return True

    @staticmethod
    def _condition_match(condition: dict[str, Any], actor: Actor, obj: ResourceObject) -> bool:
        field = str(condition["field"])
        if field.startswith("actor."):
            actual: Any = actor.attributes.get(field.split(".", 1)[1])
        elif field.startswith("object."):
            actual = obj.attributes.get(field.split(".", 1)[1])
        else:
            actual = {
                "owner_id": obj.owner_id,
                "tenant_id": obj.tenant_id,
                "sensitivity": obj.sensitivity,
                **obj.attributes,
            }.get(field)
        expected = condition["value"]
        operator = condition["op"]
        if operator == "eq":
            return actual == expected
        if operator == "ne":
            return actual != expected
        if operator == "in":
            return isinstance(expected, list) and actual in expected
        if operator == "not_in":
            return isinstance(expected, list) and actual not in expected
        if operator == "startswith":
            return (
                isinstance(actual, str)
                and isinstance(expected, str)
                and actual.startswith(expected)
            )
        return (operator == "exists") == (actual is not None)


def load_fixtures(path: str) -> tuple[tuple[Actor, ...], tuple[ResourceObject, ...]]:
    """Load and validate actor/object fixtures used by the oracle."""

    document, _ = load_document(path, "fixture document")
    if not isinstance(document, dict):
        raise FixtureError("fixture document must contain a mapping at the top level")
    raw_actors = document.get("actors")
    raw_objects = document.get("objects")
    if not isinstance(raw_actors, list) or not raw_actors:
        raise FixtureError("fixture document requires a non-empty 'actors' list")
    if not isinstance(raw_objects, list) or not raw_objects:
        raise FixtureError("fixture document requires a non-empty 'objects' list")
    actors: list[Actor] = []
    seen_actors: set[str] = set()
    for index, item in enumerate(raw_actors):
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
            raise FixtureError(f"actor {index} requires a non-empty string 'id'")
        if item["id"] in seen_actors:
            raise FixtureError(f"duplicate actor id {item['id']!r}")
        seen_actors.add(item["id"])
        roles = item.get("roles", [])
        if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
            raise FixtureError(f"actor {item['id']!r} roles must be a list of strings")
        attributes = item.get("attributes", {})
        if not isinstance(attributes, dict):
            raise FixtureError(f"actor {item['id']!r} attributes must be a mapping")
        actors.append(
            Actor(
                id=item["id"],
                roles=tuple(roles),
                tenant=str(item.get("tenant", "")),
                attributes=dict(attributes),
            )
        )
    objects: list[ResourceObject] = []
    seen_objects: set[str] = set()
    for index, item in enumerate(raw_objects):
        if not isinstance(item, dict) or not isinstance(item.get("ref"), str) or not item["ref"]:
            raise FixtureError(f"object {index} requires a non-empty string 'ref'")
        if item["ref"] in seen_objects:
            raise FixtureError(f"duplicate object ref {item['ref']!r}")
        seen_objects.add(item["ref"])
        if not isinstance(item.get("resource"), str) or not item["resource"]:
            raise FixtureError(f"object {item['ref']!r} requires a non-empty 'resource'")
        attributes = item.get("attributes", {})
        if not isinstance(attributes, dict):
            raise FixtureError(f"object {item['ref']!r} attributes must be a mapping")
        objects.append(
            ResourceObject(
                ref=item["ref"],
                resource=item["resource"],
                owner_id=str(item.get("owner_id", "")),
                tenant_id=str(item.get("tenant_id", "")),
                sensitivity=str(item.get("sensitivity", "normal")),
                attributes=dict(attributes),
            )
        )
    return tuple(actors), tuple(objects)
