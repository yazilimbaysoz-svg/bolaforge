"""Offline authorization oracle tests.

Baysöz Labs <baysozlabs@proton.me>
"""

import pytest

from bolaforge.errors import FixtureError, PolicyError
from bolaforge.models import Actor, Effect, ResourceObject
from bolaforge.policy import AuthorizationPolicy, load_fixtures

POLICY = {
    "version": "1.0",
    "default_effect": "deny",
    "resources": {
        "orders": {
            "owner_field": "owner_id",
            "tenant_field": "tenant_id",
            "rules": [
                {
                    "id": "deny-sensitive",
                    "effect": "deny",
                    "roles": ["*"],
                    "actions": ["delete"],
                    "scope": "any",
                    "priority": 1,
                    "conditions": {"all": [{"field": "sensitivity", "op": "eq", "value": "admin"}]},
                },
                {
                    "id": "admin-all",
                    "effect": "allow",
                    "roles": ["admin"],
                    "actions": ["*"],
                    "scope": "any",
                    "priority": 10,
                },
                {
                    "id": "owner-rw",
                    "effect": "allow",
                    "roles": ["user"],
                    "actions": ["read", "update"],
                    "scope": "own",
                    "priority": 20,
                },
                {
                    "id": "tenant-read",
                    "effect": "allow",
                    "roles": ["user"],
                    "actions": ["read"],
                    "scope": "tenant",
                    "priority": 30,
                },
                {
                    "id": "public-read",
                    "effect": "allow",
                    "roles": ["anonymous"],
                    "actions": ["read"],
                    "scope": "public",
                    "priority": 40,
                },
            ],
        }
    },
}

ALICE = Actor("alice", ("user",), "t1")
BOB = Actor("bob", ("user",), "t1")
CAROL = Actor("carol", ("user",), "t2")
ADMIN = Actor("admin", ("admin",), "t1")
ANON = Actor("anon", ())
ORDER = ResourceObject("order-1", "orders", "alice", "t1")
ORDER_ADMIN = ResourceObject("order-2", "orders", "alice", "t1", "admin")


def test_owner_scope_and_tenant_scope() -> None:
    policy = AuthorizationPolicy(POLICY)
    assert policy.decide(ALICE, ORDER, "read").effect is Effect.ALLOW
    assert policy.decide(ALICE, ORDER, "update").effect is Effect.ALLOW
    assert policy.decide(BOB, ORDER, "read").effect is Effect.ALLOW
    assert policy.decide(BOB, ORDER, "update").effect is Effect.DENY
    assert policy.decide(CAROL, ORDER, "read").effect is Effect.DENY


def test_deny_overrides_allow_and_priority_is_deterministic() -> None:
    policy = AuthorizationPolicy(POLICY)
    assert policy.decide(ADMIN, ORDER_ADMIN, "delete").effect is Effect.DENY
    assert policy.decide(ADMIN, ORDER, "delete").effect is Effect.ALLOW
    assert policy.decide(BOB, ORDER_ADMIN, "read").rule_id == "tenant-read"


def test_anonymous_roles_and_default_effect() -> None:
    policy = AuthorizationPolicy(POLICY)
    assert policy.decide(ANON, ORDER, "read").effect is Effect.DENY
    public = ResourceObject("public-1", "orders", "alice", "t1", attributes={"public": True})
    assert policy.decide(ANON, public, "read").effect is Effect.ALLOW
    assert (
        policy.decide(ALICE, ResourceObject("x", "unknown"), "read").rule_id == "POLICY-NO-RESOURCE"
    )
    permissive = {**POLICY, "default_effect": "allow"}
    assert AuthorizationPolicy(permissive).decide(CAROL, ORDER, "delete").effect is Effect.ALLOW


def test_conditions_operators() -> None:
    condition = {"field": "actor.level", "op": "in", "value": ["high", "critical"]}
    document = {
        "version": "1.0",
        "resources": {
            "files": {
                "rules": [
                    {
                        "effect": "allow",
                        "roles": ["user"],
                        "actions": ["read"],
                        "scope": "any",
                        "conditions": {"any": [condition]},
                    }
                ]
            }
        },
    }
    policy = AuthorizationPolicy(document)
    high = Actor("u", ("user",), "t1", {"level": "high"})
    low = Actor("v", ("user",), "t1", {"level": "low"})
    obj = ResourceObject("f", "files")
    assert policy.decide(high, obj, "read").effect is Effect.ALLOW
    assert policy.decide(low, obj, "read").effect is Effect.DENY


@pytest.mark.parametrize(
    "mutator",
    [
        lambda doc: doc.update(version="2.0"),
        lambda doc: doc.update(default_effect="maybe"),
        lambda doc: doc.update(resources={}),
        lambda doc: doc["resources"]["orders"].update(rules=[]),
        lambda doc: doc["resources"]["orders"]["rules"][0].update(effect="permit"),
        lambda doc: doc["resources"]["orders"]["rules"][0].update(scope="global"),
        lambda doc: doc["resources"]["orders"]["rules"][0].update(priority=-1),
        lambda doc: doc["resources"]["orders"]["rules"][0].update(conditions={"bad": []}),
        lambda doc: doc["resources"]["orders"]["rules"][0].update(
            conditions={"all": [{"field": "x", "op": "gt", "value": 1}]}
        ),
    ],
)
def test_invalid_policies_are_rejected(mutator) -> None:
    document = {
        "version": "1.0",
        "default_effect": "deny",
        "resources": {
            "orders": {
                "rules": [
                    {
                        "effect": "allow",
                        "roles": ["user"],
                        "actions": ["read"],
                        "scope": "own",
                        "priority": 5,
                    }
                ]
            }
        },
    }
    mutator(document)
    with pytest.raises(PolicyError):
        AuthorizationPolicy(document)


def test_fixture_validation_and_loading(tmp_path) -> None:
    path = tmp_path / "fixtures.json"
    path.write_text(
        '{"actors":[{"id":"a","roles":["user"],"tenant":"t1"}],'
        '"objects":[{"ref":"o","resource":"orders","owner_id":"a","tenant_id":"t1"}]}',
        encoding="utf-8",
    )
    actors, objects = load_fixtures(str(path))
    assert actors[0].id == "a" and objects[0].ref == "o"
    path.write_text('{"actors":[],"objects":[{"ref":"o","resource":"orders"}]}', encoding="utf-8")
    with pytest.raises(FixtureError):
        load_fixtures(str(path))
