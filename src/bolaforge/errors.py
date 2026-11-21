"""Exception hierarchy for bolaforge.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations


class BolaforgeError(Exception):
    """Base class for all expected bolaforge failures."""


class SpecError(BolaforgeError):
    """Invalid, oversized or unsafe OpenAPI input."""


class PolicyError(BolaforgeError):
    """Invalid authorization policy document."""


class FixtureError(BolaforgeError):
    """Invalid actor or object fixture document."""


class PlanError(BolaforgeError):
    """Malformed plan or verification results document."""
