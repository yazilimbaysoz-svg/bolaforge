"""Command line interface for bolaforge.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Sequence

from . import __version__
from .analyze import build_findings, extract_operations
from .attribution import ATTRIBUTION, EMAIL, REPOSITORY
from .errors import BolaforgeError
from .generate import DEFAULT_MAX_CASES, generate_cases
from .models import AttackPlan, Severity
from .policy import AuthorizationPolicy, load_fixtures
from .render import PLAN_SCHEMA_VERSION, render_text, write_json
from .sarif import build_sarif
from .spec import load_spec
from .verify import verify_files

_EPILOG = f"Built by {ATTRIBUTION} — {REPOSITORY}"
_DESCRIPTION = (
    "bolaforge compiles deterministic BOLA/IDOR adversarial test plans from OpenAPI 3.1 "
    f"documents and verifies executed results with an offline authorization oracle. {ATTRIBUTION}"
)
_VERSION_LINE = f"bolaforge {__version__} — {ATTRIBUTION}"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bolaforge",
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=_VERSION_LINE)
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    audit = subparsers.add_parser(
        "audit",
        help="analyze an OpenAPI document and compile an adversarial test plan",
        description=f"Compile a deterministic BOLA test plan. {ATTRIBUTION}",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    audit.add_argument("spec", help="path to an OpenAPI 3.1 JSON or safe-YAML document")
    audit.add_argument("--policy", required=True, help="path to the authorization policy document")
    audit.add_argument("--fixtures", required=True, help="path to actor and object fixtures")
    audit.add_argument("--out", help="directory for plan.json and findings.sarif")
    audit.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="stdout format (default: text)",
    )
    audit.add_argument(
        "--fail-on",
        default="HIGH",
        help="minimum SARIF-derived severity that fails the gate: INFO, LOW, MEDIUM, HIGH, CRITICAL or none",
    )
    audit.add_argument(
        "--max-cases",
        type=int,
        default=DEFAULT_MAX_CASES,
        help=f"deterministic case budget (default: {DEFAULT_MAX_CASES})",
    )

    verify = subparsers.add_parser(
        "verify",
        help="verify executed adversarial cases against the offline oracle",
        description=f"Independently verify executed cases. {ATTRIBUTION}",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verify.add_argument("plan", help="path to a bolaforge plan.json")
    verify.add_argument("--results", required=True, help="path to executed results JSON")
    verify.add_argument(
        "--format", choices=("text", "json"), default="text", help="stdout format (default: text)"
    )
    verify.add_argument("--out", help="optional path for the JSON verification report")

    oracle = subparsers.add_parser(
        "oracle",
        help="evaluate a single authorization decision offline",
        description=f"Evaluate one actor/object/action decision. {ATTRIBUTION}",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    oracle.add_argument("--policy", required=True, help="path to the authorization policy document")
    oracle.add_argument("--fixtures", required=True, help="path to actor and object fixtures")
    oracle.add_argument("--actor", required=True, help="actor id from the fixtures")
    oracle.add_argument(
        "--object", required=True, dest="object_ref", help="object ref from the fixtures"
    )
    oracle.add_argument(
        "--action", required=True, help="action such as read, create, update or delete"
    )
    oracle.add_argument("--resource", help="override the object's policy resource")
    return parser


def _emit(payload: Any, output_format: str, text: str) -> None:
    if output_format == "text":
        print(text)
    else:
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))


def _run_audit(args: argparse.Namespace) -> int:
    spec = load_spec(args.spec)
    policy = AuthorizationPolicy.load(args.policy)
    actors, objects = load_fixtures(args.fixtures)
    operations = extract_operations(spec.document)
    findings = build_findings(operations, policy, actors, objects)
    cases, truncated = generate_cases(operations, actors, objects, policy, max_cases=args.max_cases)
    plan = AttackPlan(
        schema_version=PLAN_SCHEMA_VERSION,
        attribution=ATTRIBUTION,
        spec=spec.source,
        spec_digest=spec.digest,
        policy_digest=policy.digest,
        operations=operations,
        actors=actors,
        objects=objects,
        cases=cases,
        findings=findings,
        truncated=truncated,
    )
    sarif = build_sarif(plan, spec.source)
    if args.out:
        write_json(f"{args.out.rstrip('/')}/plan.json", plan.to_dict())
        write_json(f"{args.out.rstrip('/')}/findings.sarif", sarif)
    if args.format == "sarif":
        _emit(sarif, "json", "")
    elif args.format == "json":
        _emit(plan.to_dict(), "json", "")
    else:
        print(render_text(plan, spec.source))
        if truncated:
            print(
                f"WARNING: case budget of {args.max_cases} exhausted; plan is truncated.",
                file=sys.stderr,
            )
    if args.fail_on == "none":
        return 0
    threshold = Severity.parse(args.fail_on)
    worst = max(
        (finding.severity for finding in findings),
        default=Severity.INFO,
        key=lambda severity: severity.rank,
    )
    return 1 if worst.rank >= threshold.rank else 0


def _run_verify(args: argparse.Namespace) -> int:
    report = verify_files(args.plan, args.results)
    if args.out:
        write_json(args.out, report)
    if args.format == "json":
        _emit(report, "json", "")
    else:
        summary = ", ".join(f"{key}={value}" for key, value in sorted(report["summary"].items()))
        print(f"bolaforge verification — {ATTRIBUTION}")
        print(f"Verdicts: {summary or 'none'}")
        print(f"Result: {'PASS' if report['passed'] else 'FAIL'}")
        failures = [item for item in report["verdicts"] if item["verdict"] == "BOLA_CONFIRMED"]
        for failure in failures[:10]:
            print(
                f"  CONFIRMED {failure['case_id']} status={failure['status']} ({failure['technique']})"
            )
    return 0 if report["passed"] else 1


def _run_oracle(args: argparse.Namespace) -> int:
    policy = AuthorizationPolicy.load(args.policy)
    actors, objects = load_fixtures(args.fixtures)
    actor = next((item for item in actors if item.id == args.actor), None)
    obj = next((item for item in objects if item.ref == args.object_ref), None)
    if actor is None:
        raise BolaforgeError(f"unknown actor {args.actor!r}")
    if obj is None:
        raise BolaforgeError(f"unknown object {args.object_ref!r}")
    decision = policy.decide(actor, obj, args.action, args.resource)
    print(
        json.dumps(
            {
                "attribution": ATTRIBUTION,
                "actor": actor.id,
                "object": obj.ref,
                "action": args.action,
                **decision.to_dict(),
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""

    parser = _build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    try:
        if args.command == "audit":
            return _run_audit(args)
        if args.command == "verify":
            return _run_verify(args)
        if args.command == "oracle":
            return _run_oracle(args)
    except BolaforgeError as exc:
        print(f"bolaforge: error: {exc}", file=sys.stderr)
        print(f"bolaforge by {EMAIL}", file=sys.stderr)
        return 2
    except (ValueError, OSError) as exc:
        print(f"bolaforge: error: {exc}", file=sys.stderr)
        print(f"bolaforge by {EMAIL}", file=sys.stderr)
        return 2
    parser.print_help()
    return 0
