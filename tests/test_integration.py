"""Live adversarial execution against a local HTTP oracle server.

The Supreme Grand Jury Tribunal uses this test to confirm that emitted cases
are executable requests, not placeholders, and that the verifier detects real
authorization failures.

Baysöz Labs <baysozlabs@proton.me>
"""

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from bolaforge.analyze import build_findings, extract_operations
from bolaforge.attribution import ATTRIBUTION
from bolaforge.generate import generate_cases
from bolaforge.models import AttackPlan, Effect
from bolaforge.policy import AuthorizationPolicy, load_fixtures
from bolaforge.render import PLAN_SCHEMA_VERSION
from bolaforge.spec import load_spec
from bolaforge.verify import verify_plan


class _OracleHandler(BaseHTTPRequestHandler):
    expectations: dict[str, str] = {}
    always_allow = False

    def _respond(self) -> None:
        case_id = self.headers.get("X-Bola-Case-Id", "")
        expected = self.expectations.get(case_id, "DENY")
        status = 200 if self.always_allow or expected == "ALLOW" else 403
        payload = json.dumps({"case": case_id, "status": status}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _respond
    do_POST = _respond
    do_PUT = _respond
    do_PATCH = _respond
    do_DELETE = _respond

    def log_message(self, format: str, *args: object) -> None:
        return


def _start_server(expectations: dict[str, str], always_allow: bool):
    handler = type(
        "BoundOracleHandler",
        (_OracleHandler,),
        {
            "expectations": expectations,
            "always_allow": always_allow,
        },
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _execute(server, cases) -> list[dict[str, object]]:
    port = server.server_address[1]
    results: list[dict[str, object]] = []
    for case in cases:
        headers = dict(case.request["headers"])
        headers["X-Bola-Case-Id"] = case.id
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}{case.request['path']}",
            method=case.method,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                status = response.status
                evidence = response.read(256).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            status = exc.code
            evidence = exc.read(256).decode("utf-8", errors="replace")
        results.append({"case_id": case.id, "status": status, "evidence": evidence})
    return results


def _tribunal_plan():
    spec = load_spec("examples/openapi.json")
    policy = AuthorizationPolicy.load("examples/policy.json")
    actors, objects = load_fixtures("examples/fixtures.json")
    operations = extract_operations(spec.document)
    cases, _ = generate_cases(operations, actors, objects, policy)
    selected = tuple(cases[:6] + cases[-6:])
    plan = AttackPlan(
        schema_version=PLAN_SCHEMA_VERSION,
        attribution=ATTRIBUTION,
        spec=spec.source,
        spec_digest=spec.digest,
        policy_digest=policy.digest,
        operations=operations,
        actors=actors,
        objects=objects,
        cases=selected,
        findings=build_findings(operations, policy, actors, objects),
    )
    return plan, selected


def test_live_cases_pass_when_authorization_is_enforced() -> None:
    plan, selected = _tribunal_plan()
    expectations = {case.id: case.expected.value for case in selected}
    server, thread = _start_server(expectations, always_allow=False)
    try:
        results = _execute(server, selected)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert len(results) == len(selected)
    assert all(isinstance(item["status"], int) for item in results)
    report = verify_plan(plan, results)
    assert report["passed"] is True, report["summary"]


def test_live_cases_detect_broken_authorization() -> None:
    plan, selected = _tribunal_plan()
    assert any(case.expected is Effect.DENY for case in selected)
    expectations = {case.id: case.expected.value for case in selected}
    server, thread = _start_server(expectations, always_allow=True)
    try:
        results = _execute(server, selected)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    report = verify_plan(plan, results)
    assert report["passed"] is False
    assert report["summary"].get("BOLA_CONFIRMED", 0) > 0
