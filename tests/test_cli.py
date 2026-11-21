"""End-to-end CLI contract tests.

Baysöz Labs <baysozlabs@proton.me>
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
BASE = [sys.executable, "-m", "bolaforge"]


def _run(*arguments):
    return subprocess.run(
        [*BASE, *arguments], cwd=ROOT, capture_output=True, text=True, check=False, timeout=30
    )


def test_version_and_help_carry_attribution() -> None:
    version = _run("--version")
    assert version.returncode == 0
    assert "bolaforge 1.0.0" in version.stdout
    assert "Baysöz Labs <baysozlabs@proton.me>" in version.stdout
    help_text = _run("--help")
    assert help_text.returncode == 0
    assert "Baysöz Labs <baysozlabs@proton.me>" in help_text.stdout
    assert (
        "audit" in help_text.stdout
        and "verify" in help_text.stdout
        and "oracle" in help_text.stdout
    )


def test_audit_outputs_json_and_sarif_and_gates(tmp_path) -> None:
    common = [
        "audit",
        str(EXAMPLES / "openapi.json"),
        "--policy",
        str(EXAMPLES / "policy.json"),
        "--fixtures",
        str(EXAMPLES / "fixtures.json"),
    ]
    gated = _run(*common, "--format", "json")
    assert gated.returncode == 1
    payload = json.loads(gated.stdout)
    assert payload["attribution"] == "Baysöz Labs <baysozlabs@proton.me>"
    assert payload["cases"] and payload["findings"]
    relaxed = _run(*common, "--format", "sarif", "--fail-on", "none")
    assert relaxed.returncode == 0
    sarif = json.loads(relaxed.stdout)
    assert sarif["version"] == "2.1.0"

    output_dir = tmp_path / "artifacts"
    output_dir.mkdir()
    written = _run(*common, "--out", str(output_dir), "--fail-on", "none")
    assert written.returncode == 0
    assert (output_dir / "plan.json").is_file()
    assert (output_dir / "findings.sarif").is_file()


def test_oracle_subcommand() -> None:
    result = _run(
        "oracle",
        "--policy",
        str(EXAMPLES / "policy.json"),
        "--fixtures",
        str(EXAMPLES / "fixtures.json"),
        "--actor",
        "user-alice",
        "--object",
        "acct-alice",
        "--action",
        "read",
        "--resource",
        "accounts",
    )
    assert result.returncode == 0
    decision = json.loads(result.stdout)
    assert decision["effect"] == "ALLOW"
    assert decision["attribution"] == "Baysöz Labs <baysozlabs@proton.me>"


def test_bad_input_reports_error_attribution() -> None:
    bad = _run(
        "audit",
        str(EXAMPLES / "openapi.json"),
        "--policy",
        "missing.json",
        "--fixtures",
        "missing.json",
    )
    assert bad.returncode == 2
    assert "Baysöz Labs" in bad.stderr or "baysozlabs@proton.me" in bad.stderr
