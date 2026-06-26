from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "policy_admit.py"
POLICY = ROOT / ".agent-policy" / "policy.toml"


def run_admit(*extra: str) -> tuple[int, dict[str, object]]:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--policy", str(POLICY), *extra],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.stdout, result.stderr
    return result.returncode, json.loads(result.stdout)


def test_read_docs_is_auto_allowed() -> None:
    code, payload = run_admit(
        "--action",
        "read_docs",
        "--repo",
        "yui-stingray/agent-safety-toolkit-example",
        "--ownership-class",
        "internal",
    )

    assert code == 0
    assert payload["mode"] == "auto_allow"
    assert payload["capability"] == "read"
    assert payload["reason"] == "repo_policy"


def test_edit_docs_requires_approval() -> None:
    code, payload = run_admit(
        "--action",
        "edit_docs",
        "--repo",
        "yui-stingray/agent-safety-toolkit-example",
        "--ownership-class",
        "internal",
    )

    assert code == 2
    assert payload["mode"] == "require_approval"
    assert payload["capability"] == "write"
    assert payload["reason"] == "repo_policy"


def test_publish_release_requires_approval() -> None:
    code, payload = run_admit(
        "--action",
        "publish_release",
        "--repo",
        "yui-stingray/agent-safety-toolkit-example",
        "--ownership-class",
        "internal",
    )

    assert code == 2
    assert payload["mode"] == "require_approval"
    assert payload["capability"] == "artifact.publish"
    assert payload["reason"] == "repo_policy"


def test_force_push_is_denied_by_hard_guardrail() -> None:
    code, payload = run_admit(
        "--action",
        "force_push",
        "--repo",
        "yui-stingray/agent-safety-toolkit-example",
        "--ownership-class",
        "internal",
    )

    assert code == 3
    assert payload["mode"] == "deny"
    assert payload["capability"] == "push.force"
    assert payload["reason"] == "hard_guardrail"


def test_external_first_write_requires_approval() -> None:
    code, payload = run_admit(
        "--action",
        "edit_docs",
        "--repo",
        "external/example",
        "--ownership-class",
        "external",
        "--first-write",
    )

    assert code == 2
    assert payload["mode"] == "require_approval"
    assert payload["reason"] == "hard_guardrail"
