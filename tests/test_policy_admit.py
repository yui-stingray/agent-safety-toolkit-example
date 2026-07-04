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


def test_audit_event_is_deterministic_and_wrapper_owned() -> None:
    code, payload = run_admit(
        "--action",
        "read_docs",
        "--repo",
        "yui-stingray/agent-safety-toolkit-example",
        "--ownership-class",
        "internal",
        "--audit-event",
        "--command",
        "read_docs",
        "--path",
        "README.md",
    )

    assert code == 0
    assert payload == {
        "capability": "read",
        "command": "read_docs",
        "context": {"ownership_class": "internal"},
        "decision": {
            "matched_repo": "yui-stingray/agent-safety-toolkit-example",
            "mode": "auto_allow",
            "reason": "repo_policy",
        },
        "path": "README.md",
        "repo": "yui-stingray/agent-safety-toolkit-example",
    }
    assert "event_id" not in payload
    assert "timestamp" not in payload


def test_audit_event_uses_public_repo_alias() -> None:
    code, payload = run_admit(
        "--action",
        "read_docs",
        "--repo",
        "yui-stingray/agent-safety-toolkit-example",
        "--repo-alias",
        "agent-safety-toolkit-example-public",
        "--ownership-class",
        "internal",
        "--audit-event",
        "--command",
        "read_docs",
        "--path",
        "README.md",
    )

    assert code == 0
    assert payload["repo"] == "agent-safety-toolkit-example-public"
    assert payload["decision"]["matched_repo"] == "agent-safety-toolkit-example-public"
    assert payload["decision"]["mode"] == "auto_allow"


def test_audit_event_rejects_path_like_repo_alias() -> None:
    code, payload = run_admit(
        "--action",
        "read_docs",
        "--repo",
        "yui-stingray/agent-safety-toolkit-example",
        "--repo-alias",
        "owner/private-repo",
        "--ownership-class",
        "internal",
        "--audit-event",
    )

    assert code == 1
    assert payload["status"] == "error"
    assert payload["error"] == "repo-alias must be a public-safe short slug"


def test_audit_event_rejects_absolute_path() -> None:
    code, payload = run_admit(
        "--action",
        "read_docs",
        "--repo",
        "yui-stingray/agent-safety-toolkit-example",
        "--ownership-class",
        "internal",
        "--audit-event",
        "--path",
        "/tmp/private-note.txt",
    )

    assert code == 1
    assert payload["status"] == "error"
    assert payload["error"] == "path must be repository-relative and must not contain parent traversal"


def test_audit_event_rejects_windows_local_path() -> None:
    backslash_path = "C:" + "\\" + "Users" + "\\" + "sample" + "\\" + "private" + "\\" + "note.txt"
    slash_path = "C:" + "/" + "Users" + "/" + "sample" + "/" + "private" + "/" + "note.txt"
    for raw_path in (backslash_path, slash_path):
        code, payload = run_admit(
            "--action",
            "read_docs",
            "--repo",
            "yui-stingray/agent-safety-toolkit-example",
            "--ownership-class",
            "internal",
            "--audit-event",
            "--path",
            raw_path,
        )

        assert code == 1
        assert payload["status"] == "error"
        assert payload["error"] == "path must be repository-relative and must not contain local path syntax"


def test_audit_event_rejects_local_path_shorthand_and_uri() -> None:
    home_path = "~" + "/" + ".ssh" + "/" + "id_rsa"
    env_path = "$" + "HOME" + "/" + ".ssh" + "/" + "id_rsa"
    uri_path = "file:" + "/" + "/" + "/" + "tmp" + "/" + "private-note.txt"
    for raw_path in (home_path, env_path, uri_path):
        code, payload = run_admit(
            "--action",
            "read_docs",
            "--repo",
            "yui-stingray/agent-safety-toolkit-example",
            "--ownership-class",
            "internal",
            "--audit-event",
            "--path",
            raw_path,
        )

        assert code == 1
        assert payload["status"] == "error"
        assert payload["error"] == "path must be a short repository-relative public path"


def test_audit_event_rejects_secret_shaped_session_id() -> None:
    code, payload = run_admit(
        "--action",
        "read_docs",
        "--repo",
        "yui-stingray/agent-safety-toolkit-example",
        "--ownership-class",
        "internal",
        "--audit-event",
        "--session-id",
        "github_pat_" + ("0" * 20),
    )

    assert code == 1
    assert payload["status"] == "error"
    assert payload["error"] == "session-id must not contain secret-shaped material"


def test_audit_event_rejects_command_text() -> None:
    code, payload = run_admit(
        "--action",
        "read_docs",
        "--repo",
        "yui-stingray/agent-safety-toolkit-example",
        "--ownership-class",
        "internal",
        "--audit-event",
        "--command",
        "cat /tmp/private-token.txt",
    )

    assert code == 1
    assert payload["status"] == "error"
    assert payload["error"] == "command must be a short non-secret label"
