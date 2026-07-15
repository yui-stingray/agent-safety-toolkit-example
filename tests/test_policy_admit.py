from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.policy_event_contract import validate_public_audit_event

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "policy_admit.py"
VALIDATOR = ROOT / "scripts" / "validate_policy_event.py"
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


def run_validator(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VALIDATOR), str(path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def write_json(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return path


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
    assert payload["error"] == "repo-alias must be a public-safe repository alias"


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
    assert payload["error"] == "path must not contain local path syntax"


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
        assert payload["error"] == "path must not contain local path syntax"


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
        assert payload["error"] == "path must not contain local path syntax"


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
    assert payload["error"] == "command must be a public-safe short label"


def test_public_audit_event_validator_accepts_alias_event(tmp_path: Path) -> None:
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
    result = run_validator(write_json(tmp_path / "policy-admission-event.json", payload))
    assert result.returncode == 0, result.stderr
    validator_payload = json.loads(result.stdout)
    assert validator_payload == {"schema_version": "agent-policy.audit-event.public.v1", "status": "ok"}


def test_module_execution_uses_repo_contract_instead_of_cwd_shadow(tmp_path: Path) -> None:
    (tmp_path / "policy_event_contract.py").write_text(
        "ACTION_CAPABILITIES = {'read_docs': 'push.force'}\n"
        "PUBLIC_AUDIT_CAPABILITIES = frozenset({'fake.capability'})\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.policy_admit",
            "--policy",
            str(POLICY),
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
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["capability"] == "read"
    event_path = write_json(tmp_path / "policy-admission-event.json", payload)
    validation = subprocess.run(
        [sys.executable, "-m", "scripts.validate_policy_event", str(event_path)],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert validation.returncode == 0, validation.stderr
    assert json.loads(validation.stdout) == {
        "schema_version": "agent-policy.audit-event.public.v1",
        "status": "ok",
    }


def test_public_audit_event_validator_rejects_raw_repo_identifier(tmp_path: Path) -> None:
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
    result = run_validator(write_json(tmp_path / "policy-admission-event.json", payload))
    assert result.returncode == 1
    combined = result.stdout + result.stderr
    assert "repo must be a public-safe repository alias" in combined
    assert "yui-stingray/agent-safety-toolkit-example" not in combined


def test_public_audit_event_validator_rejects_unsupported_shape(tmp_path: Path) -> None:
    payload = {
        "capability": "read",
        "context": {"ownership_class": "internal"},
        "decision": {"matched_repo": "agent-safety-toolkit-example-public", "mode": "auto_allow", "reason": "repo_policy"},
        "extra": "not-public-contract",
        "repo": "agent-safety-toolkit-example-public",
    }

    result = run_validator(write_json(tmp_path / "policy-admission-event.json", payload))
    assert result.returncode == 1
    assert "audit event contains unsupported fields" in result.stderr


def test_shared_public_audit_contract_rejects_non_object() -> None:
    with pytest.raises(ValueError, match="audit event must be a JSON object"):
        validate_public_audit_event([])


def test_public_audit_event_validator_rejects_secret_without_leaking_value(tmp_path: Path) -> None:
    secret_value = "github_pat_" + ("0" * 20)
    payload = {
        "capability": "read",
        "context": {"ownership_class": "internal"},
        "decision": {"matched_repo": "agent-safety-toolkit-example-public", "mode": "auto_allow", "reason": "repo_policy"},
        "repo": "agent-safety-toolkit-example-public",
        "session_id": secret_value,
    }

    result = run_validator(write_json(tmp_path / "policy-admission-event.json", payload))
    assert result.returncode == 1
    combined = result.stdout + result.stderr
    assert "secret-shaped material" in combined
    assert secret_value not in combined
