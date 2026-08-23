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


def run_admit(*extra: str, policy: Path = POLICY) -> tuple[int, dict[str, object]]:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--policy", str(policy), *extra],
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


def write_policy(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def public_audit_event(path: str) -> dict[str, object]:
    return {
        "capability": "read",
        "context": {"ownership_class": "internal"},
        "decision": {
            "matched_repo": "agent-safety-toolkit-example-public",
            "mode": "auto_allow",
            "reason": "repo_policy",
        },
        "path": path,
        "repo": "agent-safety-toolkit-example-public",
    }


def test_malformed_invocation_returns_exit_one_without_echoing_input() -> None:
    marker = "untrusted-action-marker"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--action", marker],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "policy-admit invocation is invalid\n"
    assert marker not in result.stdout + result.stderr


def test_current_policy_passes_toolkit_preflight_and_allows_read_docs() -> None:
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


def test_policy_preflight_rejects_unknown_capability_with_fixed_public_error(tmp_path: Path) -> None:
    marker = "wirte"
    policy = write_policy(
        tmp_path / "policy.toml",
        """default_mode = "auto_allow"

[[repo_policy]]
repo = "demo/repo"
ownership_class = "internal"

[repo_policy.capabilities]
wirte = "require_approval"
""",
    )

    code, payload = run_admit(
        "--action",
        "edit_docs",
        "--repo",
        "demo/repo",
        "--ownership-class",
        "internal",
        policy=policy,
    )

    assert code == 1
    assert payload["status"] == "error"
    assert payload["error"] == "policy evaluation failed"
    assert marker not in json.dumps(payload, sort_keys=True)


@pytest.mark.parametrize(
    ("first_mode", "second_mode"),
    (("auto_allow", "deny"), ("deny", "auto_allow")),
)
def test_policy_preflight_rejects_same_scope_conflicts_in_either_order(
    tmp_path: Path,
    first_mode: str,
    second_mode: str,
) -> None:
    policy = write_policy(
        tmp_path / "policy.toml",
        f"""default_mode = "require_approval"

[[repo_policy]]
repo = "demo/repo"
ownership_class = "internal"

[repo_policy.capabilities]
write = "{first_mode}"

[[repo_policy]]
repo = "demo/repo"
ownership_class = "internal"

[repo_policy.capabilities]
write = "{second_mode}"
""",
    )

    code, payload = run_admit(
        "--action",
        "edit_docs",
        "--repo",
        "demo/repo",
        "--ownership-class",
        "internal",
        policy=policy,
    )

    assert code == 1
    assert payload["status"] == "error"
    assert payload["error"] == "policy evaluation failed"


def test_policy_preflight_rejects_wildcard_ownership_conflicts(tmp_path: Path) -> None:
    policy = write_policy(
        tmp_path / "policy.toml",
        """default_mode = "require_approval"

[[repo_policy]]
repo = "demo/repo"

[repo_policy.capabilities]
write = "auto_allow"

[[repo_policy]]
repo = "demo/repo"
ownership_class = "internal"

[repo_policy.capabilities]
write = "deny"
""",
    )

    code, payload = run_admit(
        "--action",
        "edit_docs",
        "--repo",
        "demo/repo",
        "--ownership-class",
        "internal",
        policy=policy,
    )

    assert code == 1
    assert payload["status"] == "error"
    assert payload["error"] == "policy evaluation failed"


def test_policy_preflight_preserves_identical_duplicates(tmp_path: Path) -> None:
    policy = write_policy(
        tmp_path / "policy.toml",
        """default_mode = "auto_allow"

[[repo_policy]]
repo = "demo/repo"
ownership_class = "internal"

[repo_policy.capabilities]
write = "require_approval"

[[repo_policy]]
repo = "demo/repo"
ownership_class = "internal"

[repo_policy.capabilities]
write = "require_approval"
""",
    )

    code, payload = run_admit(
        "--action",
        "edit_docs",
        "--repo",
        "demo/repo",
        "--ownership-class",
        "internal",
        policy=policy,
    )

    assert code == 2
    assert payload["mode"] == "require_approval"
    assert payload["reason"] == "repo_policy"


def test_policy_preflight_preserves_disjoint_ownership_scopes(tmp_path: Path) -> None:
    policy = write_policy(
        tmp_path / "policy.toml",
        """default_mode = "require_approval"

[[repo_policy]]
repo = "demo/repo"
ownership_class = "internal"

[repo_policy.capabilities]
write = "auto_allow"

[[repo_policy]]
repo = "demo/repo"
ownership_class = "external"

[repo_policy.capabilities]
write = "deny"
""",
    )

    internal_code, internal_payload = run_admit(
        "--action",
        "edit_docs",
        "--repo",
        "demo/repo",
        "--ownership-class",
        "internal",
        policy=policy,
    )
    external_code, external_payload = run_admit(
        "--action",
        "edit_docs",
        "--repo",
        "demo/repo",
        "--ownership-class",
        "external",
        policy=policy,
    )

    assert internal_code == 0
    assert internal_payload["mode"] == "auto_allow"
    assert external_code == 3
    assert external_payload["mode"] == "deny"


def test_policy_preflight_allows_capability_omission_for_default_mode(tmp_path: Path) -> None:
    policy = write_policy(
        tmp_path / "policy.toml",
        """default_mode = "auto_allow"

[[repo_policy]]
repo = "demo/repo"
ownership_class = "internal"

[repo_policy.capabilities]
read = "auto_allow"
""",
    )

    code, payload = run_admit(
        "--action",
        "edit_docs",
        "--repo",
        "demo/repo",
        "--ownership-class",
        "internal",
        policy=policy,
    )

    assert code == 0
    assert payload["mode"] == "auto_allow"
    assert payload["reason"] == "default_mode"


def test_audit_event_is_deterministic_and_wrapper_owned() -> None:
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
    assert payload == {
        "capability": "read",
        "command": "read_docs",
        "context": {"ownership_class": "internal"},
        "decision": {
            "matched_repo": "agent-safety-toolkit-example-public",
            "mode": "auto_allow",
            "reason": "repo_policy",
        },
        "path": "README.md",
        "repo": "agent-safety-toolkit-example-public",
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
        "--repo-alias",
        "agent-safety-toolkit-example-public",
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
            "--repo-alias",
            "agent-safety-toolkit-example-public",
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
            "--repo-alias",
            "agent-safety-toolkit-example-public",
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
        "--repo-alias",
        "agent-safety-toolkit-example-public",
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
        "--repo-alias",
        "agent-safety-toolkit-example-public",
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


def test_shared_public_audit_contract_accepts_canonical_repo_path() -> None:
    validate_public_audit_event(public_audit_event("docs/adoption-recipe.md"))


@pytest.mark.parametrize("path", ("docs//adoption-recipe.md", "docs/./adoption-recipe.md", "docs/"))
def test_shared_public_audit_contract_rejects_noncanonical_repo_path(path: str) -> None:
    with pytest.raises(ValueError, match="path must be a normalized repository-relative public path"):
        validate_public_audit_event(public_audit_event(path))


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


def test_audit_event_requires_alias_without_emitting_raw_repo() -> None:
    raw_repo = "private-repository-label"
    code, payload = run_admit(
        "--action",
        "read_docs",
        "--repo",
        raw_repo,
        "--ownership-class",
        "internal",
        "--audit-event",
        "--command",
        "read_docs",
        "--path",
        "README.md",
    )

    assert code == 1
    assert payload["status"] == "error"
    assert payload["error"] == "repo-alias is required when --audit-event is used"
    assert raw_repo not in json.dumps(payload, sort_keys=True)


def test_policy_load_error_does_not_emit_path(tmp_path: Path) -> None:
    marker = "not-public-policy-location"
    missing_policy = tmp_path / marker / "policy.toml"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--policy",
            str(missing_policy),
            "--action",
            "read_docs",
            "--repo",
            "yui-stingray/agent-safety-toolkit-example",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert marker not in result.stdout + result.stderr
    assert json.loads(result.stdout)["error"] == "policy evaluation failed"


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
