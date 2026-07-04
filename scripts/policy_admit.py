#!/usr/bin/env python3
"""Runtime admission wrapper for the safety evidence demo."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path, PureWindowsPath
from typing import Final

from agent_policy import PolicyDecision, audit_event_to_json, build_audit_event, evaluate, load_policy_file

DEFAULT_REPO: Final = "yui-stingray/agent-safety-toolkit-example"
DEFAULT_POLICY: Final = ".agent-policy/policy.toml"

ACTION_CAPABILITIES: Final[dict[str, str]] = {
    "read_docs": "read",
    "edit_docs": "write",
    "publish_release": "artifact.publish",
    "force_push": "push.force",
}
SAFE_LABEL_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
SAFE_REPO_ALIAS_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
SAFE_REPO_PATH_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
WINDOWS_DRIVE_RE: Final = re.compile(r"^[A-Za-z]:[\\/]")
SECRETISH_RE: Final = re.compile(
    r"(github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})"
)

EXIT_BY_MODE: Final[dict[str, int]] = {
    "auto_allow": 0,
    "require_approval": 2,
    "deny": 3,
}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="evaluate a normalized demo action")
    parser.add_argument("--policy", default=DEFAULT_POLICY, help="path to agent-policy TOML")
    parser.add_argument("--repo", default=DEFAULT_REPO, help="repository identifier")
    parser.add_argument(
        "--repo-alias",
        default=None,
        help="optional public-safe repository slug emitted in audit events; policy matching still uses --repo",
    )
    parser.add_argument("--action", required=True, choices=sorted(ACTION_CAPABILITIES), help="demo action")
    parser.add_argument(
        "--ownership-class",
        default="internal",
        choices=("internal", "external"),
        help="ownership class supplied to conditional hard guardrails",
    )
    parser.add_argument(
        "--first-write",
        action="store_true",
        help="mark this as the first mutating interaction with the target repository",
    )
    parser.add_argument(
        "--audit-event",
        action="store_true",
        help="emit the deterministic agent-policy audit event instead of the compact decision JSON",
    )
    parser.add_argument("--session-id", default=None, help="optional wrapper-owned session identifier")
    parser.add_argument("--command", default=None, help="optional wrapper-owned command label")
    parser.add_argument("--path", default=None, help="optional wrapper-owned repository-relative path")
    return parser.parse_args(argv)


def build_context(args: argparse.Namespace) -> dict[str, object]:
    context: dict[str, object] = {"ownership_class": args.ownership_class}
    if args.first_write:
        context["first_write_to_repo"] = True
    return context


def safe_optional_label(value: str | None, *, field: str) -> str | None:
    if value is None:
        return None
    if SECRETISH_RE.search(value):
        raise ValueError(f"{field} must not contain secret-shaped material")
    if not SAFE_LABEL_RE.fullmatch(value):
        raise ValueError(f"{field} must be a short non-secret label")
    return value


def safe_optional_repo_alias(value: str | None) -> str | None:
    if value is None:
        return None
    if SECRETISH_RE.search(value):
        raise ValueError("repo-alias must not contain secret-shaped material")
    if not SAFE_REPO_ALIAS_RE.fullmatch(value):
        raise ValueError("repo-alias must be a public-safe short slug")
    return value


def safe_optional_repo_path(value: str | None) -> str | None:
    if value is None:
        return None
    path = Path(value)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        raise ValueError("path must be repository-relative and must not contain parent traversal")
    windows_path = PureWindowsPath(value)
    if "\\" in value or WINDOWS_DRIVE_RE.match(value) or windows_path.drive or windows_path.root:
        raise ValueError("path must be repository-relative and must not contain local path syntax")
    if not SAFE_REPO_PATH_RE.fullmatch(value):
        raise ValueError("path must be a short repository-relative public path")
    if any(part in ("", ".") for part in path.parts):
        raise ValueError("path must be a normalized repository-relative public path")
    if SECRETISH_RE.search(value):
        raise ValueError("path must not contain secret-shaped material")
    return path.as_posix()


def emit(payload: dict[str, object]) -> None:
    print(json.dumps(payload, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(argv if argv is not None else sys.argv[1:]))
    capability = ACTION_CAPABILITIES[args.action]

    try:
        policy = load_policy_file(Path(args.policy))
        context = build_context(args)
        audit_repo_alias = safe_optional_repo_alias(args.repo_alias)
        audit_command = safe_optional_label(args.command, field="command")
        audit_session_id = safe_optional_label(args.session_id, field="session-id")
        audit_path = safe_optional_repo_path(args.path)
        decision = evaluate(
            policy,
            repo=args.repo,
            capability=capability,
            context=context,
        )
    except Exception as exc:
        emit(
            {
                "status": "error",
                "action": args.action,
                "capability": capability,
                "error": str(exc),
            }
        )
        return 1

    if args.audit_event:
        audit_repo = audit_repo_alias or args.repo
        audit_decision = decision
        if audit_repo_alias is not None:
            audit_decision = PolicyDecision(
                mode=decision.mode,
                reason=decision.reason,
                matched_repo=audit_repo if decision.matched_repo is not None else None,
            )
        event = build_audit_event(
            repo=audit_repo,
            capability=capability,
            context=context,
            decision=audit_decision,
            session_id=audit_session_id,
            command=audit_command,
            path=audit_path,
        )
        print(audit_event_to_json(event))
    else:
        payload = {
            "status": decision.mode,
            "action": args.action,
            "repo": args.repo,
            "capability": capability,
            "mode": decision.mode,
            "reason": decision.reason,
            "matched_repo": decision.matched_repo,
        }
        emit(payload)
    return EXIT_BY_MODE[decision.mode]


if __name__ == "__main__":
    raise SystemExit(main())
