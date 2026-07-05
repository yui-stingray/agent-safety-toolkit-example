#!/usr/bin/env python3
"""Validate the public-safe agent-policy audit-event artifact."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path, PureWindowsPath
from typing import Any, Final

SCHEMA_VERSION: Final = "agent-policy.audit-event.public.v1"

TOP_LEVEL_KEYS: Final = {"repo", "capability", "context", "decision", "command", "path", "session_id"}
REQUIRED_TOP_LEVEL_KEYS: Final = {"repo", "capability", "context", "decision"}
CONTEXT_KEYS: Final = {"ownership_class", "first_write_to_repo"}
DECISION_KEYS: Final = {"mode", "reason", "matched_repo"}
CAPABILITIES: Final = {"read", "write", "artifact.publish", "push.force"}
DECISION_MODES: Final = {"auto_allow", "require_approval", "deny"}
OWNERSHIP_CLASSES: Final = {"internal", "external"}

SAFE_LABEL_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
SAFE_REPO_ALIAS_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
SAFE_REPO_PATH_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
WINDOWS_DRIVE_RE: Final = re.compile(r"^[A-Za-z]:[\\/]")
SECRETISH_RE: Final = re.compile(
    r"(github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})"
)


def load_event(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError("audit event must be readable JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("audit event must be a JSON object")
    return payload


def validate_event(payload: dict[str, Any]) -> None:
    _validate_keys(payload, allowed=TOP_LEVEL_KEYS, required=REQUIRED_TOP_LEVEL_KEYS, field="audit event")
    _validate_repo_alias(payload["repo"], field="repo")
    _validate_enum(payload["capability"], allowed=CAPABILITIES, field="capability")
    _validate_context(payload["context"])
    _validate_decision(payload["decision"])
    if "command" in payload:
        _validate_label(payload["command"], field="command")
    if "session_id" in payload:
        _validate_label(payload["session_id"], field="session_id")
    if "path" in payload:
        _validate_repo_path(payload["path"])


def _validate_keys(
    payload: dict[str, Any], *, allowed: set[str], required: set[str], field: str
) -> None:
    if any(not isinstance(key, str) or SECRETISH_RE.search(key) for key in payload):
        raise ValueError(f"{field} contains an unsafe field name")
    if set(payload) - allowed:
        raise ValueError(f"{field} contains unsupported fields")
    if required - set(payload):
        raise ValueError(f"{field} is missing required fields")


def _validate_context(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("context must be a JSON object")
    _validate_keys(value, allowed=CONTEXT_KEYS, required={"ownership_class"}, field="context")
    _validate_enum(value["ownership_class"], allowed=OWNERSHIP_CLASSES, field="ownership_class")
    if "first_write_to_repo" in value and not isinstance(value["first_write_to_repo"], bool):
        raise ValueError("first_write_to_repo must be a boolean")


def _validate_decision(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("decision must be a JSON object")
    _validate_keys(value, allowed=DECISION_KEYS, required=DECISION_KEYS, field="decision")
    _validate_enum(value["mode"], allowed=DECISION_MODES, field="decision.mode")
    _validate_label(value["reason"], field="decision.reason")
    matched_repo = value["matched_repo"]
    if matched_repo is not None:
        _validate_repo_alias(matched_repo, field="decision.matched_repo")


def _validate_enum(value: Any, *, allowed: set[str], field: str) -> None:
    if not isinstance(value, str) or SECRETISH_RE.search(value) or value not in allowed:
        raise ValueError(f"{field} must be a supported public value")


def _validate_label(value: Any, *, field: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    if SECRETISH_RE.search(value):
        raise ValueError(f"{field} must not contain secret-shaped material")
    if _looks_like_local_path(value):
        raise ValueError(f"{field} must not contain local path syntax")
    if not SAFE_LABEL_RE.fullmatch(value):
        raise ValueError(f"{field} must be a public-safe short label")


def _validate_repo_alias(value: Any, *, field: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    if SECRETISH_RE.search(value):
        raise ValueError(f"{field} must not contain secret-shaped material")
    if _looks_like_local_path(value):
        raise ValueError(f"{field} must not contain local path syntax")
    if not SAFE_REPO_ALIAS_RE.fullmatch(value):
        raise ValueError(f"{field} must be a public-safe repository alias")


def _validate_repo_path(value: Any) -> None:
    if not isinstance(value, str):
        raise ValueError("path must be a string")
    if SECRETISH_RE.search(value):
        raise ValueError("path must not contain secret-shaped material")
    if _looks_like_local_path(value):
        raise ValueError("path must not contain local path syntax")
    path = Path(value)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        raise ValueError("path must be repository-relative and must not contain parent traversal")
    if not SAFE_REPO_PATH_RE.fullmatch(value):
        raise ValueError("path must be a normalized repository-relative public path")
    if any(part in ("", ".") for part in path.parts):
        raise ValueError("path must be a normalized repository-relative public path")


def _looks_like_local_path(value: str) -> bool:
    windows_path = PureWindowsPath(value)
    return (
        value.startswith("~")
        or value.startswith("$")
        or value.lower().startswith("file:")
        or "\\" in value
        or WINDOWS_DRIVE_RE.match(value) is not None
        or bool(windows_path.drive or windows_path.root)
    )


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if len(args) != 1:
        print("usage: validate_policy_event.py <policy-admission-event.json>", file=sys.stderr)
        return 2
    try:
        payload = load_event(Path(args[0]))
        validate_event(payload)
    except ValueError as exc:
        print(f"invalid policy audit event: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"schema_version": SCHEMA_VERSION, "status": "ok"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
