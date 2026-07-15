#!/usr/bin/env python3
"""Validate the public-safe agent-policy audit-event artifact."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

if __package__:
    from .policy_event_contract import PUBLIC_AUDIT_SCHEMA_VERSION, validate_public_audit_event
else:
    from policy_event_contract import PUBLIC_AUDIT_SCHEMA_VERSION, validate_public_audit_event


def load_event(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError("audit event must be readable JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("audit event must be a JSON object")
    return payload


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if len(args) != 1:
        print("usage: validate_policy_event.py <policy-admission-event.json>", file=sys.stderr)
        return 2
    try:
        payload = load_event(Path(args[0]))
        validate_public_audit_event(payload)
    except ValueError as exc:
        print(f"invalid policy audit event: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"schema_version": PUBLIC_AUDIT_SCHEMA_VERSION, "status": "ok"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
