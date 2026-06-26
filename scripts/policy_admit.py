#!/usr/bin/env python3
"""Runtime admission wrapper for the agent safety toolkit demo."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Final

from agent_policy import evaluate, load_policy_file

DEFAULT_REPO: Final = "yui-stingray/agent-safety-toolkit-example"
DEFAULT_POLICY: Final = ".agent-policy/policy.toml"

ACTION_CAPABILITIES: Final[dict[str, str]] = {
    "read_docs": "read",
    "edit_docs": "write",
    "publish_release": "artifact.publish",
    "force_push": "push.force",
}

EXIT_BY_MODE: Final[dict[str, int]] = {
    "auto_allow": 0,
    "require_approval": 2,
    "deny": 3,
}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="evaluate a normalized demo action")
    parser.add_argument("--policy", default=DEFAULT_POLICY, help="path to agent-policy TOML")
    parser.add_argument("--repo", default=DEFAULT_REPO, help="repository identifier")
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
    return parser.parse_args(argv)


def build_context(args: argparse.Namespace) -> dict[str, object]:
    context: dict[str, object] = {"ownership_class": args.ownership_class}
    if args.first_write:
        context["first_write_to_repo"] = True
    return context


def emit(payload: dict[str, object]) -> None:
    print(json.dumps(payload, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(argv if argv is not None else sys.argv[1:]))
    capability = ACTION_CAPABILITIES[args.action]

    try:
        policy = load_policy_file(Path(args.policy))
        decision = evaluate(
            policy,
            repo=args.repo,
            capability=capability,
            context=build_context(args),
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
