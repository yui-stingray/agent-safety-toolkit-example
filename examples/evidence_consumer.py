"""Delegate evidence validation to the installed agent-guard consumer."""

from agent_guard.consumer import main


if __name__ == "__main__":
    raise SystemExit(main())
