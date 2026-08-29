#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON:-}"
if [ -z "$PYTHON_BIN" ]; then
  for candidate in python3.12 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 \
      && "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)' \
        >/dev/null 2>&1
    then
      PYTHON_BIN="$candidate"
      break
    fi
  done
fi

if [ -z "$PYTHON_BIN" ] \
  || ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)' \
    >/dev/null 2>&1
then
  echo "Python 3.12 is required; set PYTHON to a Python 3.12 executable." >&2
  exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
  echo "A timeout supervisor is required for the agent-guard 0.3.9 defense-in-depth static checks." >&2
  exit 1
fi

if [ "${1:-}" != "python" ] \
  || [ "${2:-}" != "-m" ] \
  || [ "${3:-}" != "agent_guard.cli" ]
then
  echo "agent-guard bounded execution failed" >&2
  exit 1
fi
shift 3

stdout_path=""
stderr_path=""
trap 'rm -f -- "$stdout_path" "$stderr_path"' EXIT

if ! stdout_path="$(mktemp "${TMPDIR:-/tmp}/agent-guard-bounded-stdout.XXXXXX" 2>/dev/null)" \
  || ! stderr_path="$(mktemp "${TMPDIR:-/tmp}/agent-guard-bounded-stderr.XXXXXX" 2>/dev/null)"
then
  echo "agent-guard bounded execution failed" >&2
  exit 1
fi

set +e
{
  timeout --signal=KILL 12s \
    "$PYTHON_BIN" -m agent_guard.cli "$@" \
    >"$stdout_path" 2>"$stderr_path"
} 2>>"$stderr_path"
status="$?"
set -e

if [ "$status" -eq 124 ] || [ "$status" -eq 137 ]; then
  echo "agent-guard execution exceeded the external execution budget" >&2
  exit 1
fi
if [ "$status" -ge 125 ]; then
  echo "agent-guard bounded execution failed" >&2
  exit 1
fi

cat -- "$stdout_path"
cat -- "$stderr_path" >&2
exit "$status"
