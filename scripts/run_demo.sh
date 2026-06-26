#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -n "${PYTHON:-}" ]; then
  PYTHON_BIN="$PYTHON"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  PYTHON_BIN="python3"
fi

CONTENT_TARGETS=(
  README.md
  CONTRIBUTING.md
  SECURITY.md
  CODE_OF_CONDUCT.md
  docs
  scripts
  tests
  .github
  .agent-policy
  requirements
  pyproject.toml
)

expect_exit() {
  expected="$1"
  shift
  set +e
  "$@"
  status="$?"
  set -e
  if [ "$status" -ne "$expected" ]; then
    echo "expected exit $expected but got $status: $*" >&2
    exit 1
  fi
}

"$PYTHON_BIN" scripts/policy_admit.py \
  --action read_docs \
  --repo yui-stingray/agent-safety-toolkit-example \
  --ownership-class internal

expect_exit 2 "$PYTHON_BIN" scripts/policy_admit.py \
  --action edit_docs \
  --repo yui-stingray/agent-safety-toolkit-example \
  --ownership-class internal

expect_exit 2 "$PYTHON_BIN" scripts/policy_admit.py \
  --action publish_release \
  --repo yui-stingray/agent-safety-toolkit-example \
  --ownership-class internal

expect_exit 3 "$PYTHON_BIN" scripts/policy_admit.py \
  --action force_push \
  --repo yui-stingray/agent-safety-toolkit-example \
  --ownership-class internal

expect_exit 2 "$PYTHON_BIN" scripts/policy_admit.py \
  --action edit_docs \
  --repo external/example \
  --ownership-class external \
  --first-write

"$PYTHON_BIN" -m agent_guard.cli path check --root . --policy .agent-guard/path-policy.yaml --json
"$PYTHON_BIN" -m agent_guard.cli content check \
  --repo-root . \
  --policy .agent-guard/content-policy.yaml \
  --mode preregister \
  --targets "${CONTENT_TARGETS[@]}" \
  --json
"$PYTHON_BIN" -m agent_guard.cli api check --root . --policy .agent-guard/api-policy.yaml --json
"$PYTHON_BIN" -m agent_guard.cli digest check --root . --policy .agent-guard/digest-policy.yaml --json
