#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -n "${PYTHON:-}" ]; then
  PYTHON_BIN="$PYTHON"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
else
  PYTHON_BIN="python"
fi

CONTENT_TARGETS=(
  AGENTS.md
  README.md
  CONTRIBUTING.md
  SECURITY.md
  CODE_OF_CONDUCT.md
  docs
  examples
  scripts
  tests
  .github
  .agent-policy
  requirements
  pyproject.toml
)
EVIDENCE_DIR=".agent-guard/evidence"

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

mkdir -p "$EVIDENCE_DIR"
"$PYTHON_BIN" scripts/policy_admit.py \
  --action read_docs \
  --repo yui-stingray/agent-safety-toolkit-example \
  --repo-alias agent-safety-toolkit-example-public \
  --ownership-class internal \
  --audit-event \
  --command read_docs \
  --path README.md \
  > "$EVIDENCE_DIR/policy-admission-event.json"
"$PYTHON_BIN" scripts/validate_policy_event.py "$EVIDENCE_DIR/policy-admission-event.json"

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
"$PYTHON_BIN" -m agent_guard.cli context check --root . --policy .agent-guard/context-policy.yaml --json
"$PYTHON_BIN" -m agent_guard.cli context inventory --root . --policy .agent-guard/context-policy.yaml --json
"$PYTHON_BIN" -m agent_guard.cli surface inventory \
  --root . \
  --context-policy .agent-guard/context-policy.yaml \
  --schema-version v2 \
  --json \
  > "$EVIDENCE_DIR/agent-surface-inventory.json"
"$PYTHON_BIN" -m agent_guard.cli context lock \
  --root . \
  --policy .agent-guard/context-policy.yaml \
  --check \
  --digest-policy .agent-guard/context-digest-policy.yaml \
  --json
"$PYTHON_BIN" -m agent_guard.cli content check \
  --repo-root . \
  --policy .agent-guard/content-policy.yaml \
  --mode preregister \
  --targets "${CONTENT_TARGETS[@]}" \
  --json
"$PYTHON_BIN" -m agent_guard.cli api check --root . --policy .agent-guard/api-policy.yaml --json
"$PYTHON_BIN" -m agent_guard.cli mcp check --root . --policy .agent-guard/mcp-policy.yaml --json
"$PYTHON_BIN" -m agent_guard.cli digest check --root . --policy .agent-guard/context-digest-policy.yaml --json
"$PYTHON_BIN" -m agent_guard.cli workflow check --root . --policy .agent-guard/workflow-policy.yaml --json
"$PYTHON_BIN" -m agent_guard.cli drift check --root . --profile recommended --schema-version v2 --json
"$PYTHON_BIN" -m agent_guard.cli report \
  --root . \
  --context-policy .agent-guard/context-policy.yaml \
  --evidence-preset recommended \
  --api-policy .agent-guard/api-policy.yaml \
  --mcp-policy .agent-guard/mcp-policy.yaml \
  --digest-policy .agent-guard/context-digest-policy.yaml \
  --agent-policy-audit-event "$EVIDENCE_DIR/policy-admission-event.json" \
  --format json \
  --output "$EVIDENCE_DIR/agent-guard-report.json"
"$PYTHON_BIN" -m agent_guard.cli conformance check \
  --root . \
  --evidence "$EVIDENCE_DIR/agent-guard-report.json" \
  --profile recommended \
  --json
"$PYTHON_BIN" -m agent_guard.cli evidence-pack manifest \
  --root . \
  --report "$EVIDENCE_DIR/agent-guard-report.json" \
  --artifact "$EVIDENCE_DIR/agent-surface-inventory.json" \
  --artifact "$EVIDENCE_DIR/agent-guard-report.json" \
  --agent-policy-audit-event "$EVIDENCE_DIR/policy-admission-event.json" \
  --json \
  > "$EVIDENCE_DIR/evidence-pack-manifest.json"
"$PYTHON_BIN" examples/evidence_consumer.py "$EVIDENCE_DIR/agent-guard-report.json"
