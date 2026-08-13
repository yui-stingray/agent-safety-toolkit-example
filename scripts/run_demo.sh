#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON_BIN="${PYTHON:-}"
if [ -z "$PYTHON_BIN" ]; then
  for candidate in python3.12 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 \
      && "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)'
    then
      PYTHON_BIN="$candidate"
      break
    fi
  done
fi

if [ -z "$PYTHON_BIN" ]; then
  echo "Python 3.12 is required; set PYTHON to a Python 3.12 executable." >&2
  exit 1
fi

if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)'; then
  echo "Python 3.12 is required; set PYTHON to a Python 3.12 executable." >&2
  exit 1
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
AUDIT_EVENT_DIR=".agent-policy/evidence"
AUDIT_EVENT_PATH="$AUDIT_EVENT_DIR/policy-admission-event.json"
AUDIT_EVENT_STAGE="$AUDIT_EVENT_DIR/.policy-admission-event.json.tmp"
SURFACE_INVENTORY_TMP=""
REPORT_PATH="$EVIDENCE_DIR/agent-guard-report.json"
EVIDENCE_PACK_PATH="$EVIDENCE_DIR/agent-guard-evidence-pack.json"
EVIDENCE_PACK_STAGE="$EVIDENCE_DIR/.agent-guard-evidence-pack.json.tmp"
BACKUP_DIR=""
BACKUP_READY=0
EVIDENCE_EXISTED=0
AUDIT_EVENT_EXISTED=0
PUBLISH_COMPLETE=0
DECISION_OUTPUT=""

for evidence_path in \
  ".agent-guard" \
  "$EVIDENCE_DIR" \
  ".agent-policy" \
  "$AUDIT_EVENT_DIR" \
  "$AUDIT_EVENT_PATH"
do
  if [ -L "$evidence_path" ]; then
    echo "Evidence directories and artifact paths must not be symbolic links." >&2
    exit 1
  fi
done

if [ -e "$EVIDENCE_DIR" ] && [ ! -d "$EVIDENCE_DIR" ]; then
  echo "The evidence path must be a regular directory." >&2
  exit 1
fi

if [ -d "$EVIDENCE_DIR" ]; then
  "$PYTHON_BIN" - "$EVIDENCE_DIR" <<'PY'
import sys
from pathlib import Path

evidence_dir = Path(sys.argv[1])
expected = {"agent-guard-evidence-pack.json", "agent-guard-report.json"}
entries = list(evidence_dir.iterdir())
if (
    {entry.name for entry in entries} - expected
    or any(entry.is_symlink() or not entry.is_file() for entry in entries)
):
    raise SystemExit(
        "Evidence directory contains unexpected entries; move them before running the demo."
    )
PY
fi

cleanup() {
  status="$?"
  trap - EXIT
  set +e
  if [ -n "$SURFACE_INVENTORY_TMP" ]; then
    rm -f -- "$SURFACE_INVENTORY_TMP"
  fi
  if [ -n "$DECISION_OUTPUT" ]; then
    rm -f -- "$DECISION_OUTPUT"
  fi
  rm -f -- "$AUDIT_EVENT_STAGE" "$EVIDENCE_PACK_STAGE"
  if [ "$BACKUP_READY" -eq 1 ] && [ "$PUBLISH_COMPLETE" -ne 1 ]; then
    rm -rf -- "$EVIDENCE_DIR"
    if [ "$EVIDENCE_EXISTED" -eq 1 ]; then
      mkdir -p -- "$(dirname "$EVIDENCE_DIR")"
      mv -- "$BACKUP_DIR/agent-guard-evidence" "$EVIDENCE_DIR"
    fi
    rm -f -- "$AUDIT_EVENT_PATH"
    if [ "$AUDIT_EVENT_EXISTED" -eq 1 ]; then
      mkdir -p -- "$AUDIT_EVENT_DIR"
      mv -- "$BACKUP_DIR/policy-admission-event.json" "$AUDIT_EVENT_PATH"
    fi
  fi
  if [ -n "$BACKUP_DIR" ]; then
    rm -rf -- "$BACKUP_DIR"
  fi
  exit "$status"
}
trap cleanup EXIT

expect_decision() {
  expected="$1"
  expected_mode="$2"
  expected_capability="$3"
  expected_reason="$4"
  shift 4
  DECISION_OUTPUT="$(mktemp "${TMPDIR:-/tmp}/agent-policy-decision.XXXXXX.json")"
  set +e
  "$@" > "$DECISION_OUTPUT"
  status="$?"
  set -e
  if [ "$status" -ne "$expected" ]; then
    rm -f -- "$DECISION_OUTPUT"
    DECISION_OUTPUT=""
    echo "unexpected policy decision exit status" >&2
    return 1
  fi
  if ! "$PYTHON_BIN" - "$DECISION_OUTPUT" "$expected_mode" "$expected_capability" "$expected_reason" <<'PY'
import json
import sys
from pathlib import Path

try:
    payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    expected = dict(zip(("mode", "capability", "reason"), sys.argv[2:]))
    if not isinstance(payload, dict) or any(payload.get(field) != value for field, value in expected.items()):
        raise ValueError
except (OSError, TypeError, ValueError):
    raise SystemExit(1)
PY
  then
    rm -f -- "$DECISION_OUTPUT"
    DECISION_OUTPUT=""
    echo "decision JSON does not match expected identity" >&2
    return 1
  fi
  rm -f -- "$DECISION_OUTPUT"
  DECISION_OUTPUT=""
}

expect_decision 0 auto_allow read repo_policy \
  "$PYTHON_BIN" scripts/policy_admit.py \
  --action read_docs \
  --repo yui-stingray/agent-safety-toolkit-example \
  --ownership-class internal

BACKUP_DIR="$(mktemp -d "$ROOT/../.agent-safety-toolkit-example-evidence.XXXXXX")"
if [ -d "$EVIDENCE_DIR" ]; then
  cp -a -- "$EVIDENCE_DIR" "$BACKUP_DIR/agent-guard-evidence"
  EVIDENCE_EXISTED=1
fi
if [ -f "$AUDIT_EVENT_PATH" ]; then
  cp -p -- "$AUDIT_EVENT_PATH" "$BACKUP_DIR/policy-admission-event.json"
  AUDIT_EVENT_EXISTED=1
fi
BACKUP_READY=1

rm -rf -- "$EVIDENCE_DIR"
mkdir -p "$EVIDENCE_DIR" "$AUDIT_EVENT_DIR"
rm -f -- "$AUDIT_EVENT_STAGE" "$EVIDENCE_PACK_STAGE"
SURFACE_INVENTORY_TMP="$(mktemp "${TMPDIR:-/tmp}/agent-surface-inventory.XXXXXX.json")"
"$PYTHON_BIN" scripts/policy_admit.py \
  --action read_docs \
  --repo yui-stingray/agent-safety-toolkit-example \
  --repo-alias agent-safety-toolkit-example-public \
  --ownership-class internal \
  --audit-event \
  --command read_docs \
  --path README.md \
  > "$AUDIT_EVENT_STAGE"
"$PYTHON_BIN" scripts/validate_policy_event.py "$AUDIT_EVENT_STAGE"
mv -- "$AUDIT_EVENT_STAGE" "$AUDIT_EVENT_PATH"

expect_decision 2 require_approval write repo_policy \
  "$PYTHON_BIN" scripts/policy_admit.py \
  --action edit_docs \
  --repo yui-stingray/agent-safety-toolkit-example \
  --ownership-class internal

expect_decision 2 require_approval artifact.publish repo_policy \
  "$PYTHON_BIN" scripts/policy_admit.py \
  --action publish_release \
  --repo yui-stingray/agent-safety-toolkit-example \
  --ownership-class internal

expect_decision 3 deny push.force hard_guardrail \
  "$PYTHON_BIN" scripts/policy_admit.py \
  --action force_push \
  --repo yui-stingray/agent-safety-toolkit-example \
  --ownership-class internal

expect_decision 2 require_approval write hard_guardrail \
  "$PYTHON_BIN" scripts/policy_admit.py \
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
  > "$SURFACE_INVENTORY_TMP"
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
  --agent-policy-audit-event "$AUDIT_EVENT_PATH" \
  --format json \
  --output "$REPORT_PATH"
"$PYTHON_BIN" -m agent_guard.cli conformance check \
  --root . \
  --evidence "$REPORT_PATH" \
  --profile recommended \
  --json
"$PYTHON_BIN" -m agent_guard.cli evidence-pack manifest \
  --root . \
  --report "$REPORT_PATH" \
  --artifact "$REPORT_PATH" \
  --agent-policy-audit-event "$AUDIT_EVENT_PATH" \
  --json \
  > "$EVIDENCE_PACK_STAGE"
mv -- "$EVIDENCE_PACK_STAGE" "$EVIDENCE_PACK_PATH"
"$PYTHON_BIN" examples/evidence_consumer.py "$REPORT_PATH"
"$PYTHON_BIN" -m agent_guard.consumer --evidence-dir "$EVIDENCE_DIR" "$REPORT_PATH"

PUBLISH_COMPLETE=1
