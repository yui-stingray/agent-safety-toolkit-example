# Contributing

This repository is intentionally small. Changes should keep the demo easy to audit and safe to run in a public CI environment.

## Local Checks

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements/agent-safety-tools.txt
python -m pytest -q
bash scripts/run_demo.sh
```

If you intentionally change any path in the canonical `PINNED_FILES` list in
`scripts/update_digests.py`, refresh the digest policy and verify context lock
coverage. That list includes the runner and publisher, bounded guard wrapper,
policy event scripts, policy matrix, MCP policy, and workflow policy.

```bash
python scripts/update_digests.py
agent-guard digest check --root . --policy .agent-guard/context-digest-policy.yaml
bash scripts/run_agent_guard_bounded.sh python -m agent_guard.cli context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml --json
bash scripts/run_agent_guard_bounded.sh python -m agent_guard.cli report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --api-policy .agent-guard/api-policy.yaml --mcp-policy .agent-guard/mcp-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --agent-policy-audit-event .agent-policy/evidence/policy-admission-event.json --agent-policy-audit-event-profile agent-guard.public_agent_policy_audit_event.v1 --format json
```

## Review Expectations

- Keep runtime admission behavior covered by tests.
- Keep static guard policies simple and readable.
- Keep CI read-only and free of publication steps.
- Keep examples symbolic rather than using real credentials or private data.
