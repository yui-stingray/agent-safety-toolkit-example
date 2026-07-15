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

If you intentionally change `AGENTS.md`, `README.md`,
`scripts/policy_event_contract.py`, `scripts/policy_admit.py`,
`scripts/validate_policy_event.py`, or `.agent-policy/policy.toml`, refresh the
digest policy and verify context lock coverage:

```bash
python scripts/update_digests.py
agent-guard digest check --root . --policy .agent-guard/context-digest-policy.yaml
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml --json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --format json
```

## Review Expectations

- Keep runtime admission behavior covered by tests.
- Keep static guard policies simple and readable.
- Keep CI read-only and free of publication steps.
- Keep examples symbolic rather than using real credentials or private data.
