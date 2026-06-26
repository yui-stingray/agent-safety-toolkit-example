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

If you intentionally change `README.md`, `scripts/policy_admit.py`, or `.agent-policy/policy.toml`, refresh the digest policy:

```bash
python scripts/update_digests.py
agent-guard digest check --root . --policy .agent-guard/digest-policy.yaml
```

## Review Expectations

- Keep runtime admission behavior covered by tests.
- Keep static guard policies simple and readable.
- Keep CI read-only and free of publication steps.
- Keep examples symbolic rather than using real credentials or private data.
