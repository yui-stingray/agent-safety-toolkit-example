# Agent Safety Toolkit Example

This repository is a public-safe demo of using [`agent-policy`](https://github.com/yui-stingray/agent-policy) and [`agent-guard`](https://github.com/yui-stingray/agent-guard) together as an agent safety toolkit.

It shows how the two projects can be dogfooded in a repository that is safe to publish.

## What It Demonstrates

`agent-policy` handles runtime admission:

- normalize a requested agent action into a small capability name
- evaluate the capability against a repo policy matrix
- return one of `auto_allow`, `require_approval`, or `deny`
- map that decision to a process exit code that callers can enforce

`agent-guard` handles static repository gates:

- reject private artifact paths before publication
- reject unsafe public-demo content patterns
- reject forbidden API endpoint references
- pin safety-critical file digests so drift is visible in CI

Together they cover different layers. `agent-policy` answers "may this agent action continue now?" while `agent-guard` answers "does this repository still look safe to publish and operate?"

## Runtime Admission Demo

The wrapper in `scripts/policy_admit.py` deliberately keeps action parsing small and explicit:

| Demo action | Capability | Expected mode | Exit |
| --- | --- | --- | --- |
| `read_docs` | `read` | `auto_allow` | `0` |
| `edit_docs` | `write` | `require_approval` | `2` |
| `publish_release` | `artifact.publish` | `require_approval` | `2` |
| `force_push` | `push.force` | `deny` | `3` |

Run a single admission check:

```bash
python scripts/policy_admit.py --action read_docs --repo yui-stingray/agent-safety-toolkit-example
```

## Local Verification

This demo pins dependencies with hashes for Python 3.12 on Ubuntu Linux, which is also the CI target.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements/agent-safety-tools.txt
python -m pytest -q
bash scripts/run_demo.sh
```

The end-to-end script runs:

- expected pass and fail runtime admission checks
- path guard
- content guard
- API guard
- digest guard

## Updating Digests

The digest policy pins files that define the public demo contract:

- `README.md`
- `scripts/policy_admit.py`
- `.agent-policy/policy.toml`

After an intentional change to one of those files:

```bash
python scripts/update_digests.py
agent-guard digest check --root . --policy .agent-guard/digest-policy.yaml
```

## Public Safety Scope

The repository intentionally avoids private corpora, local automation state, credentials, and private repository examples. Negative guard fixtures are generated inside tests at runtime rather than stored as committed payload files.

The policy choices here are examples, not a universal safety model. Real maintainers should adapt capability names, review thresholds, and static guard patterns to their own repositories.
