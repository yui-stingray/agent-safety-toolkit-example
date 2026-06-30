# Agent Safety Evidence Demo

This repository is a public-safe demo for one narrow handoff: static
repository evidence from [`agent-guard`](https://github.com/yui-stingray/agent-guard)
plus a deterministic admission artifact from
[`agent-policy`](https://github.com/yui-stingray/agent-policy).

It is not a comprehensive agent safety toolkit. It shows a publishable evidence
shape that maintainers can inspect, copy, and adapt.
For copying the pattern into another repository, use
[`docs/adoption-recipe.md`](docs/adoption-recipe.md).

## What It Demonstrates

`agent-policy` handles runtime admission:

- normalize a requested agent action into a small capability name
- evaluate the capability against a repo policy matrix
- return one of `auto_allow`, `require_approval`, or `deny`
- map that decision to a process exit code that callers can enforce

`agent-guard` handles static repository gates:

- reject unsafe agent context file instructions
- emit redacted agent context inventory metadata for review evidence
- emit agent surface inventory v2 metadata for documented guard commands and evidence artifacts
- verify that discovered agent context files are pinned by digest policy
- reject private artifact paths before publication
- reject unsafe public-demo content patterns
- reject forbidden API endpoint references
- pin safety-critical file digests so drift is visible in CI
- emit a sanitized JSON evidence report for reviewers and automation

Together they cover different layers. `agent-policy` answers "may this agent action continue now?" while `agent-guard` answers "does this repository still look safe to publish and operate?"
The demo pairs one runtime admission audit event with one static guard evidence
report so maintainers can review both sides without storing raw prompts,
repository contents, hashes, tokens, or local paths.

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
python3 scripts/policy_admit.py --action read_docs --repo yui-stingray/agent-safety-toolkit-example
```

Emit the deterministic audit event shape used by wrappers and CI:

```bash
python3 scripts/policy_admit.py --action read_docs --repo yui-stingray/agent-safety-toolkit-example --audit-event --command read_docs --path README.md
```

## Local Verification

This demo pins dependencies with hashes for Python 3.12 on Ubuntu Linux, which is also the CI target.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --require-hashes -r requirements/agent-safety-tools.txt
python3 -m pytest -q
bash scripts/run_demo.sh
```

The end-to-end script runs:

- expected pass and fail runtime admission checks
- path guard
- context guard
- redacted context inventory
- context lock coverage against the committed digest policy
- content guard
- API guard
- MCP config guard
- digest guard
- workflow drift guard
- policy/spec drift guard
- recommended-profile conformance check
- sanitized JSON evidence report and evidence-pack manifest
- downstream evidence consumer validation

The static guard portion is intentionally deterministic and can be inspected as
these core commands:

```bash
agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json
agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2 --json
agent-guard mcp check --root . --json
agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json
agent-guard drift check --root . --profile recommended --schema-version v2 --json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --api-policy .agent-guard/api-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --agent-policy-audit-event .agent-guard/evidence/policy-admission-event.json --format json --output .agent-guard/evidence/agent-guard-report.json
```

Treat the individual per-scanner `--json` outputs above as local inspection or
CI-internal diagnostics. The public handoff is the sanitized report and
evidence-pack output under `.agent-guard/evidence/`; do not upload raw scanner
JSON from a private repository unless a maintainer has reviewed that exact
output. The MCP config guard reads committed configuration metadata only. It
does not execute MCP servers, validate live OAuth flows, inspect MCP tool
results, or detect MCP tool-poisoning behavior.

It writes generated evidence files under `.agent-guard/evidence/`:

- `policy-admission-event.json`: deterministic `agent-policy` runtime
  admission evidence for one normalized action.
- `agent-surface-inventory.json`: sanitized `agent-guard` surface inventory v2
  metadata for context files, policy files, workflows, documented guard
  commands, and evidence artifacts.
- `agent-guard-report.json`: sanitized `agent-guard` static repository
  evidence, including context lock coverage, workflow drift, profile
  conformance, and an embedded evidence-pack manifest with a sanitized
  `agent-policy` audit-event artifact reference.
- `evidence-pack-manifest.json`: compact artifact index for reviewer handoff,
  including the report and `agent-policy` audit-event artifact references.

## Updating Digests

The digest policy pins files that define the public demo contract:

- `AGENTS.md`
- `README.md`
- `scripts/policy_admit.py`
- `.agent-policy/policy.toml`

After an intentional change to one of those files:

```bash
python3 scripts/update_digests.py
agent-guard digest check --root . --policy .agent-guard/context-digest-policy.yaml
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml --json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --api-policy .agent-guard/api-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --agent-policy-audit-event .agent-guard/evidence/policy-admission-event.json --format json --output .agent-guard/evidence/agent-guard-report.json
```

## Public Safety Scope

The repository intentionally avoids private corpora, local automation state, credentials, and private repository examples. Negative guard fixtures are generated inside tests at runtime rather than stored as committed payload files.

The policy choices here are examples, not a universal safety model. Real maintainers should adapt capability names, review thresholds, and static guard patterns to their own repositories.
