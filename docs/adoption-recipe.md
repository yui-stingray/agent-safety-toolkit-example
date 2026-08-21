# Adoption Recipe

This demo is meant to be copied into a public repository and then adapted. Do
not copy local machine paths, generated private evidence, personal hook config,
or private repository examples.

## Preview the agent-guard starter plan

Before copying this full combined demo, evaluators can inspect
[agent-guard's preview-only starter plan](https://github.com/yui-stingray/agent-guard#start-with-a-reviewed-bootstrap).
The preview does not write files in the selected repository, though it may
populate external caches. It covers only agent-guard static starter files: it
does not install or configure agent-policy, and it does not reproduce this
combined demo. Continue with this recipe only after deciding to adopt both
layers.

## Copy These Files

Start with these files:

- `.agent-policy/policy.toml`
- `.agent-guard/api-policy.yaml`
- `.agent-guard/content-policy.yaml`
- `.agent-guard/context-policy.yaml`
- `.agent-guard/context-digest-policy.yaml`
- `.agent-guard/mcp-policy.yaml`
- `.agent-guard/path-policy.yaml`
- `.agent-guard/workflow-policy.yaml`
- `examples/evidence_consumer.py`
- `scripts/policy_event_contract.py`
- `scripts/policy_admit.py`
- `scripts/run_agent_guard_bounded.sh`
- `scripts/validate_policy_event.py`
- `scripts/run_demo.sh`
- `scripts/update_digests.py`
- `requirements/agent-safety-tools.txt`

Copy the GitHub Actions job from `.github/workflows/ci.yml` if the target repo
uses GitHub Actions. Keep repository permissions read-only unless the workflow
has a specific reason to write.

## Adapt Before Publishing

Replace the demo-specific values before linking the repository publicly:

- repository identifiers such as `yui-stingray/agent-safety-toolkit-example`;
- public audit-event aliases passed as `--repo-alias` when raw repository names
  should not appear in evidence;
- the shared action-to-capability contract in
  `scripts/policy_event_contract.py`;
- wrapper argument handling and public-safe field normalization in
  `scripts/policy_admit.py`;
- the capability matrix in `.agent-policy/policy.toml`;
- content scan targets in `.agent-guard/content-policy.yaml`;
- static MCP config risk labels in `.agent-guard/mcp-policy.yaml`;
- API allow/deny rules in `.agent-guard/api-policy.yaml`;
- path rules for local artifacts, generated outputs, and private fixtures;
- branch names and workflow names in `.github/workflows/ci.yml`;
- digest pins in `.agent-guard/context-digest-policy.yaml`.

Regenerate digest pins after every intentional change to pinned files:

```bash
python3 scripts/update_digests.py
agent-guard digest check --root . --policy .agent-guard/context-digest-policy.yaml
bash scripts/run_agent_guard_bounded.sh python -m agent_guard.cli context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml --json
```

## First Verification Pass

Run the same checks locally before enabling the workflow:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements/agent-safety-tools.txt
# Run this after adding or adapting the target repository's tests.
python -m pytest -q
bash scripts/run_demo.sh
python scripts/validate_policy_event.py .agent-policy/evidence/policy-admission-event.json
python examples/evidence_consumer.py .agent-guard/evidence/agent-guard-report.json
python -m agent_guard.consumer --evidence-dir .agent-guard/evidence .agent-guard/evidence/agent-guard-report.json
```

If dependency hashes do not match on the target platform, regenerate the lock
file for that platform instead of removing hash checking.
The checked-in lock targets CPython 3.12 on GitHub-hosted Ubuntu Linux x86_64,
and `run_demo.sh` rejects a different interpreter. Set `PYTHON` explicitly when
needed. Generate a separate hash lock and CI job before claiming another
platform. The demo also requires GNU `timeout` and supervises the published
`agent-guard` 0.3.4 context check, context inventory, surface inventory, context
lock, and report for 12 seconds.
This mitigates the published version's unbounded custom context-regex execution;
it is not a fixed `agent-guard` release, so review context-policy changes before
execution.

The runner restores its snapshot after ordinary catchable failures, but
publication across `.agent-guard` and `.agent-policy` is not an atomic
transaction. `SIGKILL`, host power loss, and concurrent readers are outside the
guarantee. Run it in an isolated checkout with one writer and consume or publish
the evidence set only after a successful exit.

## Audit-event Reference Limitation and Migration

In the current `agent-guard` 0.3.4 v1 report and manifest, the audit-event
artifact reference records only the sanitized path and role. It does not bind or
verify event content identity, schema/profile semantics, or substitution. The
demo's own event schema validation is separate and is not a cryptographic or
content binding.

This v2 migration is dependency-gated. Only after a formally published
compatible `agent-guard` release should maintainers update the exact hash pin,
pass the identical event path and a recognized profile to the report/manifest
producer and packaged consumer, regenerate v2 evidence, and test substitution
rejection. Until then, retain the current 0.3.4 pin and v1 evidence.

## Do Not Copy

Do not copy or publish:

- `.venv`, `.pytest_cache`, `__pycache__`, local logs, or local databases;
- `.env*` files, private keys, tokens, or credentials;
- private corpora, bypass corpora, red-team transcripts, or personal notes;
- generated evidence from a private repository unless it has been reviewed and
  is known to be sanitized;
- `agent-policy` audit events created without the required public-safe
  `--repo-alias`;
- raw per-scanner JSON from a private repository unless a maintainer has
  reviewed that exact output;
- hook config with personal absolute paths.

The committed demo evidence is generated for this public-safe repository. Treat
it as a shape example, not proof that another repository is safe.

## What Maintainers Should Review

For each pull request that changes agent instructions, policy files, wrapper
logic, or CI guard commands, review:

- the `agent-policy` runtime admission decision or audit event;
- the public audit-event schema validation result;
- the `agent-guard` context inventory and context lock coverage;
- the `agent-guard` surface inventory v2 embedded in the report and the
  matching evidence-pack manifest, including a sanitized `agent-policy`
  audit-event artifact reference;
- the recommended-profile conformance result;
- digest drift for pinned safety-critical files;
- workflow drift for required guard commands;
- whether the evidence omits raw prompts, snippets, hash values, secrets, and
  local paths.

This recipe is deliberately narrow. It does not add an LLM reviewer, issue
triage bot, model router, broad secret scanner, agent execution UI, MCP runtime
security layer, live OAuth validator, MCP tool-poisoning detector, or governance
framework.
