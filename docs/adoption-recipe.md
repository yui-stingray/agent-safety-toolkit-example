# Adoption Recipe

This demo is meant to be copied into a public repository and then adapted. Do
not copy local machine paths, generated private evidence, personal hook config,
or private repository examples.

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
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml --json
```

## First Verification Pass

Run the same checks locally before enabling the workflow:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --require-hashes -r requirements/agent-safety-tools.txt
python3 -m pytest -q
bash scripts/run_demo.sh
python3 scripts/validate_policy_event.py .agent-guard/evidence/policy-admission-event.json
python3 examples/evidence_consumer.py .agent-guard/evidence/agent-guard-report.json
```

If dependency hashes do not match on the target platform, regenerate the lock
file for that platform instead of removing hash checking.

## Do Not Copy

Do not copy or publish:

- `.venv`, `.pytest_cache`, `__pycache__`, local logs, or local databases;
- `.env*` files, private keys, tokens, or credentials;
- private corpora, bypass corpora, red-team transcripts, or personal notes;
- generated evidence from a private repository unless it has been reviewed and
  is known to be sanitized;
- `agent-policy` audit events created without a public-safe `--repo-alias`
  when the raw repository identifier is private;
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
- the `agent-guard` surface inventory v2 and evidence-pack manifest, including
  a sanitized `agent-policy` audit-event artifact reference;
- whether `agent-surface-inventory.json` is listed as a generic `report`
  artifact by the pinned `agent-guard` release, and whether the path plus
  embedded `surface_inventory` section are sufficient for the handoff;
- the recommended-profile conformance result;
- digest drift for pinned safety-critical files;
- workflow drift for required guard commands;
- whether the evidence omits raw prompts, snippets, hash values, secrets, and
  local paths.

This recipe is deliberately narrow. It does not add an LLM reviewer, issue
triage bot, model router, broad secret scanner, agent execution UI, MCP runtime
security layer, live OAuth validator, MCP tool-poisoning detector, or governance
framework.
