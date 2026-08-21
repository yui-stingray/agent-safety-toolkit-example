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
- `scripts/evidence_publication.py`
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
python scripts/evidence_publication.py consume --repo . --consumer example
python scripts/evidence_publication.py consume --repo . --consumer packaged
```

If dependency hashes do not match on the target platform, regenerate the lock
file for that platform instead of removing hash checking.
The checked-in lock targets CPython 3.12 on GitHub-hosted Ubuntu Linux x86_64,
and `run_demo.sh` rejects a different interpreter. Set `PYTHON` explicitly when
needed. Generate a separate hash lock and CI job before claiming another
platform. The demo also requires GNU `timeout`. `agent-guard` 0.3.5
independently bounds context scans, including custom context-policy regular
expressions. The demo retains a 12-second external supervisor around context
check, context inventory, surface inventory, context lock, and report as
defense in depth; review context-policy changes before execution.

The runner generates and validates a complete candidate in sibling staging,
then publishes under an advisory writer lock with a durable rollback journal.
The next runner or snapshot consumer automatically rolls back a transaction
interrupted before the journal commit point. Use the two
`evidence_publication.py consume` commands above so readers copy report,
manifest, and event into one locked snapshot before validation.

The three fixed files are still not one portable atomic filesystem object.
Direct readers that bypass the helper can observe a transient mixed set and
must not treat raw reads as completed publication. Crash-consistency is tested
only for the documented Ubuntu Linux local-filesystem target and relies on its
`flock`, `fsync`, and atomic rename semantics; no equivalent durability is
claimed for NFS, Windows, macOS, container volumes, or storage that does not
honor those semantics.
The staging helper supports ordinary repositories and linked Git worktrees. It
rejects Git submodules; adapt and test the snapshot protocol before adopting it
in a repository that uses submodules.
Its advisory lock coordinates cooperating helper processes, not a hostile
same-user process that ignores the lock or directly modifies repository files.

## Bound Audit Events

`agent-guard` 0.3.5 emits report and evidence-pack manifest v2 artifacts when
the report and manifest producer receive the same repository-relative audit
event path and the recognized
`agent-guard.public_agent_policy_audit_event.v1` profile. The v2 entry binds
canonical JSON content with sanitized digest metadata; it does not embed the
raw event body.

Pass that same path and profile to both consumers. They fail closed on event
substitution, wrong profile or path, report/manifest mismatch, and missing,
extra, or count-mismatched evidence. The generic
`agent-policy.audit_event.v1.1` schema is not the profile recognized by
`agent-guard` 0.3.5; retain this demo's stricter public-artifact event contract.

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
  audit-event content binding;
- the recommended-profile conformance result;
- digest drift for pinned safety-critical files;
- workflow drift for required guard commands;
- whether the evidence omits raw prompts, snippets, hash values, secrets, and
  local paths.

This recipe is deliberately narrow. It does not add an LLM reviewer, issue
triage bot, model router, broad secret scanner, agent execution UI, MCP runtime
security layer, live OAuth validator, MCP tool-poisoning detector, or governance
framework.
