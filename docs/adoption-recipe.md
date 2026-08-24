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

## Toolkit Policy Integration Boundary

`yui-agent-policy` 0.1.15 extends the bounded example-hook contract by failing
closed on callback-bearing and state-mutating builtins, xtrace/`PS4` execution,
shell and environment assignments, command-bearing Git environment variables
and program options, and path-qualified or unlisted command heads. It retains
the earlier hardening for dynamic Git argv and aliases, active glob/brace
expansion, `xargs`/`find -exec` argv generation, active arithmetic,
startup-sensitive shell state, and unmodeled shell-wrapper input. These
unresolved forms map to `unknown` and fail closed. The 0.1.12 generic overlap,
context, and brace-validation fixes remain available. This demo's wrapper
retains a
fixed-vocabulary preflight before `evaluate()` as an
integration boundary: it permits the intentional current policy names and every
`ACTION_CAPABILITIES` value, rejects unknown keys such as `wirte`, and rejects
differing modes where the same repo, capability, and overlapping ownership
scopes would be order dependent. It preserves identical duplicates and disjoint
`internal` and `external` rules. Do not require each allowed capability to be
declared; omission can intentionally use `default_mode`. Adapt this fixed
vocabulary with `scripts/policy_admit.py` and the policy/action contract, but do
not treat it as a generic library replacement.

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
platform. The demo also requires GNU `timeout`. `agent-guard` 0.3.7 retains v2
audit-event path binding and independently bounds context scans, including
custom context-policy regular expressions. Its PyPI long-description self-pin
hardening is package/release hygiene, not a new runtime scanner. The demo
retains a 12-second external supervisor around context check, context inventory,
surface inventory, context lock, and report as defense in depth; review
context-policy changes before execution.

`bash scripts/run_demo.sh` is the documented end-to-end publisher. It invokes
`scripts/evidence_publication.py run --repo .`, the internal publishing path
that also mutates the three fixed evidence paths. The internal publisher
generates and validates a complete candidate in sibling staging, then publishes
under an advisory writer lock with a durable rollback journal. The commit
decision is linearized while SIGINT and SIGTERM are blocked immediately before
journal removal and directory sync. A request observed before that decision
rolls back; one delivered after it may return an interrupted status with the
new complete bundle committed. The next runner or snapshot consumer
automatically rolls back an earlier interrupted transaction.

Use the two `evidence_publication.py consume` commands above in a writable
cooperating checkout. `consume` takes a nonblocking publication lock and fails
fast while a writer or another snapshot consumer owns it, so callers retry
after the lock owner exits. After acquiring the lock, it recovers any pending
transaction and copies report, manifest, and event into one private snapshot
before validation.

For an immutable or read-only bundle, direct validation is appropriate only
when no publisher can mutate the bundle concurrently. Validate it with both
consumers using the report positional argument and the existing
`--evidence-dir`, `--agent-policy-audit-event`, and
`--agent-policy-audit-event-profile` arguments:

```bash
python examples/evidence_consumer.py \
  --repo-root . \
  --evidence-dir .agent-guard/evidence \
  --agent-policy-audit-event .agent-policy/evidence/policy-admission-event.json \
  --agent-policy-audit-event-profile agent-guard.public_agent_policy_audit_event.v1 \
  .agent-guard/evidence/agent-guard-report.json
python -m agent_guard.consumer \
  --repo-root . \
  --evidence-dir .agent-guard/evidence \
  --agent-policy-audit-event .agent-policy/evidence/policy-admission-event.json \
  --agent-policy-audit-event-profile agent-guard.public_agent_policy_audit_event.v1 \
  .agent-guard/evidence/agent-guard-report.json
```

The three fixed files are still not one portable atomic filesystem object.
Direct readers that bypass the helper can observe a transient mixed set and
must not treat raw reads as completed publication. Crash-consistency is tested
only for the documented Ubuntu Linux local-filesystem target and relies on its
`flock`, `fsync`, and atomic rename semantics. Safe staged-process cleanup also
requires Linux `/proc` and the `pidfd_open` and `pidfd_send_signal` system
calls. No equivalent durability or process-cleanup guarantee is claimed for
NFS, Windows, macOS, container volumes, older kernels without pidfds, or
storage that does not honor those filesystem semantics.
Stale-stage recovery signals a recorded child session only when it can pin the
matching leader identity. If the leader has disappeared while executable
members remain, the helper preserves the stage and fails closed instead of
trusting a reusable numeric session ID; retry after those processes exit or
inspect the local state before removing it.
The staging helper supports ordinary repositories and linked Git worktrees. It
rejects Git submodules; adapt and test the snapshot protocol before adopting it
in a repository that uses submodules.
Its advisory lock coordinates cooperating helper processes, not a hostile
same-user process that ignores the lock or directly modifies repository files.

## Bound Audit Events

`agent-guard` 0.3.7 continues to emit report and evidence-pack manifest v2
artifacts, retaining v2 audit-event path binding when the report and manifest
producer receive the same repository-relative audit event path and the recognized
`agent-guard.public_agent_policy_audit_event.v1` profile. The v2 entry binds
canonical JSON content with sanitized digest metadata; it does not embed the
raw event body.

Pass that same path and profile to both consumers with `--repo-root .`. At
0.3.7, v2 consumers verify supplied event content and profile; when given
`--repo-root`, they also verify the canonical repository-relative event
location. Consumers fail closed on content substitution, wrong profiles, wrong
event locations when
given `--repo-root`, report/manifest mismatch, and missing, extra, or
count-mismatched evidence. Do not duplicate guard validation in this recipe.
The generic
`agent-policy.audit_event.v1.1` schema is not the profile recognized by
`agent-guard` 0.3.7; retain this demo's stricter public-artifact event contract.
Neither event profile records the installed `yui-agent-policy` package version. The
hash-locked environment plus CI regeneration establish process-level version
provenance; consumers must not infer a producer version from the standalone
event or evidence-pack binding.

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
