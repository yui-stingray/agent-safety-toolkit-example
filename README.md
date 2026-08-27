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

Together they cover different layers. `agent-policy` answers "may this agent action continue now?" while `agent-guard` answers "does this repository satisfy the selected deterministic static evidence profile?"
The demo pairs one runtime admission audit event with one static guard evidence
report so maintainers can review both sides without storing raw prompts,
repository contents, hashes, tokens, or local paths.

## Runtime Admission Demo

The shared contract in `scripts/policy_event_contract.py` keeps the demo
action-to-capability vocabulary small and explicit, and gives the producer and
validator one public-safe field grammar. The wrapper in
`scripts/policy_admit.py` uses that contract for runtime decisions, and
`scripts/validate_policy_event.py` uses it to validate public audit events:

| Demo action | Capability | Expected mode | Exit |
| --- | --- | --- | --- |
| `read_docs` | `read` | `auto_allow` | `0` |
| `edit_docs` | `write` | `require_approval` | `2` |
| `publish_release` | `artifact.publish` | `require_approval` | `2` |
| `force_push` | `push.force` | `deny` | `3` |

Invalid invocations and program errors exit `1`; exit `2` is reserved for a
validated `require_approval` decision.

Run a single admission check:

```bash
python3 scripts/policy_admit.py --action read_docs --repo yui-stingray/agent-safety-toolkit-example
```

Emit the deterministic audit event shape used by wrappers and CI:

```bash
python3 scripts/policy_admit.py --action read_docs --repo yui-stingray/agent-safety-toolkit-example --repo-alias agent-safety-toolkit-example-public --audit-event --command read_docs --path README.md
```

`--repo` is the identifier evaluated against `.agent-policy/policy.toml`.
Audit events are public evidence, so `--repo-alias` is required with
`--audit-event`; the raw repository identifier is never used as an audit-event
fallback.
`scripts/validate_policy_event.py` validates the committed public audit-event
artifact and rejects raw repository identifiers, local paths, unsupported
fields, and secret-shaped values before `agent-guard` references it.
The earlier `yui-agent-policy` 0.1.12 release introduced an opt-in
generic `agent-policy.audit_event.v1.1` JSON schema, but this demo intentionally
keeps its stricter public-artifact profile. The generic schema does not replace
the demo's raw repo identifier, local path, or secret-shaped value checks.

### Toolkit Policy Preflight

`yui-agent-policy` 0.1.17 extends the bounded example-hook contract by failing
closed when unresolved parameter expansion can become a `wait` option or any
argument of a recognized Git command, including global options before its
subcommand. It retains the 0.1.16 hardening for active output redirection,
ANSI-C quoted words, file-writing command heads such as `tee`, and every Git
push or send-pack form without an explicit visible force option. Explicit
visible force forms remain `push.force`; the other modeled push and send-pack
forms map to `unknown`. It also retains the 0.1.15
hardening for callback-bearing and state-mutating builtins, xtrace/`PS4`
execution, shell and environment assignments, command-bearing Git environment
variables and program options, and path-qualified or unlisted command heads,
and the earlier hardening for dynamic Git argv and aliases, active glob/brace
expansion, `xargs`/`find -exec` argv generation, active arithmetic,
startup-sensitive shell state, and unmodeled shell-wrapper input. These
unresolved forms map to `unknown` and fail closed. The 0.1.12 generic overlap,
context, and brace-validation fixes remain available. Before calling
`evaluate()`, this toolkit retains a
fixed-vocabulary preflight as an integration boundary. It accepts the
intentional names in the current policy matrix plus every `ACTION_CAPABILITIES`
value, rejects unknown keys such as `wirte`, and rejects differing modes for
the same repo and capability when ownership scopes overlap. Identical duplicates
and disjoint `internal`/`external` rules remain valid. An allowed capability may
be omitted so `default_mode` can apply. This preflight is not a generic
replacement for `yui-agent-policy` validation.

## Local Verification

This demo's checked-in lock targets CPython 3.12 on GitHub-hosted Ubuntu Linux
x86_64, which is also the CI target. Generate a separate hash lock and CI job
before claiming support for another platform.

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements/agent-safety-tools.txt
python -m pytest -q
bash scripts/run_demo.sh
python scripts/evidence_publication.py consume --repo . --consumer example
python scripts/evidence_publication.py consume --repo . --consumer packaged
```

`scripts/run_demo.sh` rejects non-3.12 interpreters. Set `PYTHON` to an
explicit Python 3.12 executable when the activated environment is not first on
`PATH`. It also requires GNU `timeout`. `agent-guard` 0.3.8 retains v2
audit-event path binding and independently bounds context scans, including
custom context-policy regular expressions. It also fails closed on
meaning-changing workflow option overrides, hostile Git inspection state,
unbounded inventory or transform inputs, self-authorizing inline suppressions,
and inconsistent evidence component sections. As a
repository-local defense in depth, the script retains a 12-second external
supervisor around context check, context inventory, surface inventory, context
lock, drift check, report, and evidence-pack manifest: timeout output is
discarded and the demo fails closed. This does not claim a fix in the installed
package. Review repository policy changes before running the demo.

The end-to-end script runs:

- expected pass and fail runtime admission checks
- public-safe audit-event schema validation
- path guard
- context guard
- redacted context inventory
- context lock coverage against the committed digest policy
- content guard
- API guard
- MCP config guard with a reviewed repo policy
- digest guard
- workflow drift guard
- policy/spec drift guard
- recommended-profile conformance check
- sanitized JSON evidence report and evidence-pack manifest
- downstream evidence consumer validation

The static guard portion is intentionally deterministic and can be inspected as
these core commands:

```bash
agent-guard() {
  PYTHON="$(command -v python)" bash scripts/run_agent_guard_bounded.sh \
    python -m agent_guard.cli "$@"
}
agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json
agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2 --json
agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml --json
agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json
agent-guard drift check --root . --profile recommended --schema-version v2 --json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --api-policy .agent-guard/api-policy.yaml --mcp-policy .agent-guard/mcp-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --agent-policy-audit-event .agent-policy/evidence/policy-admission-event.json --agent-policy-audit-event-profile agent-guard.public_agent_policy_audit_event.v1 --format json
unset -f agent-guard
```

The temporary `agent-guard` shell function above routes every displayed command
through the bounded wrapper; it does not invoke the installed executable
directly. This standalone report command writes only to stdout for inspection.
`bash scripts/run_demo.sh` is the documented end-to-end publisher; it invokes
`scripts/evidence_publication.py run --repo .`, the internal publishing path
that also mutates the three fixed evidence paths.

Treat the individual per-scanner `--json` outputs above as local inspection or
CI-internal diagnostics. The public handoff is the sanitized report and
evidence-pack output under `.agent-guard/evidence/`; do not upload raw scanner
JSON from a private repository unless a maintainer has reviewed that exact
output. The MCP config guard reads committed configuration metadata only. It
does not execute MCP servers, validate live OAuth flows, inspect MCP tool
results, or detect MCP tool-poisoning behavior.

It writes the runtime admission artifact separately under
`.agent-policy/evidence/`:

- `policy-admission-event.json`: deterministic `agent-policy` runtime
  admission evidence for one normalized action.

The fixed public `agent-guard` bundle under `.agent-guard/evidence/` contains:

- `agent-guard-report.json`: sanitized `agent-guard` static repository
  evidence, including surface inventory v2, context lock coverage, workflow
  drift, profile conformance, and an embedded evidence-pack manifest with a
  bound `agent-policy` audit-event content digest.
- `agent-guard-evidence-pack.json`: compact artifact index for reviewer handoff,
  including the report and the matching `agent-policy` audit-event content
  binding.

The internal publisher takes an advisory writer lock, snapshots the non-ignored
working tree into sibling staging, and generates and validates the complete
replacement there before touching the fixed public paths. Publication uses a
durable rollback journal and same-filesystem atomic replacement for each file
in report, manifest, then event order. Removing and syncing the journal is the
commit operation. Its decision is linearized while SIGINT and SIGTERM are
blocked immediately before journal removal: a request observed before that
decision rolls back, while one delivered after it may return an interrupted
status with the new complete bundle committed. Before that decision, an
interrupted transaction is rolled back by the next runner or snapshot consumer
without consuming its backup.
It refuses to replace a bundle directory containing unexpected entries, so
unrelated local evidence is not deleted implicitly.
Use `scripts/evidence_publication.py consume` in a writable cooperating
checkout: it takes a nonblocking publication lock and fails fast while a writer
or another snapshot consumer owns it, so callers retry after the lock owner
exits. After acquiring the lock, it recovers any pending transaction and copies
all three files into one private snapshot before invoking the selected consumer.

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

The three fixed files still cannot be replaced in one portable filesystem
operation, so an uncoordinated process that reads the paths directly can
observe a transient mixed set; it must not treat raw reads as a completed
publication. The protocol is tested on the documented Ubuntu Linux
local-filesystem target. Publication durability relies on `flock`, `fsync`,
and atomic rename semantics; staged-process cleanup additionally requires
Linux `/proc` and the `pidfd_open` and `pidfd_send_signal` system calls. It
does not claim equivalent crash durability or process cleanup for NFS,
Windows, macOS, container volumes, older kernels without pidfds, or storage
that does not honor those filesystem semantics.
Stale-stage recovery signals a recorded child session only while it can pin
the matching leader identity. If that leader has disappeared while executable
session members remain, the helper preserves the stage and fails closed rather
than trusting a reusable numeric session ID; retry after those processes exit
or inspect that local state before removing it.
The staging snapshot supports ordinary repositories and linked Git worktrees,
but rejects Git submodules rather than silently producing a partial snapshot.
The advisory lock coordinates this helper's writers and readers; it is not an
authorization boundary against another same-user process that ignores the lock
or mutates repository filenames directly.
The standalone surface inventory command remains a local/CI check; this demo
uses the identical section embedded in the report as the public handoff.
The manifest binds the separately stored, sanitized runtime admission event so
reviewers can correlate the two evidence layers without co-locating the event
in the static bundle directory.

### Bound Audit Events

`agent-guard` 0.3.8 continues to emit `agent-guard.report_evidence.v2` and
`agent-guard.evidence_pack_manifest.v2`, retaining v2 audit-event path binding
when the producer receives the same repository-relative event path and the recognized
`agent-guard.public_agent_policy_audit_event.v1` profile. The manifest records
canonical JSON SHA-256 binding metadata, not the raw event body. Pass that path
and profile to both consumers with `--repo-root .`. At 0.3.8, v2 consumers
verify supplied event content and profile; when given `--repo-root`, they also
verify the canonical repository-relative event location. Both consumers reject
substitution, wrong profiles, wrong event locations when given `--repo-root`,
report/manifest mismatches, and missing, extra, or count-mismatched evidence.
This toolkit does not duplicate guard validation.

The `yui-agent-policy` generic `agent-policy.audit_event.v1.1` JSON schema is
separate from the profile accepted by `agent-guard` 0.3.8. This demo keeps its
stricter public-artifact event contract, including raw repository identifier,
local path, and secret-shaped value checks.

Neither event profile records the installed `yui-agent-policy` package
version. The hash-locked environment plus CI regeneration establish
process-level version provenance; consumers must not infer a producer version
from the standalone event or evidence-pack binding.

## Updating Digests

The digest policy pins files that define the public demo contract:

- `AGENTS.md`
- `README.md`
- `scripts/run_demo.sh`
- `scripts/evidence_publication.py`
- `scripts/run_agent_guard_bounded.sh`
- `scripts/policy_event_contract.py`
- `scripts/policy_admit.py`
- `scripts/validate_policy_event.py`
- `.agent-policy/policy.toml`
- `.agent-guard/mcp-policy.yaml`
- `.agent-guard/workflow-policy.yaml`

After an intentional change to one of those files:

```bash
python3 scripts/update_digests.py
agent-guard digest check --root . --policy .agent-guard/context-digest-policy.yaml
bash scripts/run_agent_guard_bounded.sh python -m agent_guard.cli context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml --json
bash scripts/run_demo.sh
```

## Public Safety Scope

The repository intentionally avoids private corpora, local automation state,
credentials, and private repository examples. Guard-regression payloads that
need executable checks are generated inside tests at runtime rather than stored
as committed payload files.
The small committed `fixtures/adversarial/` corpus is inert, dummy-valued, and
fenced for documentation and review only; production scripts and the demo runner
do not import or execute it.

The policy choices here are examples, not a universal safety model. Real maintainers should adapt capability names, review thresholds, and static guard patterns to their own repositories.
