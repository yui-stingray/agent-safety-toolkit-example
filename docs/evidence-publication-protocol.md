# Evidence Publication Protocol

This document is the normative contract for the three-file evidence publisher
implemented by `scripts/evidence_publication.py`. `MUST`, `MUST NOT`, `SHOULD`,
and `MAY` are normative. Explanatory text is informative.

## Scope and Platform

The fixed publication set, in replacement order, is:

1. `.agent-guard/evidence/agent-guard-report.json` (`report`)
2. `.agent-guard/evidence/agent-guard-evidence-pack.json` (`manifest`)
3. `.agent-policy/evidence/policy-admission-event.json` (`event`)

The protocol targets CPython 3.12 on GitHub-hosted Ubuntu Linux x86_64 and a
local filesystem that honors `flock`, regular-file and directory `fsync`, and
same-filesystem atomic rename. Staged-process cleanup also requires Linux
`/proc`, `pidfd_open`, and `pidfd_send_signal`. It makes no equivalent guarantee
for NFS, Windows, macOS, container volumes, older kernels without pidfds, or a
same-user process that ignores the lock.

Three paths cannot be replaced by one portable filesystem operation. A reader
MUST therefore use the cooperating snapshot consumer while publication can be
concurrent. An immutable bundle MAY be validated directly only when no writer
can mutate it.

## Durable Objects

The state directory is a sibling of the repository. It and all publication
state MUST be private to the current user, non-symlink, and structurally
validated before use. The publisher and snapshot consumer MUST hold an
exclusive advisory `publication.lock`; lock contention fails closed.

### Stage marker

The stage marker has exactly these fields:

| Field | Contract |
| --- | --- |
| `schema_version` | `agent-safety-toolkit.evidence-stage.v1` |
| `parent_pid`, `child_pid` | positive process IDs, except `child_pid` is zero before launch |
| `parent_start`, `child_start` | Linux process-start identities or `null` before child launch |
| `nonce` | 32 lowercase hexadecimal characters |
| `worktree_device`, `worktree_inode` | staged worktree identity or `null` before creation |

The parent MUST publish the marker durably before releasing the staged child.
Recovery MUST signal a recorded child session only after pinning the matching
process/start/session identity. If safe cleanup cannot be proven, recovery MUST
preserve state and fail closed.

### Transaction marker and journal

The transaction marker is exactly:

```json
{"schema_version":"agent-safety-toolkit.evidence-transaction.v1"}
```

The journal has exactly `schema_version`, `root_device`, `root_inode`, and
`artifacts`. Its schema is `agent-safety-toolkit.evidence-publication.v1`.
`artifacts` MUST contain exactly the three fixed roles in the order above.
Each entry has exactly:

| Field | Contract |
| --- | --- |
| `role` | fixed role |
| `path` | fixed canonical repository-relative path |
| `old_present` | whether the complete old set existed |
| `old_digest`, `old_mode` | old private-copy identity and mode, or both `null` |
| `new_digest` | new private-copy identity |
| `rollback_temp` | fixed repository-relative rollback temporary path |

Digests use lowercase unpadded base32 SHA-256 with a leading `b`. The journal is
local recovery state, not public evidence. It MUST NOT contain artifact bodies,
raw tokens, endpoint URLs, credentials, or personal paths. Unknown fields,
roles, paths, ordering, file types, modes, repository identity, or digest shapes
MUST fail closed.

## State Machine

| State | Durable evidence | Permitted next action or recovery |
| --- | --- | --- |
| `IDLE` | no active transaction | clean validated stale preparation/stage state, then stage |
| `STAGED` | stage marker and complete candidate | validate both consumers; live set remains unchanged on crash |
| `PREPARING` | private `transaction-preparing-*` tree | finish preparation or remove the validated private tree; live set remains unchanged |
| `ROLLBACK_CAPABLE` | durable `transaction/` marker, `old/`, `new/`, and journal | publish in fixed order; any crash with journal present restores the complete old set |
| `PUBLISHED_UNCOMMITTED` | live set matches all new digests and journal remains | validate a private snapshot, then commit; recovery still restores the old set |
| `COMMITTED` | journal unlink and transaction-directory `fsync` are durable | new set is authoritative; remaining marker/private copies are cleanup-only |
| `INVALID` | schema, binding, type, identity, or digest contradiction | fail closed; do not infer whether old or new was intended |

The existence of the journal is the rollback decision. A valid transaction with
a journal MUST roll back in reverse artifact order. A valid transaction without
a journal MUST be treated as committed cleanup state. A journal without its
transaction marker is invalid.

## Write and Sync Order

The publisher MUST perform these steps in order:

1. Generate the complete candidate in sibling staging and validate both the
   example and packaged consumers before changing live paths.
2. Create the private preparation directory, transaction marker, `old/`, and
   `new/`. Write private copies using exclusive no-follow regular files; sync
   each file and its parent directory.
3. Write and sync the journal, sync the preparation directory, atomically rename
   preparation to the fixed transaction directory, then sync the state
   directory. This establishes `ROLLBACK_CAPABLE`.
4. Rename the new `report`, `manifest`, and `event` into their bound live
   directories in that order. After each rename, sync the destination regular
   file, private `new/` directory, and destination directory.
5. Verify all live new digests and validate both consumers against a private
   snapshot while the lock is held.
6. Block SIGINT and SIGTERM, reject any already-pending termination, unlink the
   journal, and sync the transaction directory. Completion of that directory
   sync is the commit linearization point.
7. Remove private copies and the transaction marker, sync the transaction
   directory, remove it, and sync the state directory.

SIGINT or SIGTERM observed before the commit decision MUST roll back. A signal
delivered after commit MAY produce an interrupted process status while the new
bundle remains authoritative. SIGKILL and power loss are handled only by the
next cooperating writer or snapshot consumer through durable-state recovery.

## Required Fault Tests

The implementation MUST keep regressions for:

- SIGTERM before publication and after the first live replacement;
- SIGKILL-equivalent crash before journal exposure and after the first live
  replacement;
- crash while rollback is copying an old artifact;
- crash after journal removal and during committed-state cleanup;
- stale stage, stale preparation, and stale transaction recovery;
- concurrent writer/writer and writer/snapshot-reader rejection;
- both consumers on the recovered snapshot;
- second-run byte stability and committed-evidence freshness.

These tests prove crash consistency only within the platform boundary above.
They do not prove durability against hostile storage, an uncooperative same-user
process, or physical media failure that violates acknowledged `fsync` semantics.

