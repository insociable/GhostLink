# ADR-0009: Rollback-aware GhostNode SQLite state

- Status: Accepted for implementation
- Date: 2026-09-18
- Tracks: #86

## Context

GhostNode persists several security-relevant state machines in one SQLite database:

- protocol-v3 message envelopes and deletion/expiry state;
- active ratchet pre-key publications;
- remaining one-time pre-keys;
- requester allocation/idempotence records;
- pre-key fetch anti-drain history;
- authenticated relay-request replay identifiers.

Normal runtime rules reject many logical regressions. They do not prove freshness across a
restore. Replacing the current SQLite file with an older valid snapshot can restore
previously consumed pre-keys, older publication state, deleted messages, expired rate-limit
history, or request IDs that were already accepted.

Client-state ADR-0008 does not cover GhostNode. Relay state needs a separate identity,
coordination key, witness namespace, and operational recovery procedure.

A counter stored only inside the same SQLite database does not solve rollback. A VM or
filesystem snapshot can restore both data and counter.

## Decision

GhostNode persistent mode will use one shared rollback-state coordinator for the complete
security-relevant SQLite database.

The coordinator separates:

1. logical database coherence and rollback detection implemented by GhostLink; and
2. whole-snapshot freshness, which is only as strong as the witness backend.

GhostLink MUST NOT claim whole-host or whole-VM anti-rollback when the witness can be
restored together with the GhostNode database.

In-memory development mode remains outside this persistence mechanism.

## Relay-state identity

One persistent GhostNode state set has:

- a random 128-bit `relay_state_id`;
- an independently random 32-byte `relay_state_coordination_key`.

The key is independent of client keys, relay TLS keys, bearer tokens, and DeviceID signing
keys.

The relay-state key MUST be loaded from a secret source and MUST NOT be placed in argv,
logs, or a public configuration document.

## Protected logical state

Version 1 protects exactly these tables:

- `messages_v3`;
- `prekey_publications`;
- `prekey_one_time`;
- `prekey_allocations`;
- `prekey_fetch_events`;
- `relay_request_replay_v1`.

The rollback metadata table itself is not part of the canonical table snapshot. Historical
or orphaned tables, including retired protocol-v2 message tables, MUST NOT silently become
trusted state.

Adding or removing a protected table requires a versioned specification change.

## Database metadata

The persistent database carries one singleton rollback metadata row containing at least:

- format version;
- `relay_state_id`;
- positive integer revision;
- previous checkpoint digest.

The metadata update is committed in the same SQLite transaction as the protected mutation.

A database that already contains rollback-aware metadata but has no matching witness record
MUST fail closed. Normal startup must not silently reinitialize its witness.

## Canonical logical snapshot

Checkpointing is over logical rows, not raw SQLite file bytes.

Raw file hashing is rejected because page layout, free pages, WAL/checkpoint behavior,
VACUUM, and SQLite implementation details are not the security state.

The canonical payload is a strict versioned representation containing:

- relay-state format version;
- the exact protected-table set;
- each protected table's rows;
- rows sorted by a table-specific deterministic key;
- integers encoded as integers;
- text encoded as exact UTF-8 strings;
- no SQLite `rowid`, page metadata, indexes, or unprotected tables.

Each table specification defines the exact column order and sort key. Unknown/missing
columns or an unexpected protected schema fail closed.

## Checkpoint digest

The relay checkpoint digest is domain-separated and authenticated:

`HMAC-SHA256(relay_state_coordination_key, domain || state_id || revision || previous_digest || SHA-256(canonical_payload))`

The witness stores only the latest accepted revision and digest for the relay-state ID.

The database stores enough authenticated lineage metadata to validate exactly one
crash-recovery successor.

## Shared mutation coordinator

All persistent stores created for one GhostNode process MUST share one
`RelayStateCoordinator`.

No protected-table mutation may bypass it.

The first implementation supports one writable GhostNode process per database. Running two
independent writable GhostNode processes against the same SQLite database is outside the
supported model until an explicit cross-process ownership mechanism is specified.

The coordinator serializes security-relevant mutations in-process and uses
`BEGIN IMMEDIATE` for the SQLite write transaction.

## Normal mutation protocol

For every protected mutation:

1. acquire the shared coordinator mutation lock;
2. require the coordinator to be in a healthy acknowledged state;
3. open one SQLite connection and `BEGIN IMMEDIATE`;
4. verify current database metadata still matches the acknowledged checkpoint;
5. perform the store mutation;
6. if the logical protected state did not change, commit/rollback without advancing state;
7. otherwise set revision `r + 1` and `previous_digest = current_digest`;
8. build the canonical logical snapshot inside the same transaction;
9. derive the next checkpoint;
10. commit the SQLite transaction durably;
11. compare-and-set the witness from checkpoint `r` to `r + 1`;
12. only after successful witness CAS mark the coordinator healthy/acknowledged again.

A second protected mutation MUST NOT begin after step 10 until step 11 succeeds.

This limits normal crash recovery to at most one durable database revision ahead of the
witness.

## Startup and crash recovery

Before persistent GhostNode becomes ready, the coordinator loads:

- rollback metadata;
- the canonical logical snapshot;
- the witness record.

It then applies the same fail-closed reconciliation rules as ADR-0008.

If database and witness match, startup continues.

If the database is exactly one revision ahead of the witness, recovery may advance the
witness only when:

- the database revision is exactly witness revision plus one;
- database `previous_digest` equals the witness digest;
- the canonical logical snapshot validates;
- the recomputed next checkpoint is valid;
- witness compare-and-set succeeds.

Any older revision, same-revision digest divergence, gap greater than one, wrong state ID,
invalid lineage, missing required witness, or malformed protected schema fails closed.

## Read and readiness behavior

Persistent GhostNode MUST finish rollback reconciliation before it serves protected
persistent state.

A rollback/reconciliation failure latches the coordinator unhealthy. Health/readiness must
report failure and protected mutations must remain blocked.

The initial threat model is offline restore/snapshot rollback, not an attacker actively
rewriting SQLite pages under a running process. Active local host compromise remains outside
the protection boundary.

## Security consequences

With a current external witness this design detects rollback affecting:

- active pre-key publication continuity;
- consumed one-time pre-key state;
- requester allocation/idempotence state;
- pre-key anti-drain event history;
- authenticated request replay state;
- message insertion/deletion/expiry state.

The authenticated logical digest also detects same-revision divergence of protected rows
when the coordination key and witness remain uncompromised.

It does not protect against:

- compromise of the running GhostNode process;
- compromise of the relay-state coordination key;
- a malicious or rollbackable witness;
- a whole-VM/filesystem restore that also restores the reference witness;
- traffic analysis;
- key transparency, client device revocation, or client recovery;
- forensic recovery of old storage blocks.

## Witness backends

A development/reference witness may live in a private sidecar SQLite file for tests and
single-host deployments.

That backend only detects rollback of the GhostNode database while the witness sidecar
remains newer. It MUST be documented as insufficient against whole-filesystem or VM
snapshot rollback.

A production whole-host anti-rollback claim requires a witness outside the restored host
state domain.

## Migration

Legacy persistent GhostNode databases are not silently enrolled.

Migration must:

1. stop normal serving;
2. validate the existing protected schemas;
3. create relay-state identity and coordination material;
4. create revision 1 metadata;
5. compute the canonical logical snapshot and checkpoint;
6. initialize the witness exactly once;
7. reopen through normal reconciliation before becoming ready.

An already rollback-aware database with a missing witness is not a legacy database and
must not use the migration path as a reset mechanism.

## Implementation order

1. canonical relay snapshot + metadata parser;
2. shared coordinator and witness integration;
3. inject one coordinator into all persistent stores;
4. convert each protected mutation to coordinated transactions;
5. startup/readiness fail-closed wiring;
6. rollback/divergence/crash tests for each protected state class;
7. Oracle runbook and threat-model update.

Implementation should remain split into reviewable PRs. No phase may weaken existing
DeviceID authentication, replay checks, pre-key atomicity, anti-drain logic, or message
lifecycle behavior.
