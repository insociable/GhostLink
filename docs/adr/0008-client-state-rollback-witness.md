# ADR-0008: Rollback-aware client state with an external monotonic witness

- Status: Accepted for implementation
- Date: 2026-09-18
- Tracks: #79

> Implementation note (current runtime): profile v5 supersedes profile v4 while retaining the client-state identity, coordination key and checkpoint model introduced by this ADR. The v5 profile additionally carries monotonic device lifecycle state under ADR-0010.

## Context

GhostLink already authenticates or encrypts its sensitive local state, but authenticated
encryption alone does not prove freshness. An attacker or restore operation can replace a
current valid state file with an older valid copy.

The affected state is split across multiple stores:

- the encrypted local profile;
- the encrypted contact-trust store;
- the encrypted libsignal ratchet/pre-key vault;
- the local replay cache and its security-relevant continuity state.

The ratchet vault also carries the highest remote pre-key publication sequence observed by
the client. Rolling that vault back can therefore erase a previously learned anti-rollback
signal.

A counter stored beside these files is not sufficient. A full application-data or
filesystem snapshot can restore both the protected state and the counter to the same old
point.

## Decision

GhostLink will introduce rollback-aware client-state coordination backed by a monotonic
witness outside the normal component state.

The design separates two properties:

1. **component coherence and rollback detection**, implemented in GhostLink; and
2. **whole-snapshot freshness**, which is only as strong as the witness backend.

GhostLink MUST NOT claim complete whole-device anti-rollback when the witness can be
rolled back together with the application state.

## Client-state identity

Profile v4 will introduce:

- a random 128-bit `client_state_id`;
- an independently random 32-byte `state_coordination_key`.

Both values are stable for the lifetime of one migrated local client state set.

The coordination key is independent of:

- the profile password;
- identity and device private keys;
- the ratchet-vault master key;
- the contact-store key.

The `client_state_id` binds all coordinated components to the same logical local client.
Mixing a component from another client state set MUST fail closed.

## Component checkpoint

Each coordinated component has an independent monotonic revision.

A logical checkpoint contains at least:

- checkpoint format version;
- `client_state_id`;
- component name;
- positive integer revision;
- previous checkpoint digest;
- canonical component payload.

The current checkpoint digest is:

`HMAC-SHA256(state_coordination_key, domain || state_id || component || revision || previous_digest || SHA-256(canonical_payload))`

The current digest is stored by the witness. The component stores enough authenticated
metadata to recompute it and to prove one-step lineage from the previous witness record.

The digest construction is domain-separated and versioned. Canonical serialization is
defined by each component specification and MUST reject unknown fields.

## Witness contract

The witness is addressed by `(client_state_id, component)` and stores exactly the latest
accepted:

- revision;
- checkpoint digest.

A witness backend MUST provide an atomic compare-and-set operation:

`CAS(expected_revision, expected_digest, next_revision, next_digest)`

A production anti-rollback claim requires the witness to remain monotonic when GhostLink's
ordinary application state is restored to an older snapshot.

## Normal update protocol

Before a component mutation:

1. load the witness record;
2. load and authenticate the current component;
3. require exact equality between component revision/digest and witness revision/digest;
4. construct revision `r + 1` with `previous_digest = current_digest`;
5. durably commit the component;
6. atomically compare-and-set the witness from the old checkpoint to the new checkpoint.

A writer MUST NOT perform another security-relevant mutation of that component until step
6 succeeds.

This rule limits crash recovery to at most one durable component revision ahead of the
witness.

## Crash recovery

Three crash points are valid:

### Before component commit

The component and witness remain at revision `r`. Normal open continues.

### After component commit, before witness commit

The component is at `r + 1` while the witness remains at `r`.

Recovery MAY advance the witness only when all of the following hold:

- component revision is exactly witness revision plus one;
- component `previous_digest` equals the witness digest;
- the component authenticates successfully;
- the recomputed new checkpoint digest is valid;
- witness compare-and-set from `r` to `r + 1` succeeds.

This is a roll-forward of an already durable authenticated write, not acceptance of an
older state.

### After witness commit

Both component and witness are at `r + 1`. Normal open continues.

## Fail-closed cases

GhostLink MUST reject the component when:

- component revision is lower than witness revision;
- equal revisions have different digests;
- component revision is more than one ahead of the witness;
- one-step lineage does not match the witness digest;
- `client_state_id` or component name differs;
- checkpoint authentication or canonical parsing fails;
- a required witness record disappears after initialization.

There is no automatic witness reset and no automatic adoption of an older state.

## Component integration

### Profile

Profile v4 carries `client_state_id`, `state_coordination_key`, and profile checkpoint
metadata inside authenticated encrypted profile content.

Profile migration is explicit. Restoring profile v3 after a v4 migration is not silently
accepted when a witness exists.

### Contact trust store

The encrypted contact store receives checkpoint metadata in its authenticated plaintext.
A rollback that would restore an older `verified`, `changed`, candidate, or pinned
identity state is rejected when the witness remains current.

### Ratchet vault

The ratchet engine persists checkpoint metadata inside the encrypted vault snapshot and
updates the witness as part of every durable state mutation protocol.

The highest-seen remote publication sequence is therefore covered by the same rollback
boundary as libsignal session and pre-key lifecycle state.

The Python/Node boundary MUST expose witness coordination without placing the coordination
key in argv or environment variables.

### Replay state

The replay database receives authenticated checkpoint metadata bound with the
`state_coordination_key`.

Replay acceptance and pruning MUST update replay state and its checkpoint atomically from
SQLite's point of view, followed by the witness compare-and-set.

A replay database restored to an older authenticated checkpoint is rejected when the
witness remains newer.

## Witness backends

### Development file witness

A private atomically replaced file-backed witness MAY be implemented for deterministic
tests and development.

It protects against component rollback only while that witness file remains newer.

It MUST carry an explicit warning that it does not protect against a filesystem or machine
snapshot that rolls back the witness itself.

### Production witness

A production backend must live outside the rollback domain of ordinary GhostLink state.
Candidates include suitable hardware/OS monotonic storage or a separately specified
external transparency/witness mechanism.

This ADR defines the interface and security requirements but does not select one universal
production backend.

## Backup and restore

Normal backups must treat the coordinated component set as security-sensitive state.

Restoring an older backup while the monotonic witness remains current MUST fail closed.

Migration to a new machine or deliberate witness replacement requires an explicit recovery
procedure that proves the chosen backup is the intended latest state and creates a new
witness binding. It MUST NOT happen automatically during ordinary open.

A future recovery design may add signed export/import checkpoints, but that is outside this
ADR.

## Migration

Legacy client state is not silently enrolled.

The migration sequence is explicit:

1. upgrade the local profile to v4, generating the state identity and coordination key;
2. checkpoint each existing component from its authenticated current state;
3. initialize witness records exactly once;
4. verify every component against its initialized witness before completing migration.

If a component already contains rollback-aware metadata but its witness record is missing,
normal runtime fails closed instead of reinitializing it.

## Security consequences

This design detects:

- rollback of one coordinated component while the witness remains current;
- mix-and-match state from a different local client;
- divergent state at the same revision;
- rollback of highest-seen remote publication sequence with the ratchet vault;
- rollback of replay state with a current witness;
- complete application-state rollback when the witness backend is outside that rollback
  domain.

It does not protect against:

- malware controlling an unlocked client;
- compromise of the coordination key;
- compromise or rollback of the witness backend itself;
- a malicious production witness violating its monotonic contract;
- traffic analysis, key transparency, relay rollback, device revocation or recovery;
- forensic recovery of old storage blocks.

## Implementation order

Implementation should remain split into small reviewable changes:

1. checkpoint primitives and witness interface;
2. explicit profile-v4 migration and state identity;
3. contact-store integration;
4. replay-state integration;
5. ratchet-vault/RPC integration;
6. backup/recovery documentation and complete end-to-end rollback tests.

No phase may weaken existing fail-closed contact, ratchet, replay or pre-key behavior.

## Acceptance

Issue #79 is complete only when:

- rollback-aware formats are versioned and strictly parsed;
- witness loss, rollback and divergence fail closed;
- the one-step crash recovery path is tested;
- contact, replay and ratchet/highest-seen rollback tests pass;
- profile migration is explicit and atomic;
- whole-snapshot protection is claimed only for a witness backend that actually survives
  the tested rollback domain;
- threat-model and operational documentation state the remaining limitations precisely.
