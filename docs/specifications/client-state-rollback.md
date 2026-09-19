# Client-state rollback checkpoints and witness

Status: checkpoint/witness primitives plus profile-v5, contact-store, replay-state, and ratchet-vault/highest-seen integration implemented. The reference SQLite witness remains development-only.

## Scope

This specification defines the common checkpoint format and monotonic-witness contract used
by ADR-0008.

Profile v5 provides the root state identity, authenticated profile checkpoint metadata and persisted monotonic device lifecycle state.
Contact trust, replay state, and the ratchet/highest-seen vault now adopt this checkpoint
format and reconcile against the monotonic witness before ordinary use.

GhostLink still does not claim complete whole-device rollback protection with the reference
SQLite witness, because that witness normally shares the same filesystem snapshot domain.
A production claim requires a witness backend outside the restored state domain.

## Root material

One rollback-aware client state set uses:

- `client_state_id`: 128 random bits encoded as 32 lowercase hexadecimal characters;
- `state_coordination_key`: exactly 32 random bytes.

The coordination key is secret and must be independent of all other GhostLink keys.

The currently reserved component names are exactly:

- `profile`;
- `contacts`;
- `ratchet`;
- `replay`.

## Revision

Each component has its own positive monotonic revision.

Revision values are limited to the JSON-safe integer range:

`1 .. 2^53 - 1`

Revision 1 has no previous checkpoint digest.

Every later revision contains the exact digest of the preceding component checkpoint.

## Canonical checkpoint document

Checkpoint digest construction uses this logical JSON document:

```json
{
  "component": "contacts",
  "payload_sha256": "<64 lowercase hex>",
  "previous_digest": null,
  "revision": 1,
  "state_id": "<32 lowercase hex>",
  "version": 1
}
```

For revisions greater than 1, `previous_digest` is a 64-character lowercase hexadecimal
HMAC digest rather than `null`.

The document is serialized as UTF-8/ASCII JSON with:

- object keys sorted lexicographically;
- no insignificant whitespace;
- separators exactly `,` and `:`;
- ASCII escaping enabled.

The component payload itself is not inserted into the checkpoint JSON. Instead:

`payload_sha256 = lowercase_hex(SHA-256(exact_canonical_component_payload_bytes))`

Component specifications define their exact canonical payload bytes.

## Checkpoint digest

The domain is the byte string:

`ghostlink-client-state-checkpoint-v1\x00`

The checkpoint digest is:

`lowercase_hex(HMAC-SHA256(state_coordination_key, domain || canonical_checkpoint_json))`

The component persists its revision and previous digest inside its own authenticated state.
The current checkpoint digest is recomputed from the component payload and stored by the
monotonic witness.

A loader must recompute the digest before comparing revision state with the witness.

## Stable checkpoint vector

For:

- coordination key: bytes `00 01 02 ... 1f`;
- state ID: `00112233445566778899aabbccddeeff`;
- component: `contacts`;
- revision: `1`;
- previous digest: `null`;
- exact payload bytes: `{"records":[],"version":1}`;

the checkpoint digest is:

`9fd5aba6d04d705529255c2ba24a4c3ffce468d349897370251a51801ec5b800`

This vector is normative for future Python/TypeScript interoperability.

## Witness record

The witness stores the latest accepted pair:

- component revision;
- checkpoint digest.

The reference SQLite development backend authenticates each stored record with the same
coordination key.

The logical witness-record JSON is:

```json
{
  "component": "contacts",
  "digest": "<checkpoint digest>",
  "revision": 1,
  "state_id": "<32 lowercase hex>",
  "version": 1
}
```

It uses the same canonical JSON rules.

The witness-record MAC domain is:

`ghostlink-client-state-witness-record-v1\x00`

The record MAC is:

`lowercase_hex(HMAC-SHA256(state_coordination_key, domain || canonical_record_json))`

For the stable checkpoint vector above, the witness-record MAC is:

`4b0890330d359f9e7dc824ce10afd2e300d2c70cf364bcc939e8903b45a60003`

## Witness compare-and-set

A witness backend is scoped to one `client_state_id`.

It supports:

- read current record by component;
- persist an authenticated component-scoped bootstrap intent before first state publication;
- atomically convert that intent into the component's revision-1 witness record;
- initialize a component explicitly exactly once at revision 1 for controlled migration/test paths;
- atomic compare-and-set from one exact record to its exactly-next revision.

Compare-and-set checks both the expected revision and expected digest.

A stale concurrent writer therefore cannot overwrite a newer witnessed checkpoint.

## Open/reconcile algorithm

Given an authenticated component checkpoint and its exact canonical payload:

1. recompute and verify the checkpoint digest;
2. read the witness record;
3. if the witness is missing at revision 1, permit initialization only when an authenticated
   bootstrap intent for that state ID/component already exists in the witness backend;
4. atomically convert that intent into the revision-1 witness record and consume the intent;
5. otherwise fail if the witness is missing after initialization;
6. fail if component revision is lower than witness revision;
7. at equal revisions, require equal digest;
8. permit exactly one component revision ahead only when its previous digest equals the
   current witness digest;
9. in that one-ahead case, compare-and-set the witness forward;
10. fail when the component is more than one revision ahead.

The one-ahead rule exists only for a crash after durable component commit and before
witness commit.

First initialization uses a separate bootstrap transaction:

1. write the authenticated bootstrap intent into the witness domain;
2. publish revision-1 component state;
3. atomically replace the intent with the revision-1 witness record.

A crash before step 2 may retry the initial publication because no witness record has yet
committed. A crash after step 2 but before step 3 may finalize only while the authenticated
intent still exists. Deleting/replacing the witness database removes that authorization and
normal open fails closed.

The bootstrap intent is component-scoped, lives in the same rollback domain as the
reference witness, and is not an external freshness source. Restoring a coherent old
snapshot containing both a pending intent and matching revision-1 component state remains
inside the already documented same-domain rollback limitation.

A writer is not permitted to perform another security-relevant component mutation until
its witness update succeeds.

## Reference SQLite witness

`SQLiteMonotonicWitness` is the deterministic development and test backend.

Properties:

- SQLite `BEGIN IMMEDIATE` serialization for bootstrap/finalize/initialize/compare-and-set;
- authenticated witness records and authenticated bootstrap intents;
- private `0600` file mode on POSIX;
- `synchronous=FULL`;
- multiple state IDs may coexist in one database;
- wrong coordination key or modified record fails authentication.

This backend is intentionally not a production whole-device anti-rollback primitive.

Deleting, restoring or snapshotting the SQLite witness together with the protected client
state can remove the freshness signal.

## Security boundary

Phase 1 provides:

- deterministic authenticated checkpoint construction;
- explicit component lineage;
- strict monotonic witness storage interface;
- stale-writer rejection;
- same-revision divergence detection;
- older-component rollback detection when the witness remains current;
- crash-safe first-bootstrap completion plus one-step witness roll-forward.

The contact-trust store is the first runtime component integrated with these checkpoints.
Its legacy v1 format requires explicit migration, and normal CLI access uses witness
reconciliation before trust state is consumed or mutated.

Replay state is now integrated: pruning, acceptance and replay checkpoint metadata commit
inside one SQLite transaction, followed by witness compare-and-set. A crash after the
SQLite commit may roll the witness forward by exactly one linked revision on restart.

Ratchet-vault/highest-seen state is integrated through the Python/Node RPC boundary.
The Node engine stores ratchet revision and previous-digest lineage inside authenticated
vault ciphertext, while Python independently computes the checkpoint over the exact
serialized encrypted vault bytes and advances the witness. The engine refuses another
state-changing vault operation until Python acknowledges the current checkpoint digest.

Profile v5 is itself coordinated by the reserved `profile` witness component. Fresh
profiles initialize that record, normal lifecycle-aware CLI loads reconcile it before use,
and explicit profile migration enrolls legacy v4-or-earlier state. Security-relevant
profile successors must increment the profile revision, link `state_previous_digest` to the
current checkpoint and durably replace the encrypted profile before witness compare-and-set.

Initial private profile files and device-recovery pending profiles use exclusive `O_EXCL`
creation, flush and `fsync` the file contents, then `fsync` the parent directory on POSIX.
A synchronous write/fsync failure removes the just-created target before returning failure.
Existing-profile promotion continues to use temporary-file write, file fsync, atomic
replacement and parent-directory fsync.

These tests exercise injected write/fsync failures and restart behavior. They do not
constitute proof against every physical power-cut, storage-controller or filesystem
reordering behavior.

A future production backend must keep witness state outside the rollback domain being
claimed as protected.


## Backup and restore procedure

Treat the following files for one profile as one coordinated security state set:

- the encrypted profile itself;
- the encrypted contact store;
- the encrypted ratchet vault;
- the replay database;
- the monotonic witness backend used for that client-state ID.

For the default development layout these are typically:

```text
alice.ghost
alice.ghost.contacts
alice.ghost.ratchet
alice.ghost.state.sqlite3
alice.ghost.witness.sqlite3
```

A backup may copy application-state files, but ordinary restore MUST NOT silently replace
or recreate a monotonic witness record.

If an older contact, replay, or ratchet component is restored while the witness remains
current, normal open must fail closed with rollback/divergence rather than resetting the
component or witness.

If a whole-filesystem snapshot restores the SQLite witness together with all protected
files, the reference development backend cannot detect that whole-snapshot rollback. This
is why it is not a production whole-device anti-rollback primitive.

Moving state to another machine, deliberately replacing a witness backend, or recovering
after confirmed witness loss is an explicit recovery operation and is not implemented by
ordinary CLI open/migration commands. The operator must first establish that the selected
backup is the intended latest state and then use a separately reviewed recovery/rebinding
procedure. Deleting `*.witness.sqlite3` and rerunning ordinary commands is not a valid
recovery procedure.

Legacy migration commands are only for components that genuinely predate rollback-aware
metadata. They must not be used as a generic way to rebind an already rollback-aware
component whose witness record disappeared.
