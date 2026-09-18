# Client-state rollback checkpoints and witness

Status: phase-1 primitives implemented; component integration pending under issue #79.

## Scope

This specification defines the common checkpoint format and monotonic-witness contract used
by ADR-0008.

It does not by itself make the current GhostLink client rollback-proof. The profile,
contact store, replay cache and ratchet vault must each adopt this format, and complete
whole-snapshot protection additionally requires a witness backend outside the restored
state domain.

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
- initialize a component exactly once at revision 1;
- atomic compare-and-set from one exact record to its exactly-next revision.

Compare-and-set checks both the expected revision and expected digest.

A stale concurrent writer therefore cannot overwrite a newer witnessed checkpoint.

## Open/reconcile algorithm

Given an authenticated component checkpoint and its exact canonical payload:

1. recompute and verify the checkpoint digest;
2. read the witness record;
3. fail if the witness is missing after initialization;
4. fail if component revision is lower than witness revision;
5. at equal revisions, require equal digest;
6. permit exactly one component revision ahead only when its previous digest equals the
   current witness digest;
7. in that one-ahead case, compare-and-set the witness forward;
8. fail when the component is more than one revision ahead.

The one-ahead rule exists only for a crash after durable component commit and before
witness commit.

A writer is not permitted to perform another security-relevant component mutation until
its witness update succeeds.

## Reference SQLite witness

`SQLiteMonotonicWitness` is the deterministic development and test backend.

Properties:

- SQLite `BEGIN IMMEDIATE` serialization for initialize/compare-and-set;
- authenticated witness records;
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
- crash-safe one-step witness roll-forward.

Phase 1 does not yet protect any existing GhostLink component until that component is
migrated to carry checkpoint metadata.

A future production backend must keep witness state outside the rollback domain being
claimed as protected.
