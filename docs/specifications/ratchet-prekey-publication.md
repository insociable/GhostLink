# Ratchet pre-key publication format

Status: experimental implementation

## Purpose

A GhostLink pre-key publication is the exact device-signed public payload that will later be submitted atomically to GhostNode.

It is produced only after the ratchet engine has durably prepared the corresponding private pre-key generation.

The publication contains no private libsignal material.

## Trust chain

The publication preserves the existing trust chain:

```text
GhostID
  |
  v
certified DeviceID
  |
  v
DeviceID Ed25519 signature
  |
  v
binding v2
  |
  v
libsignal public pre-key material
```

GhostNode will store already signed bindings. It must not assemble, edit or re-sign their fields.

## Outer format

The publication is deterministic JSON:

```json
{
  "version": 1,
  "publication_sequence": 7,
  "one_time": [ "... binding-v2 objects ..." ],
  "fallback": "... binding-v2 object ..."
}
```

The real `one_time` and `fallback` values are JSON binding objects, not strings.

The full serialized publication is limited to 1 MiB.

The canonical serialized form uses sorted keys and compact separators.

## Generation invariants

One publication contains:

- one positive JSON-safe publication sequence;
- between 1 and 256 one-time bindings;
- exactly one fallback binding.

Every binding must share:

- GhostID;
- DeviceID;
- libsignal protocol address;
- registration ID;
- identity public key;
- signed EC pre-key ID/public key/signature;
- issued-at timestamp;
- expires-at timestamp;
- publication sequence.

Every one-time binding:

- has `bundle_kind = one_time`;
- contains one EC one-time pre-key;
- contains one Kyber/ML-KEM one-time pre-key.

The fallback binding:

- has `bundle_kind = fallback`;
- contains no EC one-time pre-key;
- contains the generation last-resort Kyber/ML-KEM pre-key.

The publication rejects:

- duplicate 128-bit bundle IDs;
- duplicate EC one-time pre-key IDs;
- duplicate Kyber pre-key IDs;
- reuse of the fallback Kyber ID as a one-time Kyber ID;
- mixed identity/signed-pre-key/timestamp generations.

## Signing

Python owns the enrolled GhostLink device signing key.

For every public libsignal bundle returned by the local ratchet engine Python:

1. creates a binding v2;
2. assigns the generation publication sequence;
3. assigns `bundle_kind`;
4. signs the canonical binding bytes with the certified DeviceID signing key.

The outer publication is not separately signed because every member binding is individually authenticated and all generation invariants are verified locally before serialization.

The publication sequence is already inside every binding signature.

## Durable staging

The exact canonical publication JSON is written back into the encrypted ratchet vault before any future network publication.

The lifecycle state therefore contains both:

- the private records required to reconstruct the generation;
- the exact signed public payload intended for GhostNode.

A staged payload may be written again only if it is byte-for-byte identical.

A different payload for the same pending generation fails closed.

## Crash recovery

### Crash after private generation preparation, before signing

The private generation already exists in the encrypted vault.

After restart the Node engine reconstructs the same public bundles from persisted:

- EC one-time records;
- signed EC pre-key record;
- one-time Kyber records;
- last-resort Kyber record;
- identity state.

Python can then sign and stage the recovered generation.

### Crash after staging

After restart Python retrieves the exact staged JSON.

Before returning it for publication it:

1. parses the publication strictly;
2. verifies every DeviceID signature against the local enrolled device;
3. compares every binding to the reconstructed pending libsignal material;
4. requires identical sequence, timestamps and public keys.

Only then is the original staged string returned.

No new bundle IDs or signatures are generated after staging.

## RPC boundary

The local RPC exposes:

- `prepare_prekey_generation`;
- `get_pending_prekey_generation`;
- `stage_prekey_publication`.

The RPC remains local framed stdio. It is not exposed over a network socket.

## Security limitations

This staging mechanism protects continuity across normal process crashes and prevents accidental regeneration of a different payload for an already staged generation.

It does not protect against:

- compromise of the running Python or Node client;
- compromise of the enrolled DeviceID signing key;
- rollback of the entire encrypted vault to an older valid snapshot;
- a malicious future relay withholding or replaying still-valid publications.

Relay monotonic publication semantics and sender-side highest-seen sequence state are separate layers.

GhostLink remains pre-alpha and has not undergone an independent cryptographic audit.
