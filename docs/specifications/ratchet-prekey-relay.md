# GhostNode ratchet pre-key publication relay

Status: publication path implemented; fetch/pop and anti-drain controls pending

## Purpose

GhostNode stores already signed public ratchet pre-key generations for one self-certifying GhostLink DeviceID.

This endpoint is intentionally publication-only at this stage.

GhostNode does not:

- generate pre-keys;
- hold private pre-key material;
- rewrite binding fields;
- sign bindings;
- verify the user's GhostID trust relationship;
- hand out one-time bindings yet.

The future fetch path remains disabled until atomic consumption and anti-drain controls are implemented together.

## Route

```text
PUT /v2/prekeys/{device_id}
```

The request contains:

- request version;
- the 32-byte Ed25519 device signing public key as canonical Base64;
- the exact canonical signed pre-key publication JSON.

The configured shared relay Bearer token is also required when relay authentication is enabled.

## Publication authorization

The relay does not need the full GhostLink contact bundle to authorize control of a DeviceID.

DeviceID is self-certifying from the device Ed25519 signing public key.

GhostNode therefore verifies:

1. the supplied signing public key is canonical 32-byte Ed25519 public material;
2. deriving a DeviceID from that key equals the DeviceID in the route;
3. the publication parses under the strict publication/binding-v2 formats;
4. the publication is canonical JSON;
5. every binding's DeviceID and libsignal protocol address equal the route DeviceID;
6. every binding's DeviceID signature verifies under the supplied device public key;
7. no binding is issued more than five minutes in the future;
8. the generation is not already expired.

The Bearer token alone cannot authorize a forged generation for another DeviceID.

An attacker must possess the corresponding DeviceID private signing key to create a new valid publication for that DeviceID.

## GhostID trust remains end-to-end

GhostNode deliberately does not receive the long-term GhostID identity public key or the full device certificate merely to publish pre-keys.

Consequently, relay-side publication verification establishes:

```text
control of DeviceID signing key
        +
binding integrity
```

It does not establish that a recipient should trust the GhostID claimed inside the binding.

Senders must still verify fetched bindings against their already verified GhostLink contact/certificate state before establishing a libsignal session.

This preserves the end-to-end trust boundary and minimizes identity metadata disclosed to GhostNode.

## Sequence semantics

One active generation exists per DeviceID.

The relay enforces:

- first accepted sequence is exactly 1;
- an exact retry of the active sequence is idempotent;
- the active sequence with different payload is rejected;
- lower sequences are rejected;
- skipped sequences are rejected;
- replacement must be exactly `active + 1`.

The publication sequence is also covered by every DeviceID binding signature.

These rules provide relay-side monotonic continuity for the current database state.

They do not make the relay database rollback-proof.

Restoring an older valid relay database snapshot can restore an older active sequence. Sender-side highest-seen sequence persistence remains necessary to detect that after observation.

## Persistence

The in-memory implementation serializes publication replacement with a process-local lock.

The SQLite implementation uses:

```text
BEGIN IMMEDIATE
```

to serialize publication replacement.

SQLite stores:

- active publication sequence;
- generation expiration;
- exact canonical publication payload;
- fallback signed binding;
- ordered one-time signed bindings.

The database contains public signed material only.

On POSIX systems the database file retains private file permissions already used by GhostNode storage.

## Atomic replacement

A successful replacement updates the active publication and its one-time pool in one SQLite transaction.

A failed sequence check or conflicting retry rolls back without replacing the active generation.

Old relay-side one-time rows may be discarded after successful replacement because delayed senders already hold any binding they previously fetched; recipient private material retention is a separate client-side lifecycle concern.

## Fetch intentionally disabled

There is currently no public endpoint that returns or consumes the stored one-time bindings.

This is deliberate.

Publishing a fetch endpoint before anti-drain controls would allow any authorized relay client to exhaust another DeviceID's one-time pool and force fallback usage.

The fetch milestone must add together:

- atomic one-time pop;
- fallback behavior;
- remaining-count reporting;
- bounded request rate / anti-drain controls;
- concurrency tests proving one binding is not handed to two honest simultaneous fetchers.

## Failure and abuse properties

A malicious or compromised GhostNode can still:

- deny publication;
- withhold future fetches;
- delete stored public material;
- roll its database back;
- later replay still-valid signed bindings;
- observe DeviceIDs, publication timing, pool size and public pre-key material.

It cannot silently alter a binding without invalidating the DeviceID signature.

This API does not provide key transparency.

## Current limitations

- shared Bearer access control is not general per-device authentication for the message relay;
- publication authorization is cryptographic for the target DeviceID, but revocation policy is not yet implemented;
- relay database rollback protection is not implemented;
- fetch/pop and anti-drain are not implemented;
- the client-side pending -> active acknowledgement primitive is implemented, but HTTP publication orchestration/receipt validation is not yet wired;
- replenishment, rotation and GC execution are not implemented.

GhostLink remains pre-alpha and has not undergone an independent cryptographic/protocol audit.
