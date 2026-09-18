# GhostNode ratchet pre-key publication relay

Status: publication and authenticated atomic fetch/pop implemented; sender orchestration pending

## Purpose

GhostNode stores already signed public ratchet pre-key generations for one self-certifying GhostLink DeviceID.

GhostNode now exposes publication plus authenticated allocation of already signed public bindings.

GhostNode does not:

- generate pre-keys;
- hold private pre-key material;
- rewrite binding fields;
- sign bindings;
- verify the user's GhostID trust relationship;
- establish libsignal sessions for clients.

Fetch authorization proves control of a requester DeviceID. It does not prove that the target trusts that requester. GhostID trust remains end-to-end at the sender/recipient layer.

## Routes

Publication:

```text
PUT /v2/prekeys/{device_id}
```

Authenticated fetch/allocation:

```text
POST /v2/prekeys/{device_id}/fetch
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

## Fetch requester proof

A fetch request contains:

- version 1;
- requester DeviceID;
- requester Ed25519 signing public key;
- random 128-bit lowercase-hex `request_id`;
- `issued_at`;
- requester Ed25519 signature.

The signed canonical message is domain-separated and includes the target DeviceID from the route. Redirecting a captured request to another target therefore invalidates the signature.

GhostNode verifies:

1. canonical requester DeviceID syntax;
2. canonical 32-byte Ed25519 public key encoding;
3. `derive_device_id(requester_signing_public_key) == requester_device_id`;
4. request timestamp within the five-minute acceptance window;
5. requester signature over the target-bound canonical request.

The shared Bearer token remains an additional relay access control when configured. Bearer possession alone is not treated as requester identity.

## Atomic allocation semantics

For one active target generation:

- the first authenticated requester allocation removes exactly one one-time signed binding;
- the same requester DeviceID receives at most one one-time allocation for that target publication sequence;
- repeated or concurrent requests from that requester return the same stored allocation;
- distinct concurrent requesters receive distinct one-time bindings while the pool is non-empty;
- once the one-time pool is empty, the reusable signed fallback binding is returned;
- the response includes target/requester DeviceIDs, publication sequence, expiration, bundle kind and remaining one-time count.

The SQLite implementation performs lookup, rate-limit check, one-time deletion, allocation persistence and remaining-count calculation inside one `BEGIN IMMEDIATE` transaction.

## Anti-drain controls and limits

GhostNode limits **new one-time allocations per target DeviceID per time window**.

Defaults:

```text
window = 60 seconds
max_new_one_time_allocations = 10
```

Both values are configurable.

Idempotent retries are checked before this limiter, so retrying an existing allocation is not blocked and cannot consume another one-time key.

This materially limits accidental retry drain and slows a bearer-authorized attacker. It is **not Sybil-proof**: an attacker able to create many self-certifying requester DeviceIDs can still consume multiple allocations over time. Stronger admission, abuse controls, or transparency are separate future work.

## Persistence

The in-memory implementation serializes publication replacement and allocation with a process-local lock.

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
- currently unallocated one-time signed bindings;
- requester/target/generation allocation records;
- short-window target allocation-rate events.

All stored pre-key bindings remain public signed material. Requester DeviceIDs and allocation timing are metadata, not secret key material.

The database contains public signed material only.

On POSIX systems the database file retains private file permissions already used by GhostNode storage.

## Atomic replacement

A successful replacement updates the active publication and its one-time pool in one SQLite transaction.

A failed sequence check or conflicting retry rolls back without replacing the active generation.

Publication retry compares the immutable canonical publication payload, not the mutable remaining one-time pool. Therefore retrying the exact publication after fetches is idempotent and never restores consumed one-time rows.

Old relay-side one-time rows may be discarded after successful replacement because delayed senders already hold any binding they previously fetched; recipient private material retention is a separate client-side lifecycle concern.

## Sender verification boundary

The fetch endpoint returns a target-signed binding but does not itself establish target trust.

The application sender must still:

1. parse the returned binding strictly;
2. verify the binding against its existing `VerifiedContact`;
3. verify expiration and DeviceID signature;
4. enforce the locally persisted highest-seen publication sequence;
5. only then pass the public material into libsignal session establishment.

That application workflow remains the next milestone.

## Failure and abuse properties

A malicious or compromised GhostNode can still:

- deny publication;
- withhold future fetches;
- delete stored public material;
- roll its database back;
- later replay still-valid signed bindings;
- observe requester DeviceID -> target DeviceID fetch relationships, timing, pool size and public pre-key material.

It cannot silently alter a binding without invalidating the DeviceID signature.

This API does not provide key transparency.

## Client publication orchestration

The application layer now performs publication as one crash-safe workflow:

1. recover or prepare the exact staged signed publication;
2. submit it to GhostNode with the self-certifying DeviceID signing public key;
3. require HTTP 200;
4. parse the receipt with exact fields and bounded integer values;
5. require receipt DeviceID, publication sequence, expiration and one-time count to equal the locally staged publication;
6. only then call the local ratchet-engine publication commit.

A successful HTTP status alone is not sufficient to mutate local lifecycle state.

If the relay stores the generation but the response is lost, the local state remains pending. Restart retries the exact staged payload; GhostNode's same-sequence exact retry is idempotent.

If the relay returns a malformed or mismatched receipt, the client fails closed and leaves the generation pending.

## Current limitations

- shared Bearer access control is not general per-device authentication for the message relay;
- publication authorization is cryptographic for the target DeviceID, but revocation policy is not yet implemented;
- relay database rollback protection is not implemented;
- requester authentication and target rate limiting reduce drain but are not Sybil-resistant admission control;
- sender-side HTTP fetch -> VerifiedContact verification -> libsignal orchestration is not yet wired;
- replenishment, rotation and GC execution are not implemented.

GhostLink remains pre-alpha and has not undergone an independent cryptographic/protocol audit.
