# GhostLink Local Profile v5

## Purpose

A local profile persists the private material required for one GhostLink identity/device
and the independent local keys used for encrypted client state across restarts.

Unlike a Contact Bundle or QR payload, a local profile contains private material and MUST
NOT be shared.

## Version 5 payload

Profile v5 retains three independently random 32-byte local-state keys:

- `ratchet_master_key`: unlocks the encrypted libsignal ratchet/pre-key vault;
- `contact_store_key`: protects the local human-trust contact store;
- `state_coordination_key`: authenticates rollback-aware component checkpoints.

It also contains a random 128-bit lowercase-hex `client_state_id` that binds coordinated
local-state components to one logical client state set.

The profile component persists rollback-lineage metadata inside the encrypted payload:

- `state_revision`: a positive JSON-safe monotonic revision, initialized to `1`;
- `state_previous_digest`: `null` at revision 1 and the preceding 32-byte checkpoint
  digest for later revisions.

Profile v5 also stores the exact canonical identity-signed device lifecycle statement
defined by ADR-0010. A fresh profile starts at lifecycle epoch 1. The statement must name
the same active DeviceID and GhostID as the private profile keys; mismatch, invalid
signature or non-canonical lifecycle state fails closed.

All local-state keys are generated independently with PyNaCl randomness. None is derived
from another local key, identity/device keys, the profile password, GhostID or DeviceID.

The coordination key and client-state ID exist only inside the authenticated profile
ciphertext. They are not included in Contact Bundles, QR payloads, GhostNode data,
command-line arguments or environment variables.

## At-rest protection

Profile v5 uses libsodium SecretBox through PyNaCl. The SecretBox key is derived from the
user password with Argon2id.

The outer document stores only:

- version;
- random Argon2id salt;
- fixed supported KDF parameters;
- cipher identifier;
- authenticated ciphertext.

GhostLink does not implement a custom cipher or password KDF.

## Validation

When a profile is opened, GhostLink verifies the existing identity/device relationships and
requires current v5 state material to use exact canonical sizes:

- ratchet master key: 32 bytes;
- contact-store key: 32 bytes;
- state-coordination key: 32 bytes;
- client-state ID: 128-bit lowercase hexadecimal;
- state revision: positive JSON-safe integer;
- previous digest: absent/null only at revision 1, otherwise 32-byte lowercase hexadecimal.

Malformed or inconsistent profiles are rejected.

## v1, v2, v3 and v4 compatibility

Older profiles remain readable for explicit migration:

- v1 contains no local-state keys;
- v2 contains the ratchet master key only;
- v3 contains ratchet and contact-store keys;
- v4 adds the stable client-state identity and independent coordination key;
- v5 adds the persisted identity-signed monotonic active-device lifecycle statement.

Missing legacy fields decode as `None`. The explicit migration command remains:

```bash
ghostlink profile-upgrade --profile alice.ghost
```

The upgrade preserves GhostID, DeviceID, identity/device private material and all existing
valid local-state keys. It generates only missing keys/state identity, serializes profile
v5 under the same password, and atomically replaces the encrypted profile.

There is no silent migration during messaging or trusted-contact operations.

A partially present state identity/coordination-key pair is invalid and fails closed rather
than silently generating the missing half.

## Rollback-aware state boundary

Profile v5 is the root source for the stable `client_state_id` and
`state_coordination_key` defined by ADR-0008.

The profile component itself is now enrolled in the reserved `profile` witness record.
Normal lifecycle-aware CLI profile loads reconcile the encrypted profile against that
record before using its security state. Equal-revision divergence, older-profile rollback,
missing witness state and invalid one-step lineage fail closed. A crash after a durable
profile successor is written but before witness compare-and-set may advance the witness by
exactly one linked revision on the next open.

Contact, replay and ratchet-vault stores keep their independent component revisions under
the same stable client-state identity.

A file/SQLite development witness can itself be rolled back with a full filesystem
snapshot. Whole-snapshot anti-rollback requires a witness outside the restored state
domain.

## Limitations

Password-based local encryption does not protect an already compromised running endpoint.

Profile v5 does not provide hardware-backed storage, forensic secure erasure, key
transparency or complete whole-device anti-rollback by itself. It persists the monotonic
device-lifecycle authority needed for recovery/revocation, while the user-facing recovery
workflow and relay stale-device enforcement remain separate implementation stages.

GhostLink remains pre-alpha and is not production-ready.
