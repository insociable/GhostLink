# GhostLink Local Profile v3

## Purpose

A local profile persists the private material required for one GhostLink identity/device
and two independent local keys used for encrypted client state across restarts.

Unlike a Contact Bundle or QR payload, a local profile contains private material and MUST
NOT be shared.

## Version 3 payload

Profile v3 contains two independently random 32-byte keys:

- `ratchet_master_key`: unlocks the encrypted libsignal ratchet/pre-key vault;
- `contact_store_key`: protects the local human-trust contact store.

Both are generated independently with PyNaCl randomness. Neither is derived from the
other, from identity/device keys, from the password, GhostID, or DeviceID.

The ratchet key MUST NOT be reused for the contact store, and the contact-store key MUST
NOT be used by the ratchet engine.

Both values exist only inside the authenticated profile ciphertext. They are not included
in Contact Bundles, QR payloads, GhostNode data, command-line arguments, or environment
variables.

## At-rest protection

Profile v3 uses libsodium SecretBox through PyNaCl. The SecretBox key is derived from the
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
also requires:

- a v2 or v3 ratchet master key, when present, to be exactly 32 bytes;
- a v3 contact-store key to be exactly 32 bytes.

Malformed or inconsistent profiles are rejected.

## v1 and v2 compatibility

Older profiles remain readable for explicit migration:

- v1 contains neither local state key;
- v2 contains the ratchet master key only;
- v3 contains both independent keys.

Missing keys decode as `None`. The explicit command remains:

```bash
ghostlink profile-upgrade --profile alice.ghost
```

The upgrade preserves GhostID, DeviceID, identity/device private material, and any existing
v2 ratchet master key. It generates only the missing random keys, serializes profile v3
under the same password, and atomically replaces the encrypted profile.

There is no silent migration during messaging or trusted-contact operations.

## Contact-store boundary

Profile v3 supplies the independent key required by the contact store defined in ADR-0006.
It does not contain contact records, labels, trust states, or replacement candidates.

This keeps contact trust persistence separate from identity/device and ratchet state while
retaining authenticated local storage.

## Limitations

Password-based local encryption does not protect an already compromised running endpoint.

Profile v3 does not provide hardware-backed storage, forensic secure erasure, recovery,
rotation, device revocation, or client-state anti-rollback. Restoring older local snapshots
can restore older client state.

GhostLink remains pre-alpha and is not production-ready.
