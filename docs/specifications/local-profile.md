# GhostLink Local Profile v2

## Purpose

A local profile persists the private material required for one GhostLink identity/device and the secret used to unlock that device's encrypted libsignal ratchet vault across client restarts.

Unlike a contact bundle, a local profile contains secrets. It MUST NOT be shared.

## Version 2 secret payload

Profile v2 keeps the existing identity/device material and adds:

- a random 32-byte ratchet-vault master key.

The ratchet master key is generated independently with the operating-system-backed PyNaCl randomness source. It is not derived from the identity signing key, device signing key, device encryption key, password, DeviceID or GhostID.

The master key is stored only inside the authenticated profile ciphertext. It is not written to:

- process arguments;
- environment variables;
- GhostNode;
- logs;
- the ratchet vault file itself.

When the CLI starts the local ratchet engine, the unlocked master key is passed to the child only through the existing framed stdin RPC.

## At-rest protection

Version 2 encrypts the private profile payload with libsodium SecretBox through PyNaCl.

The SecretBox key is derived from the user's password with Argon2id. The outer profile stores:

- version;
- a random Argon2id salt;
- the fixed supported KDF parameters;
- cipher identifier;
- authenticated ciphertext.

GhostLink does not implement a custom cipher or password KDF.

## Validation

When a profile is unlocked, GhostLink reconstructs the identity/device and verifies that:

1. the private identity seed derives the expected GhostID;
2. the private device signing key derives the public signing key in the certificate;
3. the private device encryption key derives the public encryption key in the certificate;
4. the DeviceID matches the device signing public key;
5. the device certificate is signed by the identity key;
6. a v2 ratchet master key decodes to exactly 32 bytes.

Any mismatch rejects the profile.

## Legacy v1 compatibility

Profile v1 remains readable for identity/contact operations.

A v1 profile intentionally decrypts with `ratchet_master_key = None`. Ratcheted CLI commands fail closed and instruct the user to run:

```bash
ghostlink profile-upgrade --profile alice.ghost
```

The upgrade:

1. decrypts and validates the legacy profile;
2. generates a fresh independent 32-byte ratchet master key;
3. serializes profile v2 under the same user password;
4. atomically replaces the encrypted profile file;
5. preserves the GhostID, DeviceID and existing identity/device private keys.

There is no silent migration during `send` or `inbox`.

## Resource limits

Profiles accept only the fixed Argon2id work parameters emitted by the implementation. A modified profile therefore cannot request an arbitrarily expensive KDF invocation.

## Limitations

Password-based local encryption does not protect a running client whose process, password or unlocked keys are compromised.

Profile-v2 encryption does not provide hardware-backed key storage, forensic secure erasure, recovery, rotation or device revocation.

The separate ratchet vault is only as recoverable as its encrypted profile-held master key. Restoring an older profile/vault pair can restore older local state; client-state anti-rollback remains a separate hardening problem.

GhostLink remains pre-alpha and unsuitable for sensitive real-world communications until the documented security gaps and independent review are addressed.
