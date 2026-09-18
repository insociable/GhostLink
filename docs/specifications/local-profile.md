# GhostLink Local Profile v1

## Purpose

A local profile persists the private material required for a GhostLink identity and one enrolled device across client restarts.

Unlike a contact bundle, a local profile contains secrets. It MUST NOT be shared.

## At-rest protection

Version 1 encrypts the private profile payload with libsodium's SecretBox through PyNaCl.

The SecretBox key is derived from the user's password with Argon2id. The profile stores:

- a random Argon2id salt;
- the exact KDF parameters used by profile v1;
- the authenticated ciphertext.

The plaintext payload contains the identity signing seed, device signing seed, device encryption private key, and the signed public device certificate.

GhostLink does not implement a custom cipher or password KDF.

## Validation

When a profile is unlocked, GhostLink reconstructs the identity and device and verifies that:

1. the private identity seed derives the expected GhostID;
2. the private device signing key derives the public signing key in the certificate;
3. the private device encryption key derives the public encryption key in the certificate;
4. the DeviceID matches the device signing public key;
5. the device certificate is signed by the identity key.

Any mismatch rejects the profile.

## Resource limits

Profile v1 accepts only its own fixed Argon2id work parameters when decrypting. An attacker therefore cannot modify a profile file to request an arbitrarily large KDF memory or CPU cost.

## Limitations

Password-based local encryption does not protect a running client whose process, password, or unlocked keys are compromised.

The current profile format is experimental. Secure OS keychain integration, hardware-backed keys, recovery, rotation, revocation, and migration policies remain future work.

GhostLink remains unsuitable for sensitive real-world communications until the protocol and clients have been independently reviewed.
