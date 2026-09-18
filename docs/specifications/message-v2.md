# GhostLink Message Protocol v2

Protocol v2 adds authenticated lifecycle metadata and a sender-generated message identifier to the existing device-to-device encrypted message primitive.

## Outer relay envelope

A v2 relay envelope contains:

- `version = 2`;
- `message_id`: 128 random bits encoded as 32 lowercase hexadecimal characters;
- sender DeviceID;
- recipient DeviceID;
- `created_at`: UTC Unix seconds;
- `expires_at`: UTC Unix seconds;
- ciphertext.

The outer fields are routing metadata and are visible to a relay.

## Authenticated encrypted payload

The encrypted payload contains the same version, message ID, sender DeviceID, recipient DeviceID, creation time, expiration time, and the plaintext.

After authenticated decryption, the recipient compares every duplicated field with the outer envelope. A mismatch rejects the message.

This prevents an untrusted relay from silently changing message identity or lifecycle metadata.

## Message identifiers

Message IDs are generated with Python's cryptographically secure `secrets` module as 16 random bytes and encoded using lowercase hexadecimal.

They are not derived from timestamps, plaintext, ciphertext, identities, counters, or relay state.

## Lifecycle rules

The initial profile defines:

- default lifetime: 24 hours;
- maximum lifetime: 7 days;
- future-clock tolerance: 5 minutes;
- expiration-clock tolerance: 5 minutes.

Expiration is enforced by the recipient after successful authenticated decryption and metadata comparison.

The relay may additionally reject or purge expired ciphertext, but relay time is never the security authority.

## Cryptographic construction

The current experimental v2 core continues to use PyNaCl `Box`, which provides authenticated public-key encryption based on libsodium primitives.

GhostLink does not implement a custom cipher, MAC, nonce generator, or key agreement function.

Protocol v2 improves lifecycle authentication and replay-defense foundations. It does **not** provide forward secrecy or post-compromise security. Ratcheted message protocol v3 is now implemented separately using the pinned official libsignal integration.

## Runtime status

Protocol v2 is retained only as historical/local codec code. Shared lifecycle policy constants now live in a protocol-neutral module, so the current v3 runtime no longer imports the v2 codec.

The reference GhostNode no longer exposes `/v2/messages...`, `GhostNodeClient` no longer provides static-v2 send/receive/delete methods, and the CLI no longer exposes `node-smoke`.

Current network messaging is protocol v3 only. The `/v2/prekeys/...` namespace remains active because it is the current ratchet pre-key bootstrap API, not the retired static message relay.