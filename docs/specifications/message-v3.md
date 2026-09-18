# GhostLink Ratcheted Message Protocol v3

Status: implemented transport path; CLI cutover pending.

## Purpose

Protocol v3 is the explicitly ratcheted GhostLink message format.

It is separate from static protocol v2. A v3 message is never silently converted to v2, and failure to establish or decrypt a ratcheted session never triggers static encryption.

## Outer relay envelope

A v3 envelope contains:

- `version = 3`;
- `message_id`: 128 random bits encoded as 32 lowercase hexadecimal characters;
- sender DeviceID;
- recipient DeviceID;
- `created_at` Unix seconds;
- `expires_at` Unix seconds;
- libsignal ciphertext framing type;
- opaque libsignal ciphertext.

GhostNode can observe these fields and ciphertext size. It does not receive plaintext or ratchet private state.

## Authenticated relay context

Before encryption, GhostLink constructs a canonical binary context containing:

- a fixed domain separator for GhostLink ratcheted message v3;
- protocol version;
- message ID;
- sender DeviceID;
- recipient DeviceID;
- creation timestamp;
- expiration timestamp.

The sender encrypts:

```text
canonical_context || application_plaintext
```

through the pinned official libsignal implementation.

The libsignal ciphertext type is not duplicated in the context. It is cryptographic framing: changing it causes libsignal deserialization/decryption failure.

## Transactional context verification

The recipient reconstructs the expected canonical context from the relay envelope and calls the local `decrypt_context_bound` ratchet RPC.

The ratchet engine:

1. snapshots persistent libsignal state;
2. decrypts the ciphertext;
3. compares the decrypted prefix with the expected context;
4. commits the updated ratchet vault only when the prefix matches;
5. restores the previous ratchet state on mismatch or decrypt failure.

This matters because checking relay metadata only after a normal decrypt would allow a malicious relay to advance a session before the application discovered the mismatch.

## Replay ordering

After context-bound decryption succeeds, the client:

1. validates the message lifecycle against local time;
2. atomically records `(sender_device_id, message_id)` in the persistent replay cache;
3. exposes application plaintext only after the replay ID is accepted.

A replay-cache rollback can still weaken replay suppression and remains a documented local-state rollback limitation.

## Lifecycle

Protocol v3 currently uses the same lifecycle limits as v2:

- default lifetime: 24 hours;
- maximum lifetime: 7 days;
- future clock tolerance: 5 minutes;
- expiration clock tolerance: 5 minutes.

Relay time checks are operational hardening only. The recipient remains the security authority after cryptographic context verification.

## Size limits

The current profile bounds:

- application plaintext to 512 KiB;
- relay ciphertext to 1 MiB;
- local RPC frames to 2 MiB.

These are implementation limits, not cryptographic constants.

## Session bootstrap

A sender must already have a verified ratchet session or create one through the implemented flow:

```text
GhostNode pre-key fetch
  -> VerifiedContact verification
  -> highest-seen publication sequence
  -> libsignal session establishment
```

There is no automatic fallback to static v2.

## Security boundary

Protocol v3 provides the ratcheted message transport needed for forward-secrecy/post-compromise behavior supplied by the pinned libsignal implementation.

It does not solve:

- malicious relay availability attacks;
- traffic analysis;
- relay database rollback;
- key transparency;
- per-device authentication for general message-relay operations;
- endpoint compromise;
- device revocation/recovery;
- independent cryptographic review.

GhostLink remains pre-alpha.
