# GhostNode Relay Protocol v2

GhostNode v2 transports protocol-v2 ciphertext envelopes without decrypting message content.

## API

The experimental v2 relay surface is:

- `POST /v2/messages` — store one encrypted envelope;
- `GET /v2/messages/{recipient_device_id}` — list non-expired envelopes for one recipient;
- `DELETE /v2/messages/{recipient_device_id}/{message_id}` — remove one delivered envelope.

The existing v1 routes remain available temporarily during migration.

## Envelope validation

GhostNode validates only relay-visible structure:

- protocol version must be `2`;
- message IDs are 32 lowercase hexadecimal characters;
- DeviceIDs use the canonical `device1:` representation;
- timestamps are non-negative integers;
- expiration is after creation;
- declared lifetime does not exceed seven days;
- ciphertext is valid Base64 and decodes to at most 1 MiB;
- unknown JSON fields are rejected.

These checks are operational hardening, not proof that the message is authentic.

## Time policy

The relay rejects envelopes that are already expired beyond the five-minute clock tolerance or whose creation time is more than five minutes in the future.

The recipient remains the security authority. It authenticates the encrypted inner lifecycle fields and performs its own time validation after decryption.

## Idempotency and deduplication

The key is the pair:

`(recipient_device_id, message_id)`

Submitting the exact same envelope again is idempotent and returns the stored envelope.

Reusing the same key for different envelope content returns HTTP 409.

Relay deduplication is defense in depth only. A recipient must still maintain its own persistent replay cache because a malicious or reset relay can forget prior state.

## SQLite storage

When persistent storage is configured, v2 uses a dedicated `messages_v2` table in the existing GhostNode SQLite database.

The primary key is `(recipient_device_id, message_id)`. An index on recipient and expiration supports inbox lookup and expiry cleanup.

Protocol-v1 storage is left untouched during staged migration.

## Access control

V2 uses the same optional shared Bearer relay token as V1.

This token limits who may use the relay. It does not authenticate individual GhostIDs or DeviceIDs and does not replace end-to-end cryptographic authentication.

## Health

The global `/health` endpoint now requires both the v1 and v2 configured stores to be available.

## Security boundary

GhostNode sees routing and lifecycle metadata:

- sender DeviceID;
- recipient DeviceID;
- message ID;
- creation and expiration times;
- ciphertext size.

GhostNode never receives message plaintext or client private keys.

Metadata reduction, per-device relay authentication, ratcheting, forward secrecy, and traffic-analysis resistance remain separate milestones.
