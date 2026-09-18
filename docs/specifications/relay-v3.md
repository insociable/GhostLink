# GhostNode Ratcheted Relay Protocol v3

Status: implemented; current user-facing send/inbox relay path.

## API

The v3 relay surface is intentionally separate from static v2:

- `POST /v3/messages` — store one ratcheted ciphertext envelope;
- `GET /v3/messages/{recipient_device_id}` — list non-expired v3 envelopes;
- `DELETE /v3/messages/{recipient_device_id}/{message_id}` — remove one delivered v3 envelope.

The historical `/v2/messages...` surface is retired; current network message delivery uses `/v3/messages...` only.

## Envelope validation

GhostNode validates relay-visible structure only:

- protocol version is exactly 3;
- message ID is 32 lowercase hexadecimal characters;
- sender/recipient DeviceIDs are canonical;
- timestamps are non-negative;
- expiration follows creation;
- lifetime is at most seven days;
- ciphertext type is a bounded integer;
- ciphertext is canonical Base64 and decodes to at most 1 MiB;
- unknown JSON fields are rejected.

Envelope validation is separate from relay-request authentication. End-to-end message authenticity still comes from libsignal plus the verified GhostLink contact/session state.

## Time policy

GhostNode rejects envelopes outside the relay acceptance window:

- creation more than five minutes in the future;
- expiration more than five minutes in the past.

The receiver independently verifies lifecycle after context-bound libsignal decryption.

## Idempotency

The relay key is:

```text
(recipient_device_id, message_id)
```

Exact retry is idempotent.

Reusing the same key for different v3 envelope content returns HTTP 409.

## SQLite isolation

Persistent v3 envelopes use the dedicated `messages_v3` table.

Static v2 uses `messages_v2`.

This separation is deliberate so migration/cutover cannot silently reinterpret old ciphertext as ratcheted traffic.

## Device-authenticated request access

Every protocol-v3 message operation requires an Ed25519 request proof from the DeviceID authorized for that operation:

- `POST /v3/messages` is signed by the envelope `sender_device_id`;
- `GET /v3/messages/{recipient_device_id}` is signed by that recipient DeviceID;
- `DELETE /v3/messages/{recipient_device_id}/{message_id}` is signed by that recipient DeviceID.

The request carries the public DeviceID signing key. GhostNode derives the self-certifying DeviceID from that key and verifies an operation-specific signature covering method, canonical logical path, authenticated DeviceID, request ID, issuance time and the SHA-256 digest of the canonical JSON body.

Proofs are accepted only within a five-minute clock-skew window. A 128-bit request ID is accepted once per DeviceID; replay state is process-local in in-memory development mode and persisted in a dedicated SQLite table when GhostNode uses SQLite. Replaying the same proof after a persistent GhostNode restart therefore fails closed unless the relay database itself has been rolled back.

Invalid, stale, replayed or ownership-mismatched proofs return a generic HTTP 401 response.

The optional shared Bearer token remains an additional coarse access-control layer when configured. It is not the DeviceID identity mechanism.

The complete wire decision is recorded in [ADR-0004](../adr/0004-device-authenticated-ratchet-relay.md).

Static protocol-v2 message routes are not upgraded by this mechanism. They remain a legacy/diagnostic bearer-only surface and are never used as an automatic fallback from v3.

## Health

`/health` requires all configured stores to be available:

- static v2 message storage;
- ratcheted v3 message storage;
- pre-key publication/fetch storage;
- protocol-v3 request-replay storage.

## Relay visibility

GhostNode observes:

- sender and recipient DeviceIDs;
- message ID;
- creation and expiration times;
- libsignal ciphertext framing type;
- ciphertext size;
- request timing;
- the public signing key corresponding to the authenticated DeviceID;
- per-request authentication timestamp and request ID.

GhostNode does not receive plaintext, libsignal session secrets, identity private keys or pre-key private material.

## Malicious relay

A malicious relay can still:

- drop or delay messages;
- reorder envelopes;
- replay stored ciphertext;
- modify external envelope metadata;
- restore older relay database state.

External metadata modification is detected by protocol v3 context-bound decryption. The ratchet transaction rolls back instead of committing the modified message.

Availability and database rollback remain separate problems. A relay-database rollback can also roll back the persisted request-ID replay cache. Device-key compromise and identity-authorized device revocation/recovery remain separate problems.
