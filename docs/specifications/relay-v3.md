# GhostNode Ratcheted Relay Protocol v3

Status: implemented; user-facing CLI cutover pending.

## API

The v3 relay surface is intentionally separate from static v2:

- `POST /v3/messages` — store one ratcheted ciphertext envelope;
- `GET /v3/messages/{recipient_device_id}` — list non-expired v3 envelopes;
- `DELETE /v3/messages/{recipient_device_id}/{message_id}` — remove one delivered v3 envelope.

There is no automatic translation between `/v2/messages` and `/v3/messages`.

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

These checks do not authenticate the sender. End-to-end authenticity comes from libsignal plus the verified GhostLink contact/session state.

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

## Access control

The current v3 relay inherits the optional shared Bearer access control.

That token is not per-device authentication and does not prove the sender DeviceID. General per-device authentication for message relay remains a documented hardening gap.

## Health

`/health` requires all configured stores to be available:

- static v2 message storage;
- ratcheted v3 message storage;
- pre-key publication/fetch storage.

## Relay visibility

GhostNode observes:

- sender and recipient DeviceIDs;
- message ID;
- creation and expiration times;
- libsignal ciphertext framing type;
- ciphertext size;
- request timing.

GhostNode does not receive plaintext, libsignal session secrets, identity private keys or pre-key private material.

## Malicious relay

A malicious relay can still:

- drop or delay messages;
- reorder envelopes;
- replay stored ciphertext;
- modify external envelope metadata;
- restore older relay database state.

External metadata modification is detected by protocol v3 context-bound decryption. The ratchet transaction rolls back instead of committing the modified message.

Availability and database rollback remain separate problems.
