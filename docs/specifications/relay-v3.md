# GhostNode Ratcheted Relay Protocol v3

Status: implemented; current user-facing send/inbox relay path.

## API

The v3 relay surface is intentionally separate from static v2:

- `POST /v3/messages` — store one ratcheted ciphertext envelope;
- `GET /v3/messages/{recipient_device_id}` — list non-expired v3 envelopes;
- `DELETE /v3/messages/{recipient_device_id}/{message_id}` — remove one delivered v3 envelope;
- `PUT /v3/device-lifecycle/{ghost_id}` — publish identity-signed monotonic device lifecycle state;
- `GET /v3/device-lifecycle/{ghost_id}` — read the relay's highest accepted lifecycle state.

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

The historical static-v2 message runtime is retired. No current route can reinterpret old static ciphertext as ratcheted traffic.

## Device-authenticated request access

Every protocol-v3 message operation requires an Ed25519 request proof from the DeviceID authorized for that operation:

- `POST /v3/messages` is signed by the envelope `sender_device_id`;
- `GET /v3/messages/{recipient_device_id}` is signed by that recipient DeviceID;
- `DELETE /v3/messages/{recipient_device_id}/{message_id}` is signed by that recipient DeviceID.

The request carries the public DeviceID signing key. GhostNode derives the self-certifying DeviceID from that key and verifies an operation-specific signature covering method, canonical logical path, authenticated DeviceID, request ID, issuance time and the SHA-256 digest of the canonical JSON body.

Proofs are accepted only within a five-minute clock-skew window. A 128-bit request ID is accepted once per DeviceID; replay state is process-local in in-memory development mode and persisted in a dedicated SQLite table when GhostNode uses SQLite. Replaying the same proof after a persistent GhostNode restart therefore fails closed unless the relay database itself has been rolled back.

Invalid, stale, replayed or ownership-mismatched proofs return a generic HTTP 401 response.

The optional shared Bearer token remains an additional coarse access-control layer when configured. It is not the DeviceID identity mechanism.

## Device lifecycle enforcement

GhostNode can record the highest identity-signed lifecycle statement accepted for a GhostID. A newer epoch names the only active DeviceID for the current single-device architecture and makes previously observed DeviceIDs for that GhostID stale.

Lifecycle publication is authorized by the GhostID identity signature and, when configured, the shared Bearer gate. It does not rely on the superseded device signing key.

Once a relay has observed a newer lifecycle epoch, known superseded DeviceIDs are rejected on:

- protocol-v3 message submission;
- protocol-v3 inbox listing and deletion;
- pre-key publication and owner status;
- pre-key fetch when either the authenticated requester or target DeviceID is known to be superseded.

Unknown DeviceIDs remain accepted during migration. Because the current lifecycle statement names only the active device, a relay that first learns an identity after rotation cannot retroactively map a never-registered older DeviceID to that GhostID.

The current CLI therefore publishes its signed lifecycle before `prekey-sync`, `send` and `inbox`. `device-recover` first ensures the current device is registered, prepares the replacement locally, publishes the newer lifecycle to GhostNode, and only then promotes the replacement profile. If remote publication fails or is ambiguous, the old profile remains active and the pending recovery can be resumed.

For persisted human-verified contacts, `send` and `inbox` query the configured relay for the contact GhostID before using ratchet state. A cryptographically valid newer epoch for the already-pinned identity is applied through the contact store's monotonic lifecycle rules. When the active DeviceID changes, the client durably invalidates the superseded libsignal session, cached remote identity and highest-seen remote pre-key sequence before persisting the replacement contact. Lower epochs and same-epoch divergence continue to fail closed. A lifecycle lookup returning 404 keeps the current verified contact for migration compatibility; this cannot discover a rotation that the configured relay has never learned.

Persistent lifecycle rows participate in the shared relay-state rollback checkpoint. Empty lifecycle tables are omitted from the canonical checkpoint payload so an already-enrolled pre-lifecycle database can be upgraded without invalidating its existing witnessed digest; once lifecycle rows exist, rolling them back while the witness remains newer fails closed.

The complete wire decision is recorded in [ADR-0004](../adr/0004-device-authenticated-ratchet-relay.md).

Historical static protocol-v2 message routes are retired and are not an alternate path around lifecycle enforcement.

## Health

`/health` requires all configured stores to be available:

- ratcheted v3 message storage;
- pre-key publication/fetch storage;
- protocol-v3 request-replay storage;
- device-lifecycle registry storage;
- the shared relay-state rollback coordinator when persistent SQLite is configured.

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

Availability remains a separate problem. Persistent relay state, including lifecycle rows and the request-ID replay cache, is covered by the shared monotonic witness while that witness remains newer than the protected database. A whole-volume or VM snapshot that rolls the database and reference witness back together remains outside that protection claim.
