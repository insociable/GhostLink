# ADR-0002: Authenticated message lifecycle and replay protection

- Status: Accepted
- Date: 2026-09-18

## Context

GhostLink message protocol v1 authenticates and encrypts the message payload between two device encryption keys, but it does not carry an authenticated sender-generated message identifier, creation time, or expiration time.

A captured valid v1 envelope can therefore be submitted to a relay again and accepted as another delivery. The recipient can decrypt it again because the captured ciphertext remains cryptographically valid.

The relay is explicitly outside the trust boundary. It may help with routing, deduplication and expiration, but it must not be trusted to decide whether a message is authentic, fresh, or safe to display.

GhostLink is pre-1.0 and currently experimental. There is no production compatibility requirement that justifies carrying a weak v1 message format indefinitely.

## Decision

Introduce a message protocol v2 before adding conversation history or mobile clients.

### Sender-generated message ID

Every message MUST contain a cryptographically random 128-bit `message_id` generated locally by the sender.

The identifier:

- MUST NOT be derived from plaintext, ciphertext, contact identity, counters or wall-clock time;
- MUST be included inside the encrypted/authenticated payload;
- MUST also be present in the outer relay envelope so a relay can deduplicate without reading plaintext;
- SHOULD use a fixed canonical text representation in the relay JSON.

The implementation should use the operating-system/libsodium cryptographic random source already available to GhostLink.

### Authenticated lifecycle fields

Protocol v2 adds:

- `created_at`: UTC Unix timestamp in whole seconds;
- `expires_at`: UTC Unix timestamp in whole seconds.

The following routing/lifecycle fields MUST exist both in the outer relay envelope and inside the encrypted payload:

- protocol version;
- message ID;
- sender DeviceID;
- recipient DeviceID;
- created timestamp;
- expiration timestamp.

After successful decryption, the recipient MUST require an exact match between the outer fields and the authenticated inner fields.

This allows GhostNode to route and expire ciphertext while preventing a compromised relay from silently changing those values without the recipient detecting the change.

### Time rules

The initial v2 profile uses:

- maximum message lifetime: 7 days;
- permitted future clock skew: 5 minutes;
- permitted expiration clock skew: 5 minutes.

A client MUST reject a decrypted message when:

- `expires_at <= created_at`;
- the declared lifetime exceeds the maximum;
- `created_at` is too far in the future;
- the message is expired beyond the allowed skew;
- authenticated inner lifecycle fields differ from the outer envelope.

A relay MAY reject obviously invalid lifecycle values earlier and SHOULD remove expired envelopes, but recipient-side validation remains authoritative for security.

### Replay cache

A recipient MUST maintain a persistent cache of accepted `message_id` values scoped to the authenticated sender device.

A received message is processed in this order:

1. verify the expected sender public device;
2. authenticate and decrypt the ciphertext;
3. verify outer fields equal authenticated inner fields;
4. validate timestamps and expiration;
5. check the persistent replay cache;
6. atomically record the accepted message ID;
7. expose the plaintext to the user;
8. acknowledge/delete the relay copy.

If the same authenticated message ID has already been accepted for that sender device, the plaintext MUST NOT be displayed again.

Replay-cache entries need to be retained for at least the maximum message lifetime plus allowed clock skew. Messages older than that must already fail expiration validation.

### Relay deduplication

GhostNode SHOULD enforce uniqueness for a message ID within the relevant recipient namespace.

Relay deduplication is defense in depth and resource protection. It is not the security boundary because a malicious or reset relay could forget its deduplication state.

### Protocol migration

The migration is staged through reviewed pull requests: message core, relay/client transport, persistent replay state, then removal of the v1 runtime path.

GhostLink is pre-1.0 and does not commit to protocol-v1 backward compatibility. Once the v2 client cutover is validated, the reference runtime rejects v1 rather than carrying two security models indefinitely.

## Consequences

Advantages:

- exact captured-envelope replay becomes detectable by recipients;
- the relay can purge expired ciphertext without seeing plaintext;
- the relay can deduplicate retries;
- lifecycle metadata cannot be changed undetectably by the relay;
- the model is compatible with a later ratcheting protocol.

Costs and limitations:

- creation/expiration times are metadata visible to the relay;
- clients need persistent replay state;
- clock errors can cause valid messages to be rejected;
- this does not add forward secrecy or post-compromise security;
- this does not prevent traffic analysis;
- rate limiting and abuse prevention are separate concerns.

## Security note

Protocol v2 should be treated as another experimental hardening step, not as a replacement for a reviewed asynchronous messaging protocol such as a Double Ratchet design.

The static PyNaCl `Box` construction remains temporary until GhostLink adopts and reviews a ratcheting session protocol.

## Implementation status

Accepted and implemented in the reference codebase on 2026-09-18.

The protocol-v2 message core authenticates duplicated routing/lifecycle metadata, GhostNode provides v2 relay storage and deduplication, and the CLI uses a persistent SQLite replay cache before displaying plaintext.

The temporary protocol-v1 runtime path has been removed; protocol v2 is canonical.