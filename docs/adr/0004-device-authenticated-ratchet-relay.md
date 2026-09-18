# ADR-0004: Device-authenticated ratcheted relay requests

- Status: Accepted
- Date: 2026-09-18

## Context

GhostLink's current user-facing message transport is ratcheted protocol v3.

End-to-end authenticity is provided by the verified GhostLink contact state plus the pinned official libsignal implementation, but GhostNode's `/v3/messages` HTTP operations currently inherit only the optional shared Bearer access token.

That leaves three relay-layer problems:

- any holder of the shared token can submit an envelope claiming another sender DeviceID;
- any holder of the shared token can list another recipient DeviceID's pending envelopes;
- any holder of the shared token can delete another recipient DeviceID's pending envelopes.

The pre-key publication/fetch/status protocols already prove control of self-certifying DeviceID signing keys for their own operations. Message-relay authentication should use the same identity primitive without turning GhostNode into a central identity authority.

## Decision

Protocol-v3 message-relay requests MUST carry an operation-specific Ed25519 proof from the GhostLink DeviceID that is authorized to perform the operation.

The relay never receives a client private key.

The shared Bearer token, when configured, remains an additional coarse access-control layer. It is not the device identity mechanism and is not sufficient by itself for protocol-v3 message operations.

## Authorized device per operation

The authenticated DeviceID is bound to the operation:

- `POST /v3/messages`: the authenticated device MUST equal `sender_device_id`;
- `GET /v3/messages/{recipient_device_id}`: the authenticated device MUST equal `recipient_device_id`;
- `DELETE /v3/messages/{recipient_device_id}/{message_id}`: the authenticated device MUST equal `recipient_device_id`.

This prevents a valid device proof from being replayed to act on another device's mailbox.

## Key discovery and enrollment

No GhostNode-side identity enrollment is required for request authentication.

Each request carries:

- the canonical DeviceID;
- the canonical Base64 Ed25519 signing public key.

GhostNode derives the DeviceID from the supplied public key and requires it to match the claimed DeviceID.

This proves control of the self-certifying DeviceID without storing private material or making GhostNode authoritative for GhostID ownership.

The identity-signed GhostLink device certificate remains a peer/contact trust mechanism. It is not required by GhostNode to verify request ownership of a self-certifying DeviceID.

## Request proof format

Version 1 uses these headers:

```text
X-GhostLink-Device-ID
X-GhostLink-Signing-Key
X-GhostLink-Request-ID
X-GhostLink-Issued-At
X-GhostLink-Signature
```

The request ID is 128 random bits encoded as lowercase hexadecimal.

The signing key and signature use canonical padded Base64.

`issued_at` is an integer Unix timestamp in seconds.

## Canonical signed request

The Ed25519 signature covers:

```text
domain = "ghostlink-relay-request-v1\0"

canonical JSON:
{
  "version": 1,
  "method": <uppercase HTTP method>,
  "path": <canonical logical API path>,
  "device_id": <canonical DeviceID>,
  "request_id": <128-bit lowercase hex>,
  "issued_at": <Unix seconds>,
  "body_sha256": <lowercase hex SHA-256 of canonical body bytes>
}
```

JSON keys are sorted and serialized without insignificant whitespace.

For requests with a JSON body, the body is canonical JSON with sorted keys and compact separators before hashing.

For requests without a body, the body bytes are empty.

The signature therefore binds the proof to protocol version/domain, method, logical route, authenticated DeviceID, one request nonce, freshness timestamp and exact canonical body semantics.

The server reconstructs the canonical logical path from validated route parameters rather than signing raw percent-encoding. Query parameters are not part of the v1 authenticated message-relay surface and MUST NOT be introduced without a protocol revision.

## Freshness

GhostNode accepts a request proof only when `issued_at` is within plus or minus five minutes of its current Unix time.

This bounds the useful lifetime of a captured proof.

Clock synchronization is therefore an operational dependency.

## Replay prevention

Freshness alone does not prevent replay inside the accepted window.

GhostNode maintains a replay cache keyed by:

```text
(device_id, request_id)
```

An authenticated request ID may be accepted only once.

When GhostNode uses SQLite storage, accepted request IDs are persisted in a dedicated table in the relay database and are inserted under a uniqueness constraint.

Development/in-memory mode uses a process-local synchronized replay cache.

Entries older than the freshness retention window may be garbage-collected.

A replay is rejected with the same generic authentication error used for other proof failures.

## Failure and retry behavior

Clients generate a fresh request ID for each HTTP attempt.

A transport failure therefore does not require reusing an authentication nonce.

Protocol-v3 message submission remains message-idempotent at the envelope layer: a retry with a fresh authenticated request ID and the identical message envelope is accepted according to the existing `(recipient_device_id, message_id)` idempotency rule.

## Error policy

Invalid, stale, replayed, mismatched or incorrectly signed request proofs return a generic authentication failure.

GhostNode MUST NOT reveal whether a proof failed because of:

- DeviceID/public-key mismatch;
- wrong authorized device;
- stale/future timestamp;
- duplicate request ID;
- invalid signature.

Normal post-authentication resource errors, such as a missing message during deletion, may retain their existing HTTP semantics.

## Multi-device behavior

Every GhostLink device has its own signing key and therefore its own self-certifying DeviceID.

Each device authenticates independently.

One device cannot list or delete another device's mailbox merely because both devices belong to the same GhostID.

Cross-device mailbox delegation would require a separate explicit protocol and is not implied by identity membership.

## Key rotation

The DeviceID is derived from the device signing public key.

Rotating the signing key therefore creates a new DeviceID rather than silently changing the key behind an existing DeviceID.

The new device must be distributed and verified through the normal GhostLink device/contact trust flow.

## Revocation

Request authentication proves current control of a DeviceID. It does not by itself tell GhostNode that an identity owner has revoked a previously valid device.

Complete identity-authorized device revocation/recovery remains a separate protocol gap.

Until that design exists, compromise of a device signing private key allows an attacker controlling that key to authenticate as that DeviceID.

This limitation MUST remain documented in the threat model and MUST NOT be described as solved by this ADR.

## Legacy protocol v2

At the time of this ADR, the static `/v2/messages` surface was retained as a separate legacy path and was deliberately not upgraded here.

That historical decision has since been superseded by ADR-0007: the static-v2 message relay is removed from the reference runtime. The `/v2/prekeys/...` ratchet bootstrap API remains current.

## Metadata consequences

Device authentication necessarily exposes to GhostNode the public signing key corresponding to the already-visible DeviceID and a per-request timestamp/request ID.

GhostNode already observes message-routing DeviceIDs and request timing.

The new proof improves authorization but does not provide traffic-analysis resistance or hide sender/recipient relationships.

## Rate limiting and abuse

Cryptographic authentication answers "which DeviceID authorized this request"; it does not establish that the requester is a human, non-Sybil or non-abusive actor.

Rate limiting, quotas, Sybil-resistant admission and abuse controls remain separate work.

## TLS

Request signatures do not replace TLS.

A passive observer still sees transport metadata, and active network attackers can still deny service.

Public GhostNode deployment remains blocked on reviewed TLS ingress/hardening in addition to this authentication work.

## Validation gates

The implementation must demonstrate:

1. valid sender-authenticated protocol-v3 submission;
2. valid recipient-authenticated list and delete;
3. sender/public-key mismatch rejection;
4. recipient ownership mismatch rejection;
5. signature tamper rejection;
6. method tamper rejection;
7. path tamper rejection;
8. body tamper rejection;
9. stale and future proof rejection;
10. request-ID replay rejection;
11. persistent SQLite replay rejection across app restart;
12. optional Bearer control still composes with device authentication;
13. real CLI ratcheted send/inbox continues to pass;
14. no protocol-v2 fallback is introduced.

## Consequences

Advantages:

- protocol-v3 relay operations are authorized by the same self-certifying DeviceID primitive used elsewhere in GhostLink;
- no client private key is stored on GhostNode;
- a shared relay token no longer grants access to arbitrary v3 device mailboxes;
- signed requests are bound to method, path, body and freshness;
- captured proofs cannot be freely replayed within the validity window.

Costs and limitations:

- clients and GhostNode need synchronized clocks within the documented tolerance;
- the relay stores short-lived request replay identifiers;
- the request proof adds public metadata and signature-verification cost;
- complete device revocation/recovery is still unsolved;
- relay database rollback can also roll back the persisted request-replay cache;
- TLS, anti-abuse, key transparency and independent review remain required.
