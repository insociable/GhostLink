# M3 GhostNode client transport

The M3 client transport connects a local GhostLink client to a GhostNode relay.

## Boundary

The transport layer only receives a `GhostMessage` that has already been encrypted locally. It never receives the plaintext used to create that message and does not perform encryption itself.

The relay exchange is:

1. encrypt locally with the sender private device key and recipient public device key;
2. Base64-encode the ciphertext for JSON transport;
3. submit the encrypted envelope to `POST /v1/messages`;
4. retrieve encrypted envelopes using `GET /v1/messages/{device_id}`;
5. decrypt locally after the sender public device has been verified;
6. delete the relay copy only after successful local processing.

## Implementation

`ghostlink.client.GhostNodeClient` intentionally uses Python's standard HTTP stack for M3 so the client transport does not introduce another runtime dependency.

The client validates:

- the GhostNode base URL;
- expected HTTP status codes;
- exact protocol-v1 response fields;
- protocol version `1`;
- canonical `device1:` identifiers;
- Base64 ciphertext;
- a maximum decoded ciphertext size of 1 MiB;
- that the relay echoes the same encrypted envelope that was submitted.

GhostNode applies the matching validation to submitted envelopes: unknown fields, unsupported versions, malformed DeviceIDs, invalid Base64, empty ciphertext and ciphertext above 1 MiB are rejected.

Network failures, HTTP failures, and malformed relay responses are represented by separate client exceptions.

## Security status

The client can send an optional shared Bearer access token to GhostNode. This provides coarse relay access control, not per-device identity authentication. The client still does not authenticate the GhostNode itself without trusted TLS. Per-device relay authentication, replay protection, expiration and explicit delivery acknowledgement remain later milestones.

GhostLink remains experimental and is not suitable for sensitive real-world communications.
