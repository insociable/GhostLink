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
- response JSON structure;
- message identifiers;
- Base64 ciphertext;
- that the relay echoes the same encrypted envelope that was submitted.

Network failures, HTTP failures, and malformed relay responses are represented by separate client exceptions.

## Security status

The transport does not yet authenticate a GhostNode and the current relay does not authenticate clients. TLS, relay authentication, replay protection, expiration, delivery acknowledgement, and persistent ciphertext storage remain later milestones.

GhostLink remains experimental and is not suitable for sensitive real-world communications.
