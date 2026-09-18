# M3 GhostNode client transport — Protocol v2

The M3 client transport connects a local GhostLink client to a GhostNode relay using the canonical protocol-v2 envelope.

## Boundary

The transport layer receives a `GhostMessage` that has already been encrypted locally. It never receives the plaintext used to create that message and does not perform cryptographic message construction itself.

The relay exchange is:

1. construct and encrypt the authenticated protocol-v2 message locally;
2. Base64-encode ciphertext for JSON transport;
3. submit the envelope to `POST /v2/messages`;
4. retrieve encrypted envelopes with `GET /v2/messages/{device_id}`;
5. authenticate/decrypt locally with the verified sender public device;
6. validate authenticated lifecycle metadata;
7. record the message ID in persistent replay state before display;
8. delete the relay copy after successful processing unless development `--keep` is enabled.

## Client API

`ghostlink.client.GhostNodeClient` exposes:

- `health()`;
- `send(message)`;
- `receive(recipient_device_id)`;
- `delete(recipient_device_id, message_id)`.

Version-specific V1 client methods have been removed.

The transport intentionally uses Python's standard HTTP stack so it does not add another runtime HTTP dependency.

## Response validation

The client validates:

- an absolute HTTP(S) base URL without embedded credentials;
- expected HTTP status codes;
- exact protocol-v2 response fields;
- protocol version `2`;
- canonical 128-bit lowercase hexadecimal message IDs;
- canonical `device1:` identifiers;
- non-negative integer lifecycle timestamps;
- valid Base64 ciphertext;
- a maximum decoded ciphertext size of 1 MiB;
- exact equality between a submitted encrypted envelope and the relay response.

Cryptographic lifecycle validation is performed by the message layer after authenticated decryption, not by trusting the relay response.

## Security status

The optional shared Bearer token is coarse relay access control, not per-device identity authentication.

Persistent recipient-side replay protection is implemented separately from relay deduplication. GhostNode remains outside the end-to-end trust boundary.

Trusted TLS, per-device relay authentication, ratcheting, forward secrecy, traffic-analysis resistance, and independent cryptographic review remain future hardening work.

GhostLink remains experimental and is not suitable for sensitive real-world communications yet.