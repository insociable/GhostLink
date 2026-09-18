# Local ratchet-engine RPC specification

Status: experimental implementation

## Purpose

GhostLink's application/orchestration layer is Python while the maintained official libsignal bindings used by the project are Node/TypeScript.

The ratchet engine therefore runs as a local child process owned by the GhostLink client.

It is not a network service.

## Process model

The reference desktop/development architecture is:

```text
GhostLink Python client
        |
        | stdin/stdout
        | framed RPC
        v
ratchet-engine Node process
        |
        v
@signalapp/libsignal-client
        |
        v
encrypted ratchet vault
```

One local GhostLink device owns one writable ratchet-engine process and one writable vault.

The master key is sent only through the child's standard input after process creation.

It is not placed in:

- process arguments;
- environment variables;
- the vault file;
- GhostNode;
- application logs.

The Python client overwrites its temporary mutable master-key copy after the `open` request. The Node RPC layer overwrites its decoded request buffer after opening the vault.

JavaScript/Python runtimes cannot guarantee complete secure-memory erasure, so this is defense in depth rather than a secure-memory claim.

## Framing

Every request and response is:

```text
4-byte unsigned big-endian payload length
UTF-8 JSON payload
```

The maximum frame size is 2 MiB.

Zero-length and oversized frames are fatal protocol errors.

There is no delimiter scanning and no unbounded line-oriented input.

## Request shape

```json
{
  "id": 1,
  "method": "ping",
  "params": {}
}
```

Required fields are exact. Unknown request fields are rejected.

`id` is a non-negative safe integer selected monotonically by the Python client.

## Response shape

Success:

```json
{
  "id": 1,
  "ok": true,
  "result": {}
}
```

Failure:

```json
{
  "id": 1,
  "ok": false,
  "error": {
    "code": "INVALID_REQUEST",
    "message": "..."
  }
}
```

The Python client requires the response ID to match the outstanding request.

Operations on one client are serialized by a local lock; the Node persistent-party layer independently serializes state-mutating ratchet operations.

## Methods

### `ping`

Parameters: empty object.

Returns:

```json
{"rpc_version": 1}
```

### `open`

Parameters:

- canonical local GhostLink DeviceID;
- local vault path;
- 32-byte master key encoded as canonical Base64.

The libsignal address is internally fixed to:

```text
ProtocolAddress(name = DeviceID, deviceId = 1)
```

The engine may create a new encrypted vault if one does not exist or restore the existing vault if it does.

A process may be opened only once.

### `create_prekey_material`

Parameters: empty object.

Generates and atomically persists fresh:

- one-time EC pre-key;
- signed EC pre-key;
- Kyber/ML-KEM pre-key.

Pre-key identifiers are random positive 31-bit integers. Existing identifiers in the local stores are rejected on collision and a new identifier is generated.

The returned value is public libsignal material only.

The Python layer must bind and sign that material with the certified GhostLink device signing key before publication.

### `establish_session`

Parameters:

- verified remote DeviceID;
- public libsignal pre-key material.

The Python `RatchetEngineClient` does not expose an unsafe public-material shortcut: its high-level method first verifies the signed GhostLink ratchet binding against an existing `VerifiedContact`, then passes only the verified material to the engine.

The engine applies libsignal identity trust checks as a second layer.

### `encrypt`

Parameters:

- verified remote DeviceID;
- plaintext bytes encoded as canonical Base64.

Maximum plaintext size: 1 MiB.

Returns:

- libsignal ciphertext message type;
- serialized libsignal ciphertext as canonical Base64.

The Python API accepts a `VerifiedContact`, not a free-form remote address.

### `decrypt`

Parameters:

- verified remote DeviceID;
- supported libsignal message type;
- serialized libsignal ciphertext as canonical Base64.

Returns arbitrary plaintext bytes as canonical Base64.

The Python API accepts a `VerifiedContact`.

A failed decrypt is rolled back transactionally by the persistent ratchet layer and does not commit new vault state.

### `close`

Parameters: empty object.

The engine destroys its explicit vault-key buffer, closes the vault owner, returns a final success response and exits.

## Binary payloads

The RPC does not require UTF-8 application plaintext.

Encryption and decryption operate on arbitrary byte strings.

This allows future higher-level protocols to carry, for example:

- structured messages;
- attachment keys/chunks;
- signed wallet payloads;
- binary application control messages.

Those future formats remain separate protocol layers and must define their own authentication/context requirements.

## Device and identifier validation

RPC DeviceIDs must use the canonical GhostLink `device1:` format.

The ratchet protocol profile additionally enforces:

- libsignal device ID = 1;
- registration ID in `1..16380`;
- pre-key IDs as positive signed 31-bit integers;
- strict canonical Base64;
- strict public key encodings through libsignal.

Unknown fields fail closed.

## Pre-key lifecycle implemented in this milestone

Each newly published bundle uses new random IDs for all three pre-key classes.

Old private signed/Kyber pre-key records are currently retained so delayed/in-flight pre-key messages can still be processed.

One-time EC pre-keys are removed when consumed according to libsignal semantics.

Kyber usage state is persistently recorded.

## Pre-key lifecycle still pending

Before production cutover, GhostLink still needs an explicit policy for:

- desired one-time pre-key stock;
- replenishment thresholds;
- signed-pre-key rotation interval;
- Kyber pre-key rotation interval;
- safe retention window for old private pre-key records;
- garbage collection;
- relay publication replacement semantics;
- anti-rollback/latest-bundle transparency.

The current implementation deliberately avoids aggressive deletion until those semantics are fixed.

## Error handling

Expected request failures return structured errors.

Protocol/state/cryptographic failures do not cause automatic fallback to static GhostLink encryption.

Fatal framing errors terminate the engine process.

The Python owner treats unexpected EOF, pipe failure, malformed responses, response-ID mismatch and unsupported RPC versions as local engine failures.

## Cross-language validation

The repository runs a real Python-to-Node smoke test that:

1. creates verified GhostLink identities/devices for Alice and Bob;
2. starts two independent local Node/libsignal processes;
3. opens two encrypted persistent vaults;
4. verifies that vault master keys are absent from process argv/environment on Linux;
5. exports Bob's real libsignal pre-key material;
6. signs it using Bob's certified GhostLink device key;
7. confirms an invalid GhostLink device signature is rejected before session establishment;
8. verifies the valid binding against Alice's existing `VerifiedContact`;
9. establishes a real PQXDH session;
10. exchanges arbitrary binary plaintext;
11. sends a ratcheted reply;
12. closes both processes;
13. reopens both vaults in new processes;
14. continues the same ratcheted session.

The Node test suite separately exercises raw RPC validation and the same restart behavior.

GhostLink remains pre-alpha and has not undergone an independent cryptographic audit.