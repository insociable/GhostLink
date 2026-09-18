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

### `prepare_prekey_generation`

Parameters:

- one-time bundle count in `1..256`;
- issuance timestamp;
- binding lifetime up to seven days.

The engine creates the complete private generation and commits it atomically to the encrypted vault as `lifecycle.pending`.

The result contains only public libsignal material plus publication sequence/timestamps.

### `get_pending_prekey_generation`

Parameters: empty object.

Returns null when no pending generation exists.

Otherwise the engine reconstructs the pending public bundles from persisted libsignal records and returns the exact staged public payload when one already exists.

This permits recovery after a crash both before and after publication staging.

### `stage_prekey_publication`

Parameters:

- pending publication sequence;
- canonical signed publication JSON, maximum 1 MiB.

The exact payload is persisted inside the encrypted vault before any network operation.

An exact retry is accepted. A different payload for an already staged pending sequence fails closed.

### `commit_prekey_publication`

Parameters:

- acknowledged publication sequence;
- local acknowledgement timestamp.

This operation is called only after the application has validated a successful relay publication acknowledgement.

The engine atomically:

- requires a matching staged pending generation;
- promotes that generation to `active`;
- records its publication timestamp;
- moves the previous active generation to `retired` with the same transition timestamp;
- leaves retired private material intact for the delayed-message retention policy.

Repeating the acknowledgement for an already active sequence is idempotent. This permits recovery when the local commit succeeded but the RPC response was lost.

An unstaged pending generation, wrong sequence, invalid timestamp or exhausted retired-generation bound fails closed.

### `establish_session`

Parameters:

- verified remote DeviceID;
- verified remote publication sequence;
- public libsignal pre-key material.

The Python `RatchetEngineClient` does not expose an unsafe public-material shortcut: its high-level method first verifies the signed GhostLink ratchet binding against an existing `VerifiedContact`, then passes only the verified material to the engine.

The engine persists the highest publication sequence observed for each remote DeviceID inside the encrypted ratchet vault. Sequence observation and libsignal session establishment occur in one durable transaction: a lower sequence fails closed before session state changes, the same sequence is idempotent, and a higher sequence advances continuity only if session establishment succeeds.

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

The engine now implements:

- bounded pooled generation preparation;
- one signed EC pre-key shared by a generation;
- one-time EC + one-time Kyber pairs;
- a reusable Kyber last-resort fallback;
- encrypted lifecycle pending state;
- recovery of pending public material after restart;
- Python DeviceID signing of binding-v2 publication members;
- exact signed publication staging before network use;
- atomic, idempotent publication acknowledgement commit from pending to active/retired lifecycle state;
- encrypted per-DeviceID highest-seen remote publication sequence persistence before session establishment.

The detailed formats and lifecycle are specified in:

- `ratchet-prekey-lifecycle.md`;
- `ratchet-prekey-publication.md`.

## Pre-key lifecycle still pending

Before relay cutover GhostLink still needs:

- sender HTTP fetch -> VerifiedContact verification -> session establishment orchestration;
- replenishment threshold execution;
- seven-day rotation execution;
- 15-day retired-key garbage collection.

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