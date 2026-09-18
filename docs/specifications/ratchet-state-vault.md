# Ratchet state vault specification

Status: experimental implementation

## Purpose

The ratchet state vault persists all client-side libsignal state required to resume a session after restart without exposing long-lived private material in plaintext on disk.

GhostNode never receives or stores this vault.

## Cryptographic format

Version 1 uses:

- AES-256-GCM;
- a 256-bit master key supplied by the caller;
- a fresh random 96-bit nonce for every save;
- a 128-bit authentication tag;
- fixed authenticated additional data:
  `ghostlink-ratchet-state-v1`.

The master key is not stored in the vault.

The serialized outer envelope contains only:

```text
version
cipher
nonce
ciphertext
tag
```

All private libsignal state is inside the authenticated ciphertext.

## Persisted state

The encrypted payload contains:

- vault owner name and libsignal device identifier;
- local libsignal identity private key;
- local registration identifier;
- trusted remote identity keys;
- serialized ratchet sessions;
- one-time EC pre-keys;
- signed EC pre-keys;
- Kyber/ML-KEM pre-keys;
- consumed Kyber pre-key identifiers;
- base-key reuse tracking required by libsignal;
- pre-key lifecycle metadata: monotonic publication sequence, pending/active/retired generations, generation key ownership and the exact staged public publication payload needed for crash-safe retry;
- highest-seen remote publication sequence per canonical DeviceID.

The encrypted store snapshot is now version 3. Version-1 and version-2 store snapshots are accepted as migration inputs and are normalized to version 3. Version 1 receives an empty lifecycle state and both legacy versions receive an empty remote-publication continuity map. The outer AES-GCM vault envelope remains version 1, so existing encrypted vaults can be opened and migrated without changing their key or AAD.

The lifecycle parser bounds generation history, one-time key lists and staged public payload size. It rejects duplicate generation sequences, duplicate one-time key identifiers and a last-resort Kyber identifier reused as a one-time Kyber identifier.

The vault payload and every store use explicit format versions and strict field validation.

## Owner binding

A vault is bound to a specific local owner:

```text
(name, deviceId)
```

Opening valid ciphertext under a different requested owner fails closed.

The owner binding is inside the AES-GCM authenticated ciphertext.

## Atomic persistence

Each successful state-changing operation follows this sequence:

```text
snapshot current in-memory stores
        |
        v
perform libsignal operation
        |
        +-- failure --> restore snapshot, disk unchanged
        |
        v
serialize complete state
        |
        v
AES-256-GCM encrypt with fresh nonce
        |
        v
create temporary file mode 0600
        |
        v
write + fsync temporary file
        |
        v
atomic rename over live vault
        |
        v
fsync parent directory (POSIX)
```

The implementation does not persist individual stores independently.

This is important because one libsignal operation can modify several stores, for example:

- create/update a session;
- consume a one-time EC pre-key;
- mark a Kyber pre-key as used;
- update identity trust state.

Those changes must become durable together.

## In-process concurrency

Operations on one `PersistentRatchetParty` instance are serialized.

Concurrent calls such as three simultaneous sends therefore consume one ratchet state in sequence rather than racing the same chain key.

## Process ownership

Version 1 assumes one ratchet-engine process owns a vault at a time.

Two independent processes must not open the same writable vault concurrently.

The future Python-to-engine integration must enforce a single owner process for each local device state. Cross-process locking is intentionally deferred until the final engine lifecycle architecture is fixed.

## Filesystem protections

On POSIX systems:

- the vault directory is created with private permissions where possible;
- temporary files are created as `0600`;
- the final vault file is forced to `0600`;
- temporary files are removed after failed saves.

Windows ACL protection is not implemented by this module and must be provided by the application/installer or OS secret-storage integration.

## Size limits

Version 1 applies defensive limits to both encrypted and decrypted state.

The parser also limits the number of serialized store entries.

These limits are denial-of-service protections, not quota policy.

## Unlock failures

The following fail closed:

- wrong master key;
- modified ciphertext;
- modified nonce or authentication tag;
- unsupported version/cipher;
- malformed JSON;
- non-canonical Base64;
- unexpected fields;
- invalid serialized libsignal records;
- owner mismatch.

No automatic vault reset or identity regeneration is permitted.

## Key lifecycle

The vault accepts a raw 32-byte master key.

Deriving or retrieving that key is intentionally outside this module.

The production client must eventually source the master key from one of:

1. an OS keychain / hardware-backed secret where available; or
2. a password-derived key using a separately specified memory-hard KDF.

The vault must never derive a weak key by padding/truncating a password.

The in-memory master-key buffer is overwritten when the vault is explicitly closed. JavaScript/runtime copies cannot be guaranteed to be fully erased, so this is defense in depth rather than a secure-memory guarantee.

## Security properties and non-properties

The vault protects state at rest against an attacker who obtains only the encrypted file but not the master key.

It does not protect against:

- malware or an attacker controlling the running client;
- memory extraction while the vault is unlocked;
- compromise of the master key;
- malicious code executing inside the ratchet-engine process;
- filesystem rollback to an older valid vault snapshot.

Rollback protection requires an external monotonic state or trusted hardware and is a separate design problem.

## Validation

Integration tests cover:

- ciphertext-only state at rest;
- private POSIX permissions;
- wrong-key rejection;
- ciphertext tamper rejection;
- owner mismatch rejection;
- full close/reopen session continuity;
- persistence of EC pre-key consumption;
- persistence of Kyber pre-key usage;
- persistence of identity trust;
- byte-for-byte unchanged vault after failed decrypt;
- serialized concurrent sends;
- version-1 and version-2 store-state migration to version 3;
- encrypted-at-rest lifecycle metadata, staged public publication payload and remote publication continuity state;
- lifecycle role/sequence/identifier invariant rejection;
- durable highest-seen remote sequence persistence and rollback rejection.

GhostLink remains pre-alpha and has not undergone an independent cryptographic audit.