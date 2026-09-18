# Ratchet pre-key identity binding

Status: experimental implementation

## Purpose

GhostLink already has a verified identity hierarchy:

```text
GhostID identity key
        |
        | signs
        v
GhostLink device certificate
        |
        +-- DeviceID
        +-- device Ed25519 signing key
        +-- static device encryption key
```

The libsignal ratchet introduces a second cryptographic identity and a set of public pre-keys.

Those values must not become a parallel identity controlled by GhostNode.

This specification binds the complete public libsignal pre-key material to the already verified GhostLink device.

## Trust chain

The resulting chain is:

```text
verified GhostID
     |
     v
verified DeviceID + device signing key
     |
     | Ed25519 signature
     v
ratchet pre-key binding
     |
     +-- libsignal identity public key
     +-- registration ID
     +-- optional EC one-time pre-key
     +-- signed EC pre-key + signature
     +-- Kyber/ML-KEM pre-key + signature
     +-- bundle ID
     +-- issue/expiration timestamps
     +-- libsignal protocol address
```

GhostNode can store and return the signed public object, but cannot substitute any authenticated field without the GhostLink device signing private key.

## Libsignal address mapping

Every GhostLink DeviceID already identifies exactly one enrolled device.

GhostLink therefore does not require another server-maintained device-number mapping.

The canonical libsignal address is:

```text
ProtocolAddress(
    name = <GhostLink DeviceID>,
    deviceId = 1
)
```

Both sides validate this invariant.

The bootstrap `RatchetParty` remains a test harness, while the signed Python binding enforces that the production-facing address name equals the verified DeviceID.

## Registration identifier profile

GhostLink uses libsignal registration identifiers in the range:

```text
1..16380
```

The ratchet engine validates this range when:

- creating a party;
- restoring persistent state;
- importing public pre-key material.

## Signed binding format

Version 1 authenticates the following fields:

- format version;
- ratchet suite identifier;
- GhostID;
- DeviceID;
- libsignal address name;
- libsignal device ID;
- registration ID;
- random 128-bit bundle ID;
- issued-at timestamp;
- expiration timestamp;
- libsignal identity public key;
- optional one-time EC pre-key ID and public key;
- signed EC pre-key ID, public key and libsignal signature;
- Kyber/ML-KEM pre-key ID, public key and libsignal signature.

The signature is Ed25519 using the GhostLink device signing key already certified by the GhostID.

Canonical signing bytes are domain-separated and length-prefixed; JSON formatting is never signed directly.

## Ratchet suite identifier

Version 1 uses:

```text
libsignal-v4-pqxdh-triple-ratchet
```

Changing suite semantics requires a new GhostLink binding version or explicit compatible profile.

## Production lifecycle versioning

Binding version 1 was the bootstrap format used by the first local integration tests.

Binding version 2 is now the implemented signing/parsing format. The relay-side lifecycle and publication pool are still pending.

The production pre-key lifecycle defined in `ratchet-prekey-lifecycle.md` uses version 2 before GhostNode exposes ratchet pre-key publication/fetch APIs.

Version 2 adds signed lifecycle semantics including:

- a positive 64-bit `publication_sequence` shared by one atomic publication generation;
- a signed `bundle_kind` distinguishing `one_time` from `fallback`.

For a `one_time` binding, the EC one-time pre-key must be present and the Kyber key is treated as one-time lifecycle material.

For a `fallback` binding, the EC one-time pre-key must be absent and the Kyber key is the reusable last-resort key for that generation.

The relay must not be able to change this role without invalidating the GhostLink device signature.

Because ratcheted relay traffic has not yet been cut over, the project does not preserve wire compatibility with bootstrap binding version 1. The production relay path must not silently downgrade to version 1.

## Lifetime

Bindings may live for at most seven days.

The default generation lifetime is 24 hours.

Receivers allow five minutes of clock skew when checking issue and expiration times.

Expiration limits stale-bundle exposure but does not by itself provide rollback transparency.

## Public material transport

The Node ratchet engine exports the actual official libsignal `PreKeyBundle` into strict public wire material and can reconstruct a `PreKeyBundle` from it.

The public material contains:

```text
registration_id
signal_device_id
identity_key
pre_key_id / pre_key
signed_pre_key_id / signed_pre_key / signed_pre_key_signature
kyber_pre_key_id / kyber_pre_key / kyber_pre_key_signature
```

The parser rejects:

- unknown fields;
- unsupported versions;
- non-canonical Base64;
- invalid identifier ranges;
- partial optional one-time pre-keys;
- invalid EC key encodings;
- invalid Kyber public-key encodings;
- noncanonical signal device identifiers.

## First-contact verification

A receiver must already possess a `VerifiedContact` before trusting a ratchet binding.

Verification is:

1. compare GhostID with the verified contact;
2. compare DeviceID with the verified contact;
3. enforce `signal_address_name == DeviceID`;
4. enforce `signal_device_id == 1`;
5. validate bundle timestamps;
6. verify the device Ed25519 signature;
7. only then hand the public material to libsignal.

A relay-supplied GhostID or signing key is never accepted as authority for this step.

## Subsequent identity replacement

After libsignal has stored a remote identity key for a protocol address, the identity store fails closed if the same address presents a different libsignal identity key.

This remains true even if a new pre-key bundle otherwise parses correctly.

Legitimate identity reset/rotation therefore requires a future explicit re-verification/recovery workflow. GhostLink must not silently overwrite a pinned libsignal identity.

## Threat properties

### Relay substitutes a libsignal identity

Rejected: changing the identity key invalidates the GhostLink device signature.

### Relay substitutes an EC or Kyber pre-key

Rejected: all public pre-key fields are authenticated by the GhostLink device signature.

### Relay changes DeviceID/address mapping

Rejected: the signed mapping and verified contact must agree.

### Relay invents a new device signing key

Rejected by the existing GhostID -> device-certificate verification.

### Relay replays an older still-valid signed bundle

This may cause denial of service, especially if a one-time pre-key has already been consumed.

The signature alone cannot prove that a bundle is the newest published bundle.

Mitigations currently are:

- short signed lifetime;
- libsignal one-time-pre-key consumption semantics;
- local identity pinning.

Strong anti-rollback publication requires an additional mechanism such as a monotonic signed sequence with trusted latest-state knowledge, key transparency, or an append-only transparency service. That is future work.

### Device signing key is compromised

An attacker holding the GhostLink device signing private key can authenticate malicious ratchet bindings for that device.

This is a device-compromise/revocation problem, not a relay-substitution problem.

## Validation

Python tests cover:

- signed binding round-trip;
- no private GhostLink keys exported;
- identity-key tampering;
- pre-key tampering;
- wrong verified contact;
- expired/future bundles;
- deterministic DeviceID address binding;
- partial optional pre-key rejection;
- unknown wire fields;
- signing with the wrong local device;
- identity replacement changing the authenticated bytes.

Node/libsignal tests cover:

- official `PreKeyBundle` public export/import;
- PQXDH session establishment from reconstructed public material;
- exhausted one-time EC pre-key representation;
- malformed/unknown wire material;
- rejection of a changed libsignal identity under an already pinned protocol address.

GhostLink remains pre-alpha and has not undergone an independent cryptographic audit.