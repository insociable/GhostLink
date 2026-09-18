# GhostLink Identity Fingerprint

## Status

Current format: **Fingerprint v2**.

The earlier Fingerprint v1 display grouped the existing GhostID payload. It remains
recognizable for legacy diagnostics, but it is not the format used by the human trust flow
defined by ADR-0006.

## Purpose

Fingerprint v2 is a deterministic human-comparison representation of the canonical
Ed25519 identity public key.

It is a display/verification format, not a new identity identifier and not a replacement
for GhostID.

## Canonical input

The identity public key MUST be exactly the 32 raw bytes of the Ed25519 verification key
used to derive the contact's GhostID.

The fingerprint digest input is exactly:

```text
ASCII("ghostlink-contact-fingerprint-v2") || 0x00 ||
ASCII("ed25519") || 0x00 ||
identity_public_key[32]
```

Fingerprint v2 digest is:

```text
SHA-256(input)
```

This uses the existing SHA-256 primitive with a dedicated GhostLink domain separator.
No digest bits are truncated.

## Text encoding

The 32-byte digest is Base32 encoded using the RFC 4648 alphabet, with padding removed,
uppercased, and grouped into blocks of four characters.

The displayed form is prefixed with `GLF2:`.

Shape:

```text
GLF2:ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567-ABCD-EFGH-IJKL-MNOP-QRST
```

The payload contains 52 Base32 characters representing the complete 256-bit digest.

Parsers MUST reject:

- missing or incorrect `GLF2:` prefix;
- lowercase or non-Base32 payload characters;
- the wrong number of groups or characters;
- unsupported fingerprint versions.

## Verification procedure

1. Import or scan a Contact Bundle and validate it cryptographically.
2. Derive Fingerprint v2 from the validated bundle's canonical identity public key.
3. Compare the complete fingerprint through an authenticated out-of-band interaction.
4. Only an explicit successful user confirmation may change local trust state from
   `imported` to `verified`, or approve a `changed` candidate.

Examples of useful out-of-band interactions include in-person comparison, a call where the
other person is already known, or scanning a QR directly from that person's device.

A fingerprint obtained from the same untrusted channel as the bundle does not by itself
establish human identity.

## Stability

For a fixed 32-byte identity public key, Fingerprint v2 MUST be byte-for-byte stable across
platforms and implementations.

Tests SHALL include fixed vectors rather than only generated round trips.

## Limitations

Fingerprint verification does not protect a fully compromised endpoint and does not solve
key transparency, device revocation, recovery, or coercion.
