# GhostLink Contact Bundle v1

## Purpose

A contact bundle carries only the public information required for one GhostLink client to verify and address another client device.

It is designed for explicit out-of-band exchange between users. It does not contain identity or device private keys.

## Encoding

Version 1 uses a UTF-8 JSON object with these exact fields:

- `version`: integer, currently `1`;
- `ghost_id`: self-certifying GhostID of the remote identity;
- `identity_public_key`: Ed25519 identity verification key, Base64 encoded;
- `device_id`: self-certifying DeviceID;
- `device_signing_public_key`: Ed25519 device signing key, Base64 encoded;
- `device_encryption_public_key`: device encryption public key, Base64 encoded;
- `device_certificate_signature`: identity signature over the canonical device certificate, Base64 encoded.

Unknown fields and unsupported versions are rejected. Import size is limited to 16 KiB.

## Verification on import

A client importing a bundle MUST:

1. validate the document structure and version;
2. decode and validate public-key and signature lengths;
3. reconstruct the signed device certificate;
4. derive the GhostID from `identity_public_key` and require an exact match;
5. derive the DeviceID from `device_signing_public_key` and require an exact match;
6. verify the device certificate signature with the identity public key;
7. expose only the verified public device to the messaging layer.

A failure at any step rejects the contact.

## Security properties and limits

A valid bundle proves that the device certificate was authorized by the identity key contained in that same bundle and that the self-certifying identifiers are internally consistent.

It does **not** by itself prove that the identity belongs to the human the user intended to contact. The bundle or a fingerprint derived from it still needs an authenticated out-of-band verification method before GhostLink can claim verified human identity.

GhostLink remains experimental and is not yet suitable for sensitive real-world communications.
