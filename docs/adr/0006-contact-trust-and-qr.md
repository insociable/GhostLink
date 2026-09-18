# ADR-0006: Human contact trust, fingerprints, and QR verification

- Status: Accepted for implementation
- Date: 2026-09-18

## Context

GhostLink already verifies Contact Bundle v1 cryptographically: GhostID and DeviceID are
self-certifying and the device certificate is signed by the identity key. That proves
internal key continuity, but it does not prove that the identity belongs to the human the
user intended to contact.

The current Python type `VerifiedContact` and the CLI wording "Contact bundle verified"
are therefore too easy to interpret as human identity verification.

Issue #20 requires a deterministic fingerprint, public QR exchange, persistent local trust
state, and fail-closed handling when a previously human-verified identity changes.

## Decision

### Separate cryptographic validity from human trust

GhostLink SHALL use two distinct concepts:

- **validated contact bundle**: the public bundle passed all structural and cryptographic
  checks;
- **human trust state**: a local user decision about the expected human identity.

A valid signature MUST NOT create, import, or imply the `verified` human trust state.

The implementation will rename the misleading `VerifiedContact` concept to terminology
that denotes cryptographic validation only. Compatibility aliases may exist temporarily,
but user-facing text must not call a bundle "human verified" merely because signatures
validate.

### Fingerprint v2

Fingerprint v2 is derived directly from the canonical 32-byte Ed25519 identity public key
using SHA-256 with an explicit GhostLink domain separator and version. It does not reuse
the GhostID digest as its input and it does not truncate the hash.

The exact encoding is specified in
`docs/specifications/identity-fingerprint.md`.

### QR payload

QR is a transport representation only. It contains a versioned public Contact Bundle and
no trust decision, private key, profile secret, ratchet state, pre-key private material,
or bearer token.

Scanning a QR MUST run the normal Contact Bundle parser and cryptographic validation.
A QR received through an untrusted channel is equivalent to importing the same bundle
from a file. Human verification occurs only when the user explicitly associates the
scanned fingerprint/bundle with the intended person through an authenticated out-of-band
interaction.

### Persistent trust store

Human trust is security-sensitive local state and SHALL NOT be stored as unauthenticated
plaintext.

GhostLink will use a separate encrypted contact store. Its encryption key is a fresh,
independent 32-byte random `contact_store_key` kept inside the encrypted local profile.
The ratchet-vault master key is not reused.

The contact store is encrypted and authenticated with the project's existing SecretBox
primitive, written by atomic replace, versioned, and strictly parsed.

A local contact record has a stable local identifier and may also carry a user-facing
label. The stable identifier is what allows GhostLink to distinguish "the same saved
person changed identity" from "a newly imported person".

### Trust states

The persisted trust state is exactly one of:

- `imported`: bundle is cryptographically valid, but no human verification has been
  recorded;
- `verified`: the user explicitly verified the current identity fingerprint out of band;
- `changed`: the saved contact was previously `verified`, but a replacement bundle for
  that same local contact record contains a different GhostID.

Transitions are:

1. no record + valid bundle -> `imported`;
2. `imported` + explicit successful human verification -> `verified`;
3. `imported` + different valid identity -> replace candidate and remain `imported`;
4. `verified` + valid bundle with the same GhostID -> remain `verified`;
5. `verified` + valid bundle with a different GhostID -> `changed`;
6. `changed` + explicit successful verification of the candidate identity ->
   `verified` with the candidate promoted;
7. `changed` + explicit rejection of the candidate -> restore the previously pinned
   `verified` identity and discard the candidate.

A `changed` record retains the previously pinned identity and the new candidate
separately. The candidate MUST NOT silently replace the pinned identity.

### Fail-closed behavior

User-facing messaging by saved contact MUST refuse to use a `changed` record until the
candidate identity is explicitly re-verified or rejected.

Low-level diagnostic operations that consume an arbitrary bundle directly may remain for
testing, but they must be clearly labeled as bypassing local human trust and must never
upgrade trust state.

### Device changes under one identity

A new device certificate that validates under the same already-verified GhostID does not
change human trust state. It is still subject to all normal certificate validation and to
future device revocation/recovery rules.

## Consequences

Advantages:

- cryptographic validity and human verification cannot be confused;
- trust survives restart without being forgeable by editing plaintext metadata;
- a relay, bundle, or QR cannot assert `verified`;
- identity replacement is visible and blocks trusted messaging;
- the contact-store key is isolated from ratchet secrets;
- the format can be reused by desktop and mobile clients.

Costs:

- the local profile requires a new version carrying `contact_store_key`;
- contact-store migration and atomic persistence require dedicated tests;
- direct bundle-based CLI workflows must be distinguished from trusted-contact workflows;
- device revocation/recovery remains a separate design problem.

## Non-goals

This ADR does not provide key transparency, account recovery, device revocation, or
protection from a fully compromised endpoint.
