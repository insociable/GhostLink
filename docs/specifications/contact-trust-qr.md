# GhostLink Contact Trust and QR v1

## Purpose

This specification defines local human trust state and a public QR transport format for
GhostLink Contact Bundle v1.

Cryptographic bundle validation and human identity verification are separate operations.

## Terminology

- **validated bundle**: Contact Bundle v1 passed all structural, identifier, key-length,
  and signature checks;
- **local contact**: a persistent local record with a stable local identifier;
- **pinned identity**: the GhostID currently accepted for a human-verified contact;
- **candidate identity**: a newly observed GhostID awaiting a user decision;
- **trust state**: `imported`, `verified`, or `changed`.

## QR payload v1

The QR textual payload is:

```text
ghostlink:contact:1:<payload>
```

where `<payload>` is Base64url without padding over the exact UTF-8 bytes of the
canonical Contact Bundle v1 JSON emitted by `export_contact_bundle`.

Requirements:

- the decoded payload MUST be no larger than the Contact Bundle import limit;
- the prefix and version MUST match exactly;
- Base64url decoding MUST be strict;
- the decoded bundle MUST pass the normal Contact Bundle v1 importer;
- unsupported QR versions MUST fail closed;
- QR generation MUST use only the public Contact Bundle representation.

The QR payload MUST NOT contain:

- identity or device private keys;
- ratchet-vault or contact-store keys;
- private pre-keys;
- profile passwords or password-derived keys;
- bearer tokens;
- local labels, notes, trust state, verification timestamps, or other local metadata.

A byte-identical canonical Contact Bundle produces a byte-identical QR payload string.


## QR rendering and scanner boundary

GhostLink's reference CLI renders payload v1 as a **standard QR Code**, never a Micro QR
Code, using exact-pinned Segno 1.6.6. SVG is the reference export format so rendering
does not require an image-processing dependency.

QR image decoding is intentionally outside the core trust model. Desktop or mobile camera
code may decode an image to text, but that text MUST then pass the same strict
`ghostlink:contact:1:` decoder and Contact Bundle cryptographic validation before it can
be persisted.

Scanning a QR creates or updates cryptographically valid public material only. A scan
MUST NOT directly create the local `verified` trust state. Human verification remains
a separate explicit Fingerprint v2 confirmation.

## Local trust record v1

A logical record contains at least:

- `record_id`: locally generated stable identifier;
- `label`: local display label;
- `state`: one of `imported`, `verified`, `changed`;
- `current_bundle`: canonical validated Contact Bundle v1;
- `pinned_ghost_id`: GhostID accepted by human verification, or null for `imported`;
- `candidate_bundle`: canonical validated replacement bundle, present only for
  `changed`.

Trust state is local-only. It is never serialized into a public Contact Bundle or QR.

## State invariants

### imported

- `current_bundle` MUST be cryptographically valid;
- `pinned_ghost_id` MUST be null;
- `candidate_bundle` MUST be null.

### verified

- `current_bundle` MUST be cryptographically valid;
- `pinned_ghost_id` MUST equal the GhostID in `current_bundle`;
- `candidate_bundle` MUST be null.

### changed

- `current_bundle` is the previously verified, still-pinned bundle;
- `pinned_ghost_id` MUST equal the GhostID in `current_bundle`;
- `candidate_bundle` MUST be cryptographically valid;
- the candidate GhostID MUST differ from `pinned_ghost_id`.

Invalid records are rejected when the store is opened.

## State transitions

A validated bundle imported into a new local record creates `imported`.

Explicit human verification compares the complete Fingerprint v2 of the current bundle's
identity. A successful explicit confirmation changes `imported` to `verified`.

Replacing an `imported` record with a different validated identity keeps the state
`imported`, because no human identity was pinned.

Replacing a `verified` record:

- same GhostID: update validated public device material if needed and remain `verified`;
- different GhostID: preserve the pinned record, stage the replacement as
  `candidate_bundle`, and enter `changed`.

Only `verified` records are eligible for trusted-contact messaging. `imported` records
remain cryptographically valid but human-unverified, and `changed` records remain
quarantined. Both states MUST fail closed on the trusted-contact path.

The user may then:

- verify the complete Fingerprint v2 of the candidate through an authenticated out-of-band
  channel, promoting it to `current_bundle`, updating `pinned_ghost_id`, clearing the
  candidate, and returning to `verified`; or
- reject the candidate, clearing it and returning to the previous `verified` state.

No network response, relay metadata, bundle field, QR field, or signature can directly set
the human trust state to `verified`.

## Persistence

The trust store is a separate versioned authenticated-encrypted file.

Its key is an independently random 32-byte `contact_store_key` stored only inside the
encrypted local profile. The ratchet-vault master key MUST NOT be reused for this purpose.

The store uses the existing SecretBox primitive and strict schema validation. Version 1
has an outer document containing only `version`, `cipher`, and Base64 ciphertext. The
authenticated plaintext contains the store version plus a bounded list of local records.

On load, every stored Contact Bundle is parsed again through the normal cryptographic
Contact Bundle importer and every trust-state invariant is rechecked. A forged local
`verified` state whose pinned GhostID does not match the authenticated current bundle is
rejected.

Record IDs are locally generated 128-bit random lowercase hexadecimal values. Labels are
local-only, bounded text and are encrypted with the rest of the store.

Writes use a private temporary file plus atomic replace. On POSIX, the accepted store file
is mode `0600`. A crash therefore cannot leave a partially written file accepted as the
current store.

Contact-store format v2 additionally carries the profile-v4 `client_state_id`, a positive
component revision and the previous checkpoint digest inside the authenticated ciphertext.
The exact canonical v2 payload is bound to the `contacts` checkpoint defined by ADR-0008.

Normal CLI opens reconcile that checkpoint against the monotonic witness. Older revisions,
same-revision divergence, wrong client-state identity, missing witnessed stores and invalid
lineage fail closed. A crash after durable store replacement but before witness CAS may
roll the witness forward by exactly one valid linked revision.

Legacy v1 stores are never silently enrolled. The explicit command is:

```bash
ghostlink contact-store-upgrade --profile alice.ghost
```

The reference SQLite witness is development-only and does not protect against a snapshot
that rolls back the witness file together with the contact store.

## User-facing language

Interfaces MUST distinguish:

- "bundle valid" / "cryptographically valid" from
- "identity verified" / "human verified".

A `changed` identity requires a high-severity warning and an explicit user action before
trusted messaging resumes.
