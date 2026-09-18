# GhostLink Identity Fingerprint v1

## Purpose

A GhostID is already self-certifying, but its normal representation is not pleasant to compare verbally or visually.

The identity fingerprint is a **display format**, not a new identifier and not a new cryptographic primitive. It renders the complete 52-character Base32 payload of a valid `ghost1:` identifier as uppercase groups of four characters.

Example shape:

```text
ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567-ABCD-EFGH-IJKL-MNOP-QRST
```

No bits are truncated.

## Verification procedure

When adding a contact, users SHOULD compare the complete fingerprint over an authenticated channel independent of the GhostNode used for message transport.

Examples include:

- comparing it in person;
- reading it during a call where the other person is already known;
- scanning a future QR representation from the other person's device.

A matching fingerprint authenticates the GhostID being compared. Because an imported contact bundle cryptographically chains its device certificate to that GhostID, the verified identity then authenticates the device certificate contained in that bundle.

## Limitations

The fingerprint does not prove human identity unless the comparison channel itself gives the user confidence about who is on the other end.

GhostLink does not yet persist a user trust decision, warn on identity changes, or provide QR scanning. Those remain future client features.
