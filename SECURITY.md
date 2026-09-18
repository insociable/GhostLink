# Security Policy

## Project maturity

GhostLink is pre-alpha software. Do not use it for sensitive or life-critical communications.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Until a dedicated security contact is configured, contact the repository owner privately through GitHub.

## Cryptographic policy

GhostLink will not:

- invent cryptographic primitives;
- silently downgrade algorithms;
- store private identity keys on the relay;
- claim production security without an independent audit;
- implement a custom Double Ratchet or post-quantum ratchet when a maintained reviewed implementation is available;
- silently fall back from a failed ratcheted session to static encryption.

The ratchet engine pins `@signalapp/libsignal-client` exactly. Cryptographic dependency upgrades require a dedicated review PR and test run.


## Contact and local-state trust boundary

A cryptographically valid Contact Bundle or QR payload proves public-key/device consistency only; it does not prove the human identity of the peer. Human verification is an explicit local Fingerprint v2 action and is persisted separately as `imported`, `verified`, or `changed`.

Normal persisted-contact messaging fails closed unless the contact is `verified`. A different GhostID observed for an already verified contact is quarantined as `changed` until the candidate fingerprint is explicitly accepted or rejected.

Profile v3 encrypts independent ratchet-vault and contact-store keys. The current formats authenticate state but do not prevent restoration of an older otherwise-valid client snapshot. Client-state and relay-state anti-rollback remain open hardening work.

## Supported versions

No version is currently supported for production use.