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


## Dependency vulnerability policy

Python environments are audited with the pinned pip-audit development dependency, npm dependencies retain a blocking high-severity audit, and pull requests run GitHub dependency review for newly introduced high/critical advisories. Weekly Dependabot checks cover Python, npm, Docker and GitHub Actions dependency surfaces.

No vulnerability is ignored by default. Any temporary exception must identify the advisory, document exposure and rationale, and state an explicit removal condition. Automated scanners are defense-in-depth and do not replace source review, protocol review or an independent audit.

See `docs/dependency-security-policy.md` for the exact policy and limitations.

## Contact and local-state trust boundary

A cryptographically valid Contact Bundle or QR payload proves public-key/device consistency only; it does not prove the human identity of the peer. Human verification is an explicit local Fingerprint v2 action and is persisted separately as `imported`, `verified`, or `changed`.

Normal persisted-contact messaging fails closed unless the contact is `verified`. A different GhostID observed for an already verified contact is quarantined as `changed` until the candidate fingerprint is explicitly accepted or rejected.

Profile v5 encrypts independent ratchet-vault and contact-store keys and carries rollback-coordination state. Contact, replay, ratchet and profile components, plus persistent relay state, detect stale or divergent snapshots only while their monotonic witness remains newer. The reference SQLite/sidecar witnesses do **not** provide whole-device or whole-VM anti-rollback when the protected state and witness are restored together.

A higher identity-signed lifecycle epoch for the same already verified GhostID can replace the active DeviceID without repeating the human fingerprint comparison. A different GhostID still becomes `changed`.

Device revocation is not global. A GhostNode can reject an old DeviceID only from lifecycle history it has actually learned, and peer refresh depends on the configured relay having learned the newer signed lifecycle. GhostLink currently has no independent key-transparency or globally witnessed lifecycle log.

See `docs/security-assurance-matrix.md` for the current claim-by-claim classification and explicit failure boundaries.

## Supported versions

No version is currently supported for production use.
