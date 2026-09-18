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

## Supported versions

No version is currently supported for production use.