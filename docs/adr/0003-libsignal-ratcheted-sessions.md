# ADR-0003: Ratcheted sessions through libsignal

- Status: Accepted
- Date: 2026-09-18

## Context

GhostLink protocol v2 authenticates routing/lifecycle metadata, rejects replays, and encrypts messages end-to-end with static device encryption keys.

That design does not provide the session properties expected from a modern secure messenger:

- compromise of a long-lived device encryption key can expose future messages encrypted with that same static relationship;
- message keys are not automatically deleted and replaced per message by a ratchet;
- there is no Diffie-Hellman break-in recovery;
- there is no post-quantum continuous ratchet;
- asynchronous session establishment still relies on exchanging a contact bundle rather than a dedicated pre-key protocol.

Implementing a Double Ratchet or a post-quantum ratchet ourselves would create a large cryptographic review burden and unnecessary implementation risk.

## Decision

GhostLink will adopt the maintained Signal Protocol implementation from the official `signalapp/libsignal` project.

The reference integration uses the official Node package:

```text
@signalapp/libsignal-client
```

The first pinned integration version is:

```text
0.102.3
```

Both GhostLink and libsignal are AGPL-3.0-only, so the selected dependency is license-compatible with this repository.

## Protocol profile

GhostLink will use the current libsignal protocol-v4 session flow instead of implementing a custom ratchet.

The upstream implementation combines:

- PQXDH-style asynchronous pre-key session establishment including a Kyber/ML-KEM pre-key;
- the classical Double Ratchet;
- the Sparse Post-Quantum Ratchet (SPQR);
- a Triple Ratchet construction that combines the classical and post-quantum ratchets for message-key derivation.

The security goals are therefore delegated to a maintained protocol implementation rather than recreated in Python.

## Security properties targeted

### Forward secrecy

Every ratchet step derives new message keys and advances chain state. Old message keys are not the source of future chain keys.

A later compromise of current session state should not reveal earlier message keys that have already been erased by the protocol implementation.

### Classical post-compromise security

Fresh Diffie-Hellman ratchet inputs introduced after compromise can recover confidentiality for future traffic once uncompromised entropy has been mixed into both parties' state.

Recovery is not instantaneous and depends on message flow.

### Post-quantum ratcheting

The current libsignal implementation also carries SPQR state and combines its output with the Double Ratchet in the Triple Ratchet path.

This is intended to add post-quantum break-in recovery properties in addition to the classical ratchet.

GhostLink will not claim independent post-quantum security beyond the guarantees and limitations of the pinned upstream libsignal version.

## Process boundary

GhostLink is currently a Python application. The official libsignal package exposes maintained bindings for Java, Swift, and TypeScript, not Python.

GhostLink will therefore use a small local Node/TypeScript crypto engine.

```text
Python GhostLink
    |
    | local authenticated process boundary
    | structured messages only
    v
ratchet-engine (Node/TypeScript)
    |
    v
@signalapp/libsignal-client
    |
    v
libsignal Rust implementation
```

The engine is not a network service.

The initial transport between Python and the engine will be local stdio using length-bounded structured messages. A Unix-domain socket may be considered later if needed for a desktop/mobile architecture.

## Trust boundary

The ratchet engine may hold:

- local Signal identity private key material;
- signed pre-key private material;
- one-time pre-key private material;
- Kyber/ML-KEM pre-key private material;
- serialized session state;
- skipped message keys retained by libsignal for out-of-order delivery.

GhostNode must never receive those values.

GhostNode continues to see only relay-visible metadata and opaque ciphertext.

## Identity relationship

GhostLink GhostID/DeviceID remains the user-facing identity layer.

Libsignal protocol addresses are internal session identifiers and must be deterministically bound to an already verified GhostLink device.

A future migration PR must define and test that binding before ratcheted traffic becomes the default user-facing protocol.

A libsignal identity-key change for an existing verified GhostLink device must fail closed until explicitly re-verified.

## Persistent storage

The bootstrap PR uses in-memory stores only to prove the integration.

Production migration requires encrypted persistent implementations of:

- IdentityKeyStore;
- SessionStore;
- PreKeyStore;
- SignedPreKeyStore;
- KyberPreKeyStore.

They must use atomic writes/transactions and private filesystem permissions.

Secrets must not be stored in GhostNode or plaintext logs.

## Pre-key lifecycle

A later relay migration will add a dedicated public pre-key bundle API.

The relay may publish:

- registration identifier;
- device identifier;
- identity public key;
- signed EC pre-key;
- one-time EC pre-key when available;
- signed Kyber/ML-KEM pre-key.

Private pre-key material remains client-side.

One-time pre-keys must be consumed according to libsignal semantics.

## Existing protocol-v2 envelope

The current GhostLink protocol-v2 static-box encryption path will remain operational until the libsignal migration is proven end-to-end.

It must not be silently mixed with ratcheted ciphertext under the same envelope semantics.

The migration will introduce an explicit cipher-suite/session marker before ratcheted traffic is accepted by production GhostNode clients.

## Failure policy

Cryptographic and state errors fail closed.

GhostLink must not:

- fall back from a failed ratcheted session to static encryption automatically;
- regenerate identity state silently;
- ignore an identity-key replacement;
- replay a pre-key bundle after libsignal marks it consumed;
- log private keys or serialized session state.

## Dependency policy

The libsignal version is pinned exactly.

Updates require:

1. upstream release review;
2. integration test execution;
3. session compatibility tests where applicable;
4. security/changelog review;
5. explicit dependency-update PR.

Automatic major/minor floating versions are not allowed for the cryptographic engine.

## Validation gates

Before ratcheted sessions can replace GhostLink protocol-v2 static encryption, the repository must demonstrate:

1. PQXDH/pre-key session establishment;
2. Alice -> Bob first pre-key message;
3. Bob -> Alice ratcheted reply;
4. multiple sequential ratchet messages;
5. out-of-order delivery;
6. duplicate rejection;
7. persistence/restart of session state;
8. identity replacement fails closed;
9. simulated post-compromise recovery;
10. end-to-end relay transport carrying only opaque libsignal ciphertext;
11. no regression in existing GhostLink identity/contact verification.

## Consequences

Advantages:

- no custom Double Ratchet implementation;
- maintained protocol implementation;
- forward secrecy and break-in recovery become session properties;
- current libsignal provides a path to hybrid classical/post-quantum ratcheting;
- protocol behavior can be tested against upstream semantics.

Costs:

- Node/TypeScript becomes a client-side runtime dependency;
- native libsignal binaries increase package size;
- session/pre-key storage becomes substantially more complex;
- libsignal does not promise a stable third-party API across versions, so upgrades require deliberate review;
- mobile packaging will eventually need platform-native integration rather than spawning a desktop-style Node process.

## Sources

Primary references:

- Signal Double Ratchet specification: https://signal.org/docs/specifications/doubleratchet/
- Signal protocol documentation: https://signal.org/docs/
- Official libsignal repository: https://github.com/signalapp/libsignal
- Official libsignal NPM package: https://www.npmjs.com/package/@signalapp/libsignal-client