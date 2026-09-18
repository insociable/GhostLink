# GhostLink Ratchet Engine

This directory is the client-side cryptographic engine for the next GhostLink session protocol.

It intentionally delegates ratcheting to the official Signal `libsignal` implementation rather than implementing a Double Ratchet in Python.

## Current milestone

The engine now includes both the in-memory protocol harness and an encrypted persistent vault for libsignal identity, session and pre-key state.

It proves:

- PQXDH/pre-key session establishment;
- bidirectional ratcheted messaging;
- out-of-order message delivery;
- duplicate rejection;
- simulated post-compromise recovery after fresh ratchet entropy.

Persistent state is encrypted with AES-256-GCM, written atomically, and restored transactionally after restart.

The engine is **not yet wired into GhostNode or the GhostLink CLI**.

## Dependency

The cryptographic dependency is pinned exactly:

```text
@signalapp/libsignal-client 0.102.3
```

Do not loosen this version range without a dedicated dependency review.

## Run

```bash
npm ci
npm test
```

## Next milestone

Replace the bootstrap in-memory stores with encrypted persistent stores and define the local Python ↔ ratchet-engine RPC boundary before integrating ratcheted ciphertext into the relay protocol.