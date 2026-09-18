# Changelog

All notable changes will be documented in this file.

The format follows Keep a Changelog and Semantic Versioning.

## [Unreleased]

### Added

- project foundation, threat model and architecture decision process;
- GhostID and DeviceID self-certifying identifiers;
- signed device authorization certificates;
- separate device signing and encryption keys;
- verified public peer devices and versioned public contact bundles;
- password-encrypted local profiles using Argon2id and PyNaCl SecretBox;
- GhostNode ciphertext relay API with persistent SQLite storage;
- shared Bearer relay access control;
- strict relay envelope validation and 1 MiB ciphertext cap;
- Docker/Compose deployment and live container smoke tests;
- M3 command-line client and full two-client E2EE integration tests;
- protocol-v2 random 128-bit message identifiers;
- authenticated creation/expiration metadata with a seven-day maximum lifetime;
- protocol-v2 relay deduplication and expiry handling;
- persistent sender-scoped SQLite replay cache with atomic acceptance;
- protocol-v2 CLI send, inbox and live E2EE smoke flow;
- removal of the experimental protocol-v1 runtime path;
- automated dependency update monitoring;
- experimental libsignal-based ratchet engine bootstrap with PQXDH, out-of-order delivery, duplicate rejection and simulated post-compromise recovery tests.
- encrypted persistent ratchet-state vault with atomic multi-store commits and restart continuity tests.
- signed GhostID/DeviceID-to-libsignal pre-key binding with deterministic protocol-address mapping and identity-change fail-closed tests;
- bounded local Python-to-libsignal framed RPC with real cross-language PQXDH/restart smoke tests;
- randomized collision-checked pre-key identifiers while retaining delayed-message private pre-key state;
- documented production ratchet pre-key lifecycle with signed publication generations, one-time bundle pools, last-resort Kyber fallback, monotonic sequence continuity and bounded delayed-key retention;
- ratchet binding v2 with device-signed publication sequence and explicit one-time/fallback bundle roles;
- lifecycle-aware ratchet vault snapshots with v1 state migration and encrypted pending/active/retired pre-key generation metadata;
- atomic pending pre-key generation preparation with shared signed EC material, one-time EC/Kyber pairs and a reusable Kyber last-resort fallback bundle;
- crash-safe DeviceID-signed pre-key publication staging with exact payload recovery and local re-verification after restart;
- GhostNode cryptographically authenticated pre-key publication with strict per-DeviceID sequencing and atomic SQLite replacement;
- atomic idempotent local publication acknowledgement that promotes staged generations and retains the previous active generation for delayed messages;
- strict GhostNode publication orchestration that validates the complete relay receipt before committing local ratchet lifecycle state;
- encrypted per-DeviceID highest-seen remote publication sequence state with atomic rollback rejection before libsignal session establishment;
- authenticated target-bound pre-key fetch requests with atomic one-time allocation, idempotent requester allocation, fallback semantics and configurable per-target anti-drain rate limiting;
- sender-side relay fetch orchestration that strictly parses the response, verifies the signed binding against `VerifiedContact`, checks relay metadata consistency and establishes libsignal sessions under persisted highest-seen sequence enforcement.

### Security

- private profiles are encrypted at rest and local secret files are excluded from Git;
- replay IDs are recorded atomically before plaintext is exposed;
- relay-visible lifecycle metadata is duplicated inside authenticated ciphertext;
- conflicting reuse of a protocol-v2 message ID is rejected by GhostNode;
- raw GhostNode port is loopback-bound by default in Compose;
- container deployment runs as a non-root user with reduced privileges;
- Compose requires an explicit relay access token;
- ratchet pre-key publication requires proof of control of the target self-certifying DeviceID signing key in addition to relay access control;
- ratchet pre-key fetch requires target-bound proof of control of the requester DeviceID and serializes SQLite allocation so concurrent requests cannot receive the same one-time binding;
- fetched pre-key material is never trusted from relay metadata alone: the sender verifies the target-signed binding against its existing contact state before any session mutation, with no static-encryption downgrade on failure.

### Known limitations

- shared relay access control is not per-device cryptographic authentication;
- the libsignal ratchet engine provides tested forward-secrecy/post-compromise behavior, but the user-facing relay/CLI still uses the static protocol-v2 message path until explicit cutover;
- traffic metadata remains visible to the relay;
- replay-cache rollback/deletion can weaken replay suppression for still-valid captured messages;
- no independent security audit yet.