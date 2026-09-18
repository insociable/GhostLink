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
- sender-side relay fetch orchestration that strictly parses the response, verifies the signed binding against `VerifiedContact`, checks relay metadata consistency and establishes libsignal sessions under persisted highest-seen sequence enforcement;
- owner-authenticated pre-key pool status plus fail-closed automatic replenishment/expiration refresh with local lifecycle cross-checks and depletion cooldown;
- transactional 15-day retired pre-key garbage collection that removes unprotected EC/Kyber private records and associated Kyber replay metadata while preserving pending/active/recent-retired generations;
- explicitly separate protocol-v3 ratcheted message envelopes and GhostNode `/v3/messages` storage/transport;
- context-bound libsignal decryption that authenticates relay-visible v3 routing/lifecycle metadata before the ratchet transaction can commit;
- local profile v2 with an independently random 32-byte ratchet-vault master key inside the existing Argon2id/SecretBox encrypted payload;
- explicit atomic profile-v1 migration for ratcheted CLI use;
- durable ratchet-session lookup before bootstrap;
- `prekey-sync` plus user-facing `send` / `inbox` cutover to protocol v3 across persistent ratchet-engine restarts;
- DeviceID-signed protocol-v3 message-relay requests bound to method, canonical path, canonical-body digest, timestamp and random request ID;
- persistent SQLite protocol-v3 request-replay state that survives GhostNode restart;
- Oracle public HTTPS reference stack with Caddy, TCP/443-only exposure, internal GhostNode networking and automatic TLS certificate lifecycle.
- rollback-aware client-state checkpoint primitives plus an authenticated SQLite monotonic-witness reference backend with crash-safe one-step witness recovery;
- local profile v4 with a random 128-bit client-state ID and independent 32-byte state-coordination key, plus explicit atomic v1/v2/v3 migration.

### Removed

- historical static protocol-v2 `/v2/messages...` relay routes, storage runtime, GhostNodeClient send/receive/delete methods and `node-smoke` CLI diagnostic.

### Security

- private profiles are encrypted at rest and local secret files are excluded from Git;
- replay IDs are recorded atomically before plaintext is exposed;
- relay-visible lifecycle metadata is duplicated inside authenticated ciphertext;
- raw GhostNode port is loopback-bound by default in Compose;
- container deployment runs as a non-root user with reduced privileges;
- Compose requires an explicit relay access token;
- ratchet pre-key publication requires proof of control of the target self-certifying DeviceID signing key in addition to relay access control;
- ratchet pre-key fetch requires target-bound proof of control of the requester DeviceID and serializes SQLite allocation so concurrent requests cannot receive the same one-time binding;
- fetched pre-key material is never trusted from relay metadata alone: the sender verifies the target-signed binding against its existing contact state before any session mutation, with no static-encryption downgrade on failure;
- pre-key maintenance treats relay remaining-count data as untrusted operational input: sequence/expiration divergence fails closed and depletion-triggered rotation is cooldown-limited;
- retired pre-key GC fails closed on ambiguous lifecycle ownership or clock rollback and best-effort zeroizes serialized private-key store buffers before deletion;
- ratcheted v3 relay metadata tampering fails inside the durable decrypt transaction, restoring the previous ratchet state instead of consuming a modified envelope;
- the historical static-v2 message relay is retired; current network messaging uses authenticated ratcheted v3 with no downgrade path;
- user-facing send/inbox fail closed on ratchet bootstrap/decrypt errors instead of retrying via static v2;
- ratchet-vault, contact-store and state-coordination keys are kept inside the encrypted local profile and are not passed in argv or environment;
- protocol-v3 submission requires sender DeviceID control, while mailbox list/delete require recipient DeviceID control;
- stale, replayed, tampered or ownership-mismatched v3 request proofs fail with generic authentication errors; optional Bearer access control remains additive;
- relay Bearer tokens are loaded from mounted/local secret files instead of token values in argv or environment;
- Oracle public ingress disables GhostNode access logs, leaves Caddy HTTP access logging off and explicitly disables Uvicorn proxy-header trust.

### Known limitations

- compromise of a DeviceID signing key remains effective until complete device revocation/recovery is designed;
- relay database rollback can also roll back persisted protocol-v3 request-replay state;
- the libsignal ratchet engine and user-facing v3 CLI path provide tested forward-secrecy/post-compromise behavior, but GhostLink remains pre-alpha and unaudited;
- traffic metadata remains visible to the relay;
- replay-cache rollback/deletion can weaken replay suppression for still-valid captured messages;
- retired-key GC does not guarantee forensic secure erasure from runtime/allocator copies, filesystem snapshots, storage media, backups or restored old vaults;
- no independent security audit yet.