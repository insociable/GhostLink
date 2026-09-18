# Threat Model

## Protected assets

- message plaintext;
- private identity and device keys;
- libsignal ratchet/session state;
- pre-key private material;
- contact authenticity;
- local message history;
- continuity of observed remote publication sequences.

## Adversaries

GhostLink currently considers:

- compromised or malicious relay operator;
- passive network observer;
- active network attacker;
- attacker replaying captured messages or signed pre-key material;
- attacker attempting public-key substitution;
- attacker with access to relay storage;
- authorized relay client attempting resource exhaustion or pre-key draining;
- attacker restoring an older valid client or relay database snapshot.

## Endpoint compromise

The protocol does not protect secrets from an attacker controlling the running client operating system or GhostLink process.

Examples include:

- malware with process-memory access;
- keyloggers;
- endpoint screenshots;
- hardware implants;
- direct compromise of unlocked private keys.

Hardware-backed secret storage remains future hardening.

## Current implemented protections

The current codebase includes:

- self-certifying GhostID and DeviceID identifiers;
- identity-signed device authorization certificates;
- verified contact bundles;
- protocol-v2 authenticated encryption and persistent replay suppression;
- official libsignal PQXDH/session integration with classical and post-quantum ratchet components;
- encrypted persistent ratchet/pre-key vault state;
- DeviceID-signed binding-v2 pre-key publications;
- crash-safe exact publication staging;
- atomic/idempotent local publication acknowledgement from pending to active with retired-generation retention;
- GhostNode verification of DeviceID control before accepting a pre-key publication;
- strict client-side relay receipt validation before local lifecycle commit;
- exact staged-payload retry after ambiguous network failure;
- monotonic relay publication sequence checks within the current relay database state;
- encrypted client-side highest-seen remote publication sequence persistence, enforced atomically before libsignal session establishment.

These are implemented building blocks, not a production-security certification.

## Current known gaps

Before a ratcheted production cutover GhostLink still lacks:

- relay database anti-rollback protection;
- key transparency;
- pre-key fetch/pop anti-drain and rate limiting;
- automated pre-key replenishment and rotation execution;
- delayed-key garbage collection;
- complete device revocation and recovery design;
- general per-device authentication for message-relay operations;
- production TLS ingress policy and deployment hardening;
- a complete persisted contact-trust / QR verification workflow;
- independent cryptographic/protocol review.

No automatic fallback from a failed ratcheted session to static encryption is permitted.

## Metadata

GhostNode necessarily observes relay metadata including DeviceIDs, timing and ciphertext sizes.

The ratchet pre-key publication endpoint additionally exposes:

- the self-certifying DeviceID signing public key;
- public libsignal identity/pre-key material;
- publication sequence, lifetime and pool size.

Publication does not require sending the long-term GhostID identity public key or full device certificate to GhostNode.

GhostLink does not currently provide global traffic-correlation resistance.

## Post-quantum scope

GhostLink delegates PQXDH and sparse post-quantum ratchet behavior to the pinned official libsignal implementation.

The project does not claim an independently designed or independently verified post-quantum protocol.

Security claims must remain limited to the behavior of the pinned upstream implementation plus GhostLink's integration, and the integration still requires external review.

## Non-goals / external constraints

The first production protocol design does not attempt to solve:

- global passive traffic analysis;
- coercion of participants;
- a fully compromised endpoint;
- hardware implant resistance.

GhostLink remains pre-alpha. No production-security claim may be made until the documented cutover gates and independent review are complete.
