# Threat Model

## Protected assets

- message plaintext;
- private identity and device keys;
- encrypted-profile-held ratchet-vault master key;
- encrypted-profile-held contact-store key and persisted human trust state;
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
- cryptographically validated public Contact Bundles and versioned public QR payloads;
- deterministic Fingerprint v2 human verification, persisted separately from bundle validity;
- encrypted local contact trust states (`imported`, `verified`, `changed`) with verified-identity replacement quarantine;
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
- encrypted client-side highest-seen remote publication sequence persistence, enforced atomically before libsignal session establishment;
- target-bound requester DeviceID proof for pre-key fetch;
- atomic/idempotent one-time pre-key allocation with reusable fallback;
- per-target time-window limiting of new one-time allocations;
- strict sender-side fetch parsing and response/binding consistency checks;
- `ValidatedContact` cryptographic identity/device binding verification before libsignal session establishment;
- normal CLI messaging by persisted contact ID requires explicit local human trust state `verified` and fails closed for `imported` or `changed` contacts;
- no automatic fallback to static protocol-v2 when ratchet bootstrap fails;
- owner-authenticated relay pool-status reads using a signature domain separate from fetch;
- fail-closed pre-key maintenance that cross-checks relay sequence/expiration against local encrypted lifecycle state;
- automatic pool replenishment and expiration refresh with cooldown against relay-induced depletion churn;
- transactional 15-day retired pre-key garbage collection driven only by encrypted lifecycle ownership metadata;
- fail-closed retention on ambiguous lifecycle ownership or local clock rollback, with best-effort zeroization of serialized private-key buffers before in-memory removal;
- explicitly separate ratcheted message-v3 relay routes/storage with strict envelope validation and no v2 reinterpretation;
- canonical v3 routing/lifecycle context encrypted inside libsignal plaintext;
- transaction-bound context verification that restores ratchet state when relay-visible v3 metadata is modified;
- replay-cache acceptance after authenticated v3 context validation and before application plaintext is returned;
- encrypted local profile v4 carrying independently random ratchet-vault, contact-store and state-coordination keys plus a stable client-state identity;
- explicit atomic profile-v1/v2/v3 -> profile-v4 migration that establishes the stable client-state identity and coordination key required by later witness-integrated stores;
- user-facing CLI send/inbox bound to protocol v3, with the historical static-v2 network relay retired;
- durable-session detection before first-contact bootstrap, preventing unnecessary pre-key consumption on later sends;
- DeviceID-signed protocol-v3 message-relay requests bound to HTTP method, canonical logical path, canonical-body digest, freshness timestamp and random request ID;
- sender ownership enforcement for v3 submission and recipient ownership enforcement for v3 mailbox list/delete;
- persistent SQLite request-ID replay rejection across GhostNode restart, with process-local replay protection in in-memory mode;
- optional shared Bearer access control composed as an additional layer rather than accepted as DeviceID identity;
- relay Bearer-token loading from a secret file rather than token values in argv/environment;
- reference Oracle Caddy ingress with GhostNode un-published, TCP/443-only public exposure, disabled HTTP access logs and explicit Uvicorn proxy-header distrust;
- a stdlib-only external TLS gate that validates every published A/AAAA address, public certificate/hostname trust, closed TCP/80 and TCP/8000, and the HTTPS health response before live-deployment acceptance.

These are implemented building blocks, not a production-security certification.

## Current known gaps

Current security gaps still include:

- relay database anti-rollback protection;
- complete client-state anti-rollback is still incomplete: profile-v4 state identity and contact-store witness protection are implemented, while replay and ratchet/highest-seen integration remain under ADR-0008 / issue #79;
- key transparency;
- Sybil-resistant admission/abuse controls beyond requester proof and target-window rate limiting;
- complete device revocation and recovery design;
- live external validation of the reference TLS ingress (real certificate, closed TCP/80 and TCP/8000, external v3 flow) before issue #21 closure;
- independent cryptographic/protocol review.

No automatic fallback from a failed ratcheted session to static encryption is permitted.

Garbage collection removes retired key material from the current logical vault state and best-effort zeroizes the store buffers it owns. It does not guarantee forensic secure erasure from runtime copies, allocator memory, filesystem snapshots, storage media, backups or a restored older encrypted vault.

## Metadata

GhostNode necessarily observes relay metadata including DeviceIDs, timing and ciphertext sizes.

For protocol-v3 messages it additionally observes the libsignal ciphertext framing type. V3 routing/lifecycle fields are duplicated as an authenticated context inside the libsignal ciphertext; modifying those external fields causes context-bound decryption to fail and roll the ratchet transaction back.

Protocol-v3 request authentication additionally exposes the public signing key corresponding to the already-visible DeviceID plus a per-request timestamp and random request ID. The proof authorizes the relay operation; it does not hide routing metadata or provide traffic-analysis resistance. Restoring an older relay database can also restore older request-replay state, so request authentication does not solve relay anti-rollback.

The ratchet pre-key publication endpoint additionally exposes:

- the self-certifying DeviceID signing public key;
- public libsignal identity/pre-key material;
- publication sequence, lifetime and pool size.

The ratchet pre-key fetch endpoint additionally exposes requester DeviceID -> target DeviceID relationships, fetch timing and whether the target pool has reached fallback.

The owner status endpoint exposes when a DeviceID checks its own active sequence, expiration and remaining pool count. A malicious relay can falsify the remaining count, so that value is treated only as a cooldown-limited operational trigger, not as authenticated lifecycle state.

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
