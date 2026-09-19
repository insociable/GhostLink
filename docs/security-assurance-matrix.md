# Security assurance matrix

Status: consolidation snapshot of the current implementation. This is not a certification.

This document classifies security-relevant claims using five labels:

- **Complete in current scope**: implemented and covered by tests for the stated scope.
- **Partial**: implemented, but the guarantee depends on an explicit boundary or missing external component.
- **Implemented; adversarial coverage incomplete**: code exists, but consolidation still needs stronger failure/desynchronization tests.
- **Planned only**: documented direction with no current runtime guarantee.
- **Not guaranteed**: GhostLink deliberately makes no such claim.

The word "complete" never means production-audited. GhostLink remains pre-alpha and has no independent cryptographic/protocol review.

## Current claims

| Property | Status | What the current code guarantees | Boundary / failure condition |
| --- | --- | --- | --- |
| Current message runtime | **Complete in current scope** | User-facing `send` / `inbox` use message protocol v3 and the libsignal ratchet path. | Historical v2 codec code remains for local/history purposes; it is not a network fallback path. |
| Silent v3 → v2 downgrade | **Complete in current scope** | Ratchet bootstrap/encrypt/decrypt failure does not trigger static-v2 network messaging. | This says nothing about denial of service or endpoint compromise. |
| Relay plaintext access | **Complete in current scope** | GhostNode message storage and transport handle libsignal ciphertext, not application plaintext. | GhostNode still observes routing/timing/size metadata and request authentication material. |
| Traffic-analysis resistance | **Not guaranteed** | None. | Device relationships, timing, ciphertext sizes and other relay-visible metadata remain observable. |
| Human contact identity | **Partial** | Persisted contact-ID messaging requires a locally `verified` Fingerprint v2 state; different GhostID replacement is quarantined as `changed`. | Fingerprint verification depends on the human comparison channel; raw-bundle diagnostic messaging can explicitly bypass persisted trust state. |
| Same-GhostID device rotation at a peer | **Partial** | A higher identity-signed lifecycle epoch can update a verified contact without re-verifying the unchanged GhostID; stale ratchet state is invalidated before replacement is persisted. | Discovery depends on the configured relay already having learned the newer lifecycle statement. No independent transparency log exists. |
| Relay stale-device rejection | **Partial** | A relay that has learned the relevant lifecycle history rejects known superseded DeviceIDs on v3 message and pre-key routes. | A relay cannot retroactively identify a never-observed old DeviceID from an active-device-only later statement. |
| Device recovery transaction | **Implemented; adversarial coverage incomplete** | `device-recover` is resumable, publishes replacement lifecycle before profile promotion and resets device-bound ratchet state. | Consolidation still needs interruption testing after every significant recovery step and more mixed-state restoration cases. |
| Lifecycle monotonicity | **Complete in current scope** | Lower epochs and same-epoch divergent lifecycle state fail closed in contact and relay lifecycle handling. | Compromise of the long-term GhostID signing key defeats lifecycle authority for that GhostID. |
| Message/request replay | **Partial** | Authenticated v3 request IDs and client message replay state reject duplicates; SQLite-backed state survives restart. | In-memory relay replay protection is process-local; rollback detection depends on the relevant witness remaining newer. |
| Pre-key anti-replay / continuity | **Partial** | Publication sequence monotonicity, highest-seen remote sequence and authenticated fetch/status flows are enforced and persisted. | A whole-state rollback that also rolls back its witness can remove the freshness signal. |
| Client component rollback | **Partial** | Profile/contact/replay/ratchet components detect stale/divergent state when their monotonic witness remains current. | The reference SQLite witness is in the same ordinary filesystem domain and cannot detect a coherent whole-device snapshot rollback that restores it too. |
| Relay database rollback | **Partial** | Persistent relay state detects an older/divergent protected database when the relay witness remains current. | Restoring the relay database and its sidecar witness together can be indistinguishable from legitimate older state. |
| Forward-secrecy behavior | **Implemented; adversarial coverage incomplete** | The pinned official libsignal engine is used, and integration tests exercise ratchet advancement and old-session snapshot loss of access to later traffic. | GhostLink does not independently prove libsignal's forward-secrecy properties and has not received external cryptographic review. |
| Post-compromise recovery behavior | **Implemented; adversarial coverage incomplete** | An engine-level test shows an old compromised session snapshot failing after fresh ratchet entropy is mixed and propagated. | Recovery depends on later uncompromised entropy/message flow; it is not instantaneous and is not an independently verified GhostLink protocol claim. |
| Post-quantum behavior | **Partial** | GhostLink delegates PQXDH/sparse post-quantum ratchet behavior to the pinned official libsignal package. | No independently designed or independently verified GhostLink post-quantum protocol is claimed. |
| Secure deletion | **Not guaranteed** | Logical retired-key state is removed and owned serialized buffers are best-effort zeroized. | Runtime copies, allocator memory, filesystem history, snapshots, backups and media forensic recovery are outside the guarantee. |
| Malicious-relay availability | **Not guaranteed** | None. | A relay can drop, delay, withhold or selectively serve traffic. |
| Key transparency / global lifecycle discovery | **Planned only** | None. | Current lifecycle discovery is relay-scoped. |
| Sybil-resistant abuse control | **Planned only** | Request authentication and limited anti-drain controls exist. | They are not a Sybil-resistant admission system. |
| Public TLS reference deployment | **Implemented; adversarial coverage incomplete** | A Caddy 443-only reference stack and external validation utility exist. | Live certificate, closed-port and external v3-flow validation remains deployment-specific and is not yet a repository-wide production claim. |

## Evidence anchors

The classification above is grounded in executable tests and the current protocol/runtime wiring, including:

- `tests/test_relay_device_lifecycle.py`: lifecycle monotonicity, stale-device rejection and persistent rollback behavior;
- `tests/test_cli.py`: persisted contact trust, v3-only messaging, replay suppression, recovery ordering and remote device rotation refresh;
- `tests/test_contact_store.py`: verified-contact lifecycle rollback/equivocation/downgrade rejection and witness rollback;
- `tests/test_replay.py`: restart persistence, rollback/divergence detection and one-step crash recovery;
- `tests/test_relay_state.py`: relay database rollback, message resurrection, pre-key rollback and request-replay rollback;
- `tests/test_ratchet_engine_e2e.py`: encrypted ratchet persistence, highest-seen rollback, recovery reset, session invalidation and restart continuity;
- `ratchet-engine/test/ratchet.integration.test.ts`: PQXDH/session behavior and the simulated compromised-session recovery scenario;
- `tests/test_prekey_relay.py`: authenticated publication/fetch/status, monotonic sequence handling, anti-drain behavior and revoked-device rejection.

Passing tests demonstrate the stated implementation behavior under their test conditions. They do not replace an independent protocol or cryptographic audit.

The state/transition rules behind these claims are formalized in `docs/security-invariants.md`.

## Consolidation questions still open

The following are intentionally not upgraded to stronger claims until adversarial consolidation is complete:

1. multi-relay lifecycle divergence where relays know different epochs or no history;
2. exhaustive peer-unaware-of-rotation end-to-end behavior across send, inbox, pre-key bootstrap and stale queued messages;
3. rollback matrix for every individual component and coherent multi-component snapshot combination;
4. interruption after every significant `device-recover` step;
5. impossible/mixed state combinations such as profile N+1 with ratchet N or lifecycle N+1 with stale device-bound state;
6. concurrency races around lifecycle publication, contact refresh and relay state where applicable.

When one of these cases cannot be distinguished from legitimate state, documentation must say so instead of describing the property as protected.
