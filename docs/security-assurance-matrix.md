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
| Ratchet RPC bounded wait | **Complete in current scope** | Every Python-to-ratchet-engine request has a finite deadline. Timeout kills and reaps the owned child, invalidates that client instance and requires reopening from durable state. | A timeout may occur after a mutating request reached the child; the timed-out client is therefore never reused and normal vault/witness reconciliation applies on reopen. |
| Relay plaintext access | **Complete in current scope** | GhostNode message storage and transport handle libsignal ciphertext, not application plaintext. | GhostNode still observes routing/timing/size metadata and request authentication material. |
| Traffic-analysis resistance | **Not guaranteed** | None. | Device relationships, timing, ciphertext sizes and other relay-visible metadata remain observable. |
| Human contact identity | **Partial** | Persisted contact-ID messaging requires a locally `verified` Fingerprint v2 state; different GhostID replacement is quarantined as `changed`. | Fingerprint verification depends on the human comparison channel; raw-bundle diagnostic messaging can explicitly bypass persisted trust state. |
| Same-GhostID device rotation at a peer | **Partial** | A higher identity-signed lifecycle epoch can update a verified contact without re-verifying the unchanged GhostID; stale ratchet state is invalidated before replacement is persisted. | Discovery depends on the configured relay already having learned the newer lifecycle statement. No independent transparency log exists. |
| Relay stale-device rejection | **Partial** | A relay that has learned the relevant lifecycle history rejects known superseded DeviceIDs on v3 message and pre-key routes. | A relay cannot retroactively identify a never-observed old DeviceID from an active-device-only later statement. |
| Device recovery transaction | **Implemented; adversarial coverage incomplete** | `device-recover` is resumable, publishes replacement lifecycle before profile promotion and resets device-bound ratchet state. | Consolidation still needs interruption testing after every significant recovery step and more mixed-state restoration cases. |
| Initial private-file durability | **Implemented and fault-injection tested** | Initial profile and recovery-pending creation keeps `O_EXCL`, fsyncs file content and the parent directory on POSIX, and removes the target after synchronous write/fsync failure. | Fault injection exercises syscall failures, not literal power loss or every filesystem/storage-controller ordering behavior. |
| Lifecycle monotonicity | **Complete in current scope** | Lower epochs and same-epoch divergent lifecycle state fail closed in contact and relay lifecycle handling. | Compromise of the long-term GhostID signing key defeats lifecycle authority for that GhostID. |
| Message/request replay | **Partial** | Authenticated v3 request IDs and client message replay state reject duplicates; SQLite-backed state survives restart. | In-memory relay replay protection is process-local; rollback detection depends on the relevant witness remaining newer. |
| Pre-key anti-replay / continuity | **Partial** | Publication sequence monotonicity, highest-seen remote sequence and authenticated fetch/status flows are enforced and persisted. | A whole-state rollback that also rolls back its witness can remove the freshness signal. |
| Client component rollback | **Partial** | Profile/contact/replay/ratchet components detect stale/divergent state when their monotonic witness remains current. | The reference SQLite witness is in the same ordinary filesystem domain and cannot detect a coherent whole-device snapshot rollback that restores it too. |
| Relay database rollback | **Partial** | Persistent relay state detects an older/divergent protected database when the relay witness remains current. | Restoring the relay database and its sidecar witness together can be indistinguishable from legitimate older state. |
| Forward-secrecy behavior | **Implemented; adversarial coverage incomplete** | The pinned official libsignal engine is used, and integration tests exercise ratchet advancement and old-session snapshot loss of access to later traffic. | GhostLink does not independently prove libsignal's forward-secrecy properties and has not received external cryptographic review. |
| Post-compromise recovery behavior | **Implemented; adversarial coverage incomplete** | An engine-level test shows an old compromised session snapshot failing after fresh ratchet entropy is mixed and propagated. | Recovery depends on later uncompromised entropy/message flow; it is not instantaneous and is not an independently verified GhostLink protocol claim. |
| Post-quantum behavior | **Partial** | GhostLink delegates PQXDH/sparse post-quantum ratchet behavior to the pinned official libsignal package. | No independently designed or independently verified GhostLink post-quantum protocol is claimed. |
| Secure deletion | **Not guaranteed** | Logical retired-key state is removed and owned serialized buffers are best-effort zeroized. | Runtime copies, allocator memory, filesystem history, snapshots, backups and media forensic recovery are outside the guarantee. |
| Malicious-relay availability | **Not guaranteed** | None. | A relay can drop, delay, withhold or selectively serve traffic, or return oversized responses. Current mailbox retrieval is not paginated, so availability/memory use against a malicious relay is outside the protection claim. |
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

## Adversarial result: peer unaware of device rotation

Current tests now make the single-relay CLI behavior explicit:

- if the configured relay knows epoch N+1, a persisted verified peer accepts the higher lifecycle under the same pinned GhostID, invalidates the old DeviceID-bound ratchet state before contact persistence, and can bootstrap the replacement DeviceID;
- if the relay still knows only epoch N, the peer keeps the old verified contact and old session. The existence of a newer device elsewhere is not detectable from that relay view;
- if lifecycle lookup returns 404, the peer likewise keeps the current verified contact for migration compatibility. This is not evidence that no rotation occurred;
- if ratchet invalidation fails, the replacement contact is not persisted;
- if ratchet invalidation succeeds but contact-store persistence fails, the old contact remains while the old session has been removed; retrying the refresh is idempotent and converges to the replacement contact/session;
- a message queued by the superseded DeviceID before rotation is not delivered as plaintext after the peer learns N+1 because its sender DeviceID no longer matches the refreshed contact. The current CLI leaves that mismatched envelope on the relay rather than deleting it as authenticated peer traffic.

These results preserve the **partial** classification: a peer cannot reject knowledge it never received, and the configured relay is the current discovery source.

## Adversarial result: multi-relay revocation matrix

Independent relays do not share lifecycle knowledge. Tests with one GhostID rotating from Device A / epoch N to Device B / epoch N+1 confirm:

| Relay view | Device A | Device B | Lifecycle lookup |
| --- | --- | --- | --- |
| Relay A observed N then N+1 | rejected as known stale | accepted as active | N+1 |
| Relay B observed only N | accepted as locally active | accepted as an unrelated/unknown DeviceID | N |
| Relay C observed no lifecycle | accepted as unknown | accepted as unknown | 404 |

Relay B cannot infer that Device B belongs to the same GhostID until it receives identity-authorized lifecycle N+1. Relay C cannot infer either association. Therefore lifecycle revocation is intentionally **relay-scoped**, not globally discoverable.

A persistent restoration test also confirms the rollback boundary: restoring the relay database **and** its reference witness together to the same older N snapshot is accepted as internally consistent. Restoring only the older protected database while the witness remains newer is covered separately and fails closed.

## Adversarial result: rollback and restoration matrix

The current rollback-aware components now share an explicit tested matrix:

| State / witness relation | Result |
| --- | --- |
| current component state + matching current witness | accepted |
| older component state + newer witness | rejected as rollback |
| same revision + different authenticated payload | rejected as divergence |
| revision 1 + missing witness + authenticated pending bootstrap intent | intent is atomically consumed and revision-1 witness is installed |
| revision 1 + missing witness + no bootstrap intent | fail closed; no witness recreation |
| component exactly one revision ahead + valid previous digest | witness may catch up exactly one revision |
| component more than one revision ahead | rejected as a gap |
| enrolled component + missing witness after bootstrap | fail closed |
| protected state and reference witness both restored coherently to the same older snapshot | accepted as internally consistent; rollback is not detectable |
| different components at different valid revisions | accepted; revisions are component-local, not a global transaction counter |

The coherent-restore boundary is exercised directly for profile state, contact store, replay cache, ratchet vault and persistent relay state. This confirms that the reference SQLite/sidecar witnesses provide **component rollback detection only while the witness remains outside the restored snapshot**. They do not provide whole-filesystem, whole-volume or whole-VM rollback protection.

First-bootstrap fault injection now covers profile, contact, replay and ratchet state.
A failure after revision-1 state publication but before witness finalization is recoverable
only through the authenticated pending intent. Removing the witness database removes the
intent too and the same component state is rejected rather than silently re-enrolled.

A profile at revision N+1 with contacts/replay/ratchet at revision N is therefore not inherently corrupt. Each component has its own authenticated lineage and witness row. What fails closed is a mismatch *within* one component's state/witness lineage, not unequal revision numbers across independent components.

## Adversarial result: device recovery interruption matrix

The current recovery transaction has now been exercised across its security-relevant durable boundaries:

| Interruption / durable state | Result on failure | Retry behavior |
| --- | --- | --- |
| initial current-lifecycle publication fails | active profile remains N; no pending candidate; relay may still have no lifecycle record | fresh recovery produces N+1 |
| current lifecycle published, pending-profile creation fails | active profile remains N; no pending candidate; relay knows N | fresh recovery produces N+1 |
| candidate lifecycle publication fails | active profile remains N; pending candidate N+1 remains; relay remains at N | retry resumes the same candidate |
| candidate lifecycle is N+1 remotely, pending→active promotion fails | local active profile remains N; pending N+1 remains; relay knows N+1 | retry recognizes the relay's identical pending candidate and promotes N+1 |
| old ratchet vault archived with a valid ratchet witness but replacement vault absent | pending candidate + old-vault archive remain | replacement vault is recreated from the witnessed predecessor and N+1 completes |
| pending candidate + old-vault archive but no ratchet witness | inconsistent recovery state | explicit fail closed |
| ratchet vault presence disagrees with ratchet-witness presence | inconsistent recovery state | explicit fail closed |
| profile has been promoted to N+1 but directory fsync fails | local/relay candidate N+1 exists; pending path is gone; profile witness can remain at N | next command reconciles the one-step witness gap, then a new recovery request rotates to N+2 |
| profile has been promoted to N+1 but profile-witness reconciliation fails | local/relay N+1 with witness still N | next command catches the witness up, then a new recovery request rotates to N+2 |
| final old-vault archive deletion fails after valid N+1 is active | N+1 remains active with leftover archive | retry finalizes the same N+1 device/epoch without another rotation |
| cleanup archive exists but replacement vault is missing | incomplete finalization state | explicit fail before lifecycle publication/further mutation |

The transaction therefore fails closed on inconsistent artifact/witness combinations and safely resumes recognized pre-promotion states. A late interruption **after active-profile promotion** is different: because promotion removes the pending transaction marker, the next explicit `device-recover` invocation first reconciles the valid N+1 profile/witness state and then starts a new recovery, consuming N+2. This is security-consistent but is not transaction-identity idempotence.

No tested interruption produced silent acceptance of a mixed identity/device state, and no runtime correction was required.

## Adversarial result: concurrency and race matrix

The remaining security-sensitive races are now exercised directly:

| Concurrent case | Observed / required result |
| --- | --- |
| identical lifecycle publication vs itself | both calls may succeed idempotently; relay checkpoint advances once |
| two different lifecycle states at the same epoch | exactly one wins; the other is rejected as equivocation/conflict |
| lifecycle N+1 vs N+2 | final head is the highest accepted epoch; a lower late writer cannot roll it back |
| stale lifecycle vs newer lifecycle | final head remains newer; stale publication is idempotent-before-newer or rejected-after-newer |
| same DeviceID claimed by two GhostIDs | exactly one identity can own the DeviceID in that relay registry |
| lifecycle mutation vs v3 message mutation on one coordinator | serialized; both durable changes are witnessed and coordinator remains healthy |
| lifecycle mutation vs pre-key mutation on one coordinator | serialized; both durable changes are witnessed and coordinator remains healthy |
| lifecycle mutation vs authenticated request-replay insertion on one coordinator | serialized; both durable changes are witnessed and coordinator remains healthy |
| identical same-instance contact lifecycle refreshes | idempotent after process-local serialization |
| stale vs newer same-instance contact refresh | cannot finish at the stale epoch |
| two different same-epoch same-instance contact refreshes | exactly one wins after the process-local locking correction |
| two independent persistent contact writers from one witnessed revision | witness CAS permits at most one successor; an unmatched final file is rejected as divergence on next load |

This pass found one real runtime race: `ContactTrustStore.update_contact_bundle` previously performed the lifecycle check and record replacement without a process-local critical section. Two threads could both validate against the same old record and silently accept different same-epoch devices. The store now uses a process-local re-entrant lock around lifecycle bundle updates, and the adversarial race is covered by repeatable tests.

The boundary remains intentionally narrower than a distributed lock. Separate processes or independent store objects writing the same encrypted contact file are not globally serialized. Atomic file replacement plus witness compare-and-set ensures that only a witnessed successor is trusted; if a losing writer leaves divergent bytes behind, the next load fails closed instead of silently accepting them.

Persistent GhostNode protection is similarly scoped to the normal architecture: one `RelayStateCoordinator` owns the protected stores in one process. Tests demonstrate serialization through that coordinator. GhostLink does not claim distributed consensus or safe active/active multi-process sharing of one relay database and witness.

Existing pre-key tests continue to demonstrate atomic allocation under concurrent requesters; this consolidation did not require a new pre-key synchronization mechanism.

## Consolidation questions still open

The adversarial lifecycle, rollback, recovery and concurrency matrices are now covered in the current repository scope. Automated dependency-policy enforcement is now in place; the remaining internal consolidation step is the final maintainability/security review before external audit.

When one of these cases cannot be distinguished from legitimate state, documentation must say so instead of describing the property as protected.
