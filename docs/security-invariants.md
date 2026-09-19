# GhostLink security invariants

Status: consolidation document for the current implementation.

This document describes invariants that the current code attempts to enforce. It is not a protocol proof and does not replace the threat model or an independent review.

For each invariant:

- **valid state** describes a state the runtime may consume;
- **valid transition** describes a state change the runtime may accept;
- **forbidden transition** describes a change that must not be accepted silently;
- **fail-closed behavior** describes the expected rejection;
- **verifiers** names the components that currently enforce the rule;
- **boundary** records where the invariant cannot be established.

## Global boundaries

### B-1 — Endpoint compromise is outside the protection boundary

A process or operating system that can read the unlocked GhostLink process, private keys or decrypted state can violate confidentiality and authenticity. Local encryption and ratchet properties are not claims against a fully compromised running endpoint.

### B-2 — Monotonic witnesses only prove freshness while they remain newer

The reference client SQLite witness and relay sidecar witness detect stale/divergent protected state only while the witness itself has not been rolled back.

A coherent filesystem, volume or VM snapshot that restores both protected state and the reference witness to the same older point can be indistinguishable from legitimate older state.

### B-3 — Device revocation knowledge is relay-scoped

A GhostNode can reject a superseded DeviceID only from lifecycle history that it has actually learned. A relay that never observed an old DeviceID cannot infer its GhostID association from a later active-device-only lifecycle statement.

If Relay A knows N+1 while Relay B still knows N, Relay B continues to treat the N device as active. A replacement DeviceID presented to Relay B before lifecycle N+1 is published there is merely an unknown self-authenticating DeviceID, so both old and replacement DeviceIDs can be accepted by that stale relay view. This is a knowledge limitation, not global revocation.

### B-4 — Peer lifecycle discovery is relay-dependent

Persisted verified contacts refresh lifecycle state from the configured relay. A relay that has not learned a newer lifecycle cannot tell the peer that a rotation occurred. GhostLink currently has no independent key-transparency or globally witnessed lifecycle log.

---

# Identity invariants

## ID-1 — GhostID is self-certifying

**Valid state**

A GhostID matches the deterministic identifier derived from the supplied long-term Ed25519 identity verification key.

**Valid transition**

The same GhostID identity key remains stable across ordinary device rotation/recovery.

**Forbidden transition**

Treating a different identity key as the same GhostID.

**Fail-closed behavior**

Identity/lifecycle/contact verification rejects the mismatch.

**Verifiers**

`identity.py`, device certificate verification, lifecycle verification, Contact Bundle import.

**Boundary**

Compromise of the long-term identity signing key defeats the authority of this invariant for that GhostID.

## ID-2 — DeviceID is bound to an identity-authorized device certificate

**Valid state**

The DeviceID is derived from the device signing public key, and the device certificate binds:

- GhostID;
- DeviceID;
- device signing public key;
- device encryption public key;

under the GhostID identity signature.

**Forbidden transition**

Substituting a device key, DeviceID, GhostID or certificate signature independently.

**Fail-closed behavior**

Certificate/contact/lifecycle verification rejects the candidate before trusted messaging or lifecycle acceptance.

**Verifiers**

`device.py`, `device_certificate.py`, `contact.py`, `device_lifecycle.py`.

## ID-3 — Device lifecycle is identity-authorized and monotonic

**Valid state**

A lifecycle statement:

- is signed by the GhostID identity key;
- contains a valid identity-signed active-device certificate;
- has a positive bounded epoch;
- has a non-negative issuance time;
- uses canonical serialization.

**Valid transition**

A candidate for the same GhostID has a strictly higher epoch and does not move `issued_at` backwards.

**Forbidden transition**

- lower epoch;
- same-epoch different canonical state;
- different GhostID;
- forged identity/device signature;
- issuance-time regression for a newer epoch.

**Fail-closed behavior**

The candidate is rejected and current state remains authoritative.

**Verifiers**

`device_lifecycle.py`, contact-store lifecycle checks, relay lifecycle registry.

**Boundary**

Epoch authority comes from the GhostID identity key. Identity-key compromise can authorize malicious future epochs.

## ID-4 — Current architecture has one active DeviceID per GhostID

**Valid state**

One lifecycle head names one active DeviceID.

**Valid transition**

A higher lifecycle epoch replaces the previous active DeviceID.

**Security consequence**

A component that has observed the old DeviceID under an earlier epoch can mark it superseded after accepting the newer epoch.

**Boundary**

This is not a multi-device roster. Unknown historical DeviceIDs cannot be reconstructed from the latest statement alone.

## ID-5 — Human contact trust is separate from cryptographic bundle validity

**Valid state**

- `imported`: cryptographically valid material, no human identity decision;
- `verified`: current contact GhostID equals the locally pinned GhostID;
- `changed`: a different GhostID candidate is staged while the prior pinned identity remains authoritative.

**Valid transition**

- imported → verified only after matching the complete Fingerprint v2;
- verified → verified for a valid monotonic newer lifecycle under the same pinned GhostID;
- verified → changed when a different GhostID candidate is presented;
- changed → verified only after explicit verification of the candidate;
- changed → verified(previous identity) after explicit rejection.

**Forbidden transition**

- imported contact used by normal persisted-contact messaging;
- changed contact used by trusted messaging;
- lifecycle-aware contact downgraded to legacy device-only material;
- lower lifecycle epoch;
- same-epoch divergent lifecycle bytes.

**Fail-closed behavior**

Trusted contact resolution raises an error and messaging aborts.

**Verifiers**

`contact.py`, `contact_store.py`, CLI contact commands.

## ID-6 — Remote device rotation invalidates old device-bound ratchet state before contact persistence

**Valid transition**

For a persisted verified contact, a relay-provided lifecycle may replace the current device only when:

1. the relay identity public key equals the already pinned contact identity key;
2. the lifecycle/contact-store monotonic rules accept the candidate;
3. if DeviceID changed, old ratchet session/cached remote identity/highest-seen remote pre-key state is invalidated;
4. only then is the replacement contact store state persisted.

**Forbidden transition**

Persisting the replacement contact while retaining usable old DeviceID-bound ratchet state.

**Fail-closed behavior**

Any lifecycle, identity, ratchet-witness or persistence failure aborts the command.

**Verifiers**

`_refresh_message_contact_lifecycle`, `RatchetEngineClient.invalidate_session`, witnessed contact store.

**Boundary**

A 404 lifecycle lookup retains current verified state for migration compatibility; it does not prove no rotation happened. The same limitation applies when the configured relay still exposes only the previously accepted epoch.

After a peer has refreshed to a replacement DeviceID, queued envelopes from the superseded sender DeviceID are skipped rather than decrypted as current-peer traffic. The current CLI does not delete those mismatched-sender envelopes in that path, so they may remain relay-visible until normal relay expiration/cleanup.

---

# Messaging invariants

## MSG-1 — User-facing network messaging is protocol v3 only

**Valid state**

Current `send` and `inbox` use ratcheted protocol-v3 messages.

**Forbidden transition**

Automatic fallback from failed ratchet bootstrap/encryption/decryption to static protocol v2.

**Fail-closed behavior**

The command fails rather than changing cipher/runtime path.

**Verifiers**

CLI wiring, node client, retired v2 message routes, integration tests.

## MSG-2 — Relay v3 operations require DeviceID control

**Valid state**

Each request carries an Ed25519 proof from the DeviceID authorized for that operation:

- POST message: sender DeviceID;
- GET inbox: recipient DeviceID;
- DELETE delivered message: recipient DeviceID.

The proof binds method, canonical logical path, authenticated DeviceID, request ID, issuance time and canonical body digest where applicable.

**Forbidden transition**

- wrong DeviceID;
- wrong signing key;
- path/method/body substitution;
- stale proof;
- reused request ID within retained replay state.

**Fail-closed behavior**

GhostNode returns a generic unauthorized response.

**Verifiers**

`relay_request_auth.py`, `relay_v3.py`, persistent request-replay store.

**Boundary**

In-memory replay state is process-local. Persistent replay freshness still shares the relay witness rollback boundary.

## MSG-3 — Relay-visible routing metadata is authenticated by encrypted v3 context

**Valid state**

The canonical routing/lifecycle context included outside the ciphertext matches the context authenticated inside the libsignal plaintext.

**Forbidden transition**

Relay or storage modification of authenticated routing/lifecycle fields.

**Fail-closed behavior**

Context-bound decrypt fails and the ratchet transaction is rolled back rather than committing modified state.

**Verifiers**

v3 message codec/context construction and ratchet-engine transactional decrypt path.

**Boundary**

This detects modification; it does not hide routing metadata from GhostNode.

## MSG-4 — Authenticated message replay is suppressed before repeated plaintext delivery

**Valid state**

A successfully authenticated/decrypted message ID is recorded in replay state scoped to the sender DeviceID.

**Forbidden transition**

Returning application plaintext for an already retained authenticated replay ID.

**Fail-closed behavior**

The duplicate is suppressed; it may be removed from the relay without a second decrypt.

**Verifiers**

CLI inbox flow and replay cache.

**Boundary**

Replay-cache rollback is detectable only while its witness remains newer.

## MSG-5 — Message IDs and relay deduplication do not replace cryptographic replay checks

Relay message deduplication and client authenticated replay state are separate defenses. A message being unique in relay storage does not by itself authorize plaintext delivery.

---

# Pre-key and ratchet invariants

## PRE-1 — Pre-key publication is DeviceID-authenticated and generation-monotonic

**Valid state**

A relay publication is a complete device-signed generation with a device-scoped publication sequence and bounded lifetime.

**Valid transition**

- exact same generation retry may be idempotent;
- the exactly next valid publication sequence may replace the current generation.

**Forbidden transition**

- lower sequence;
- a sequence that skips the exactly-next generation;
- same sequence with different authenticated state;
- route DeviceID/signing-key mismatch;
- already expired generation.

**Fail-closed behavior**

Publication is rejected and local lifecycle commit does not advance from an unverified relay receipt.

## PRE-2 — Pre-key fetch is requester-authenticated and target-bound

**Valid state**

Fetch proof authenticates the requester DeviceID and target DeviceID. One-time allocation is atomic/idempotent for the defined request identity, with fallback behavior when one-time material is unavailable.

**Forbidden transition**

Reusing a proof for another target or substituting requester/target identity.

**Fail-closed behavior**

Fetch fails before session establishment.

## PRE-3 — Highest-seen remote publication sequence must not move backwards

**Valid transition**

Session establishment may observe the same generation sequence or a newer one according to publication semantics.

**Forbidden transition**

Establishing a session from a lower remote publication sequence than already persisted for that DeviceID.

**Fail-closed behavior**

The engine rejects before committing the replacement session/highest-seen state.

**Boundary**

Rollback of the complete ratchet vault together with its witness can erase that observation.

## RATCHET-1 — Ratchet session state is scoped to remote DeviceID

A session for a superseded DeviceID is not valid state for the replacement DeviceID even when both devices belong to the same GhostID.

## RATCHET-2 — Ratchet mutations are transactional with witness coordination

A rollback-aware mutating RPC may not be followed by another security-relevant mutation while witness synchronization is pending.

If engine state commits but witness update fails, further mutations fail until restart/reconciliation establishes one of the explicitly permitted states.

---

# Local-state invariants

## STATE-1 — Lifecycle-aware normal runtime requires profile v5

**Valid state**

Normal lifecycle-aware commands consume a password-encrypted profile v5 containing:

- stable GhostID identity material;
- active device;
- monotonic device lifecycle;
- ratchet/contact-store keys;
- stable client-state ID;
- state coordination key;
- profile checkpoint lineage.

**Valid transition**

Legacy profiles are upgraded explicitly.

**Forbidden transition**

Silently treating legacy profile state as already enrolled rollback-aware lifecycle state.

## STATE-2 — Checkpoint state and witness must agree, except for one crash-recovery successor

For any witnessed component:

**Valid state A**

Component revision/digest exactly equals witness revision/digest.

**Valid state B — sole roll-forward exception**

The component is exactly one revision ahead, its `previous_digest` equals the current witness digest, its checkpoint authenticates the exact payload, and witness compare-and-set succeeds.

**Forbidden state**

- component revision lower than witness;
- equal revision with different digest;
- component more than one revision ahead;
- one-ahead component not linked to witness digest;
- wrong state ID/component binding;
- invalid checkpoint MAC/digest;
- missing witness after enrollment.

**Fail-closed behavior**

The component is rejected. There is no ordinary automatic witness reset/adoption of older state.

**Verifiers**

`state_witness.py` and the component-specific profile/contact/replay/ratchet integration.

## STATE-3 — Security-relevant component mutations advance exact lineage

A successor checkpoint increments revision exactly once and sets `previous_digest` to the current authenticated checkpoint digest.

## STATE-4 — Witness records are scoped to client-state ID and component

Mixing a valid contact/replay/ratchet checkpoint from another client-state identity is not valid local state.

## STATE-5 — Reference witness rollback with the protected state is structurally undetectable

This is a documented non-guarantee, not an implementation bug hidden by wording. A stronger whole-device claim requires a witness outside the rollback domain.

---

# Relay-state invariants

## RELAY-1 — Persistent GhostNode stores share one rollback coordinator

The persistent v3 message store, pre-key store, authenticated request-replay store and lifecycle registry use the same configured relay-state coordinator for the same SQLite database.

Independent coordinators for those protected stores are not valid persistent configuration.

## RELAY-2 — Persistent relay readiness requires successful database/witness reconciliation

Normal persistent service must not become healthy when relay rollback coordination cannot reconcile the current database with its witness.

## RELAY-3 — Lifecycle state becomes a checkpoint input once security-relevant rows exist

The two lifecycle extension tables are omitted when absent/empty so an already witnessed pre-lifecycle database can receive empty tables without changing its old digest.

Once lifecycle rows exist, their contents are part of the canonical protected payload.

**Forbidden transition**

Restoring lifecycle history to older/empty state while the witness remains newer.

**Fail-closed behavior**

Relay-state reconciliation fails before normal persistent service.

## RELAY-4 — Known superseded devices are rejected

After the relay has observed lifecycle history associating an old DeviceID with a GhostID and then accepted a newer active DeviceID for that GhostID, the old DeviceID is rejected on the documented message/pre-key operations.

## RELAY-5 — Unknown historical devices are not globally revoked

A DeviceID absent from the relay lifecycle-device index is not inferred to be revoked merely because the relay knows a later lifecycle head for some GhostID.

This is the explicit boundary behind relay-scoped rather than global revocation.

---

# Device-recovery invariants

## REC-1 — Recovery preserves identity and client-state authority

A valid recovery candidate preserves:

- GhostID identity key;
- client-state ID;
- state coordination key;
- ratchet master key;
- contact-store key.

It must rotate DeviceID.

## REC-2 — Recovery advances lifecycle and profile lineage exactly once

A valid candidate has:

- lifecycle epoch exactly current epoch + 1;
- profile revision exactly current profile checkpoint revision + 1;
- profile previous digest equal to the current profile checkpoint digest.

Any candidate violating these conditions is rejected.

## REC-3 — Current device is registered before replacement publication is relied upon

The recovery flow ensures the current lifecycle is known to the configured relay before completing a fresh rotation path. This gives that relay the old DeviceID → GhostID history needed for later stale-device rejection.

## REC-4 — Replacement lifecycle is published before local profile promotion

The pending replacement profile is not promoted to the active profile path until the configured relay accepts the candidate lifecycle.

A relay publication outage therefore leaves the previous profile active and the candidate pending.

## REC-5 — Interrupted recovery must resume to a valid state or fail explicitly

Recognized pending/archive/vault combinations are either resumed according to the recovery checks or rejected as inconsistent.

The consolidation test phase must enumerate every significant interruption point; this document does not assume current tests cover all of them.

---

# Review rules derived from these invariants

When consolidation adds a new adversarial test, the test should identify:

1. the invariant being challenged;
2. the intentionally corrupted/stale component;
3. the other component(s) held current;
4. the expected rejection or documented non-detectability;
5. whether a witness is inside or outside the restored domain.

A code change is justified only when the test demonstrates behavior that contradicts one of these current invariants or exposes an ambiguity that must fail closed.
