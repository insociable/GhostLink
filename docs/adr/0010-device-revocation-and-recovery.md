# ADR-0010: Monotonic device revocation and recovery

- Status: Accepted for implementation
- Date: 2026-09-18
- Tracks: #92

## Context

GhostLink separates one long-term GhostID identity key from a DeviceID key pair. The
identity signs a device certificate, and peers pin the GhostID after human verification.

The current contact model already permits a verified contact to replace its public device
material while keeping the same pinned GhostID. That is not sufficient for revocation:
an older, still-valid identity-signed device certificate can later be replayed and accepted
again because device certificates carry no monotonic lifecycle state.

GhostNode also authenticates requests with the self-certifying DeviceID signing key. A
superseded device therefore remains acceptable to the relay unless the relay learns an
identity-authoritative lifecycle decision.

## Decision

GhostLink will add a versioned, identity-signed **device lifecycle statement**.

For the current single-device architecture, one lifecycle statement names exactly one
active DeviceID for a GhostID. Publishing a strictly newer lifecycle epoch implicitly
revokes every device named by an older epoch.

The GhostID remains unchanged across device recovery.

## Lifecycle authority

The long-term GhostID Ed25519 identity key is the lifecycle authority.

A lifecycle statement contains:

- format version;
- GhostID;
- positive monotonic lifecycle epoch;
- issuance time;
- the complete identity-signed active-device certificate;
- an identity signature over the complete lifecycle statement.

The lifecycle signature is domain-separated from the device-certificate signature.

Verification MUST prove all of the following:

1. the GhostID derives from the supplied identity public key;
2. the device certificate GhostID equals the lifecycle GhostID;
3. the device certificate signature is valid under the identity key;
4. the DeviceID derives from the certificate signing key;
5. the lifecycle identity signature is valid;
6. the lifecycle epoch and serialization are canonical and within bounds.

A lifecycle statement is public metadata. It contains no private key material.

## Monotonic rule

For one GhostID, clients and relays track the highest accepted lifecycle epoch.

A candidate with an epoch lower than the highest accepted epoch is a rollback and MUST be
rejected.

A candidate with the same epoch but different canonical bytes is equivocation and MUST be
rejected.

An identical same-epoch statement is an idempotent replay and MAY be accepted without
state mutation.

A candidate with a higher epoch MAY replace the current state only after complete
cryptographic verification.

The issuance time is secondary continuity metadata, not the monotonic authority. A newer
epoch whose issuance time predates the current accepted state is rejected to catch obvious
state-construction regressions.

## Revocation semantics

GhostLink currently supports one active local device per identity.

Therefore, accepting epoch `n + 1` means:

- the device named by epoch `n + 1` is active;
- every device named only by epochs `<= n` is superseded and must no longer be trusted
  for new communication.

This is intentional single-active-device semantics, not a general multi-device roster.
A future multi-device design requires a new lifecycle format rather than overloading this
one.

## Local recovery

A recovery operation:

1. unlocks the existing identity profile;
2. requires rollback-aware profile state to be healthy;
3. generates a fresh device signing and encryption key pair;
4. creates an identity-signed device certificate;
5. increments the lifecycle epoch exactly once;
6. signs the new lifecycle statement;
7. atomically persists the new active device and epoch in the profile;
8. rotates or invalidates device-bound ratchet/pre-key state as specified by the
   implementation;
9. exports lifecycle-aware contact material for peers.

The old device private key is never copied into the new state.

Recovery assumes the GhostID identity signing key remains controlled by the legitimate
user. If that root identity key is compromised, an attacker can authorize future device
epochs; this mechanism cannot recover the same GhostID from root-key compromise.

## Contact behavior

Lifecycle-aware contact material carries the identity public key plus the signed lifecycle
statement.

After a contact has accepted lifecycle-aware state, its trust store records the
highest-seen lifecycle epoch and canonical statement digest.

For an already human-verified GhostID:

- a valid higher lifecycle epoch for the same GhostID updates the active DeviceID without
  requiring a new identity fingerprint comparison;
- a lower epoch fails closed;
- same-epoch divergence fails closed;
- a legacy device-only bundle MUST NOT downgrade lifecycle-aware state;
- a different GhostID remains an identity change and requires explicit human verification.

Message send, receive, pre-key bootstrap and ratchet binding verification use only the
currently active device from the accepted lifecycle state.

## Relay behavior

GhostNode will expose an authenticated lifecycle publication/lookup mechanism.

The relay stores the highest accepted lifecycle statement per GhostID and an index from
known DeviceIDs to lifecycle status.

Once a GhostID is lifecycle-registered, security-relevant routes MUST reject a superseded
device. This includes, at minimum:

- protocol-v3 message submission by a revoked sender;
- protocol-v3 inbox/delete access for a revoked recipient device;
- pre-key publication/status for a revoked device;
- pre-key fetch requests authenticated by a revoked requester when its identity is known.

Lifecycle publication is authorized by the identity signature itself and the relay bearer
gate. A superseded device cannot create a newer epoch without the GhostID identity key.

## Relay rollback protection

Persistent relay lifecycle tables are security-relevant state.

They MUST participate in the ADR-0009 shared relay-state coordinator and its canonical
checkpoint digest. Restoring an older relay database must not resurrect a superseded
device when the monotonic witness remains current.

The reference SQLite/file witness has the same whole-snapshot limitation documented by
ADR-0009.

## Device-bound ratchet state

A DeviceID change changes the libsignal protocol address.

Existing sessions for the superseded DeviceID MUST NOT silently migrate to the new
DeviceID. The recovered device establishes fresh sessions and publishes fresh pre-keys.

Local state associated only with the old DeviceID may be retained for forensic/export
purposes only if normal send/receive paths cannot select it. The default recovery path
should prefer deletion or explicit archival over accidental reuse.

## Distribution limitation

Revocation is effective for a peer only after that peer learns a newer lifecycle
statement, unless the peer consults a relay that already enforces it.

An offline peer that knows only an older valid state cannot infer a later revocation.
Key transparency or an independently witnessed identity log can improve this property in
a future design.

This ADR therefore does not claim global instantaneous revocation.

## Migration

Existing device certificates and contact bundle v1 remain parseable during migration.

A local profile upgrade initializes lifecycle epoch 1 for its currently enrolled device
and signs the corresponding statement.

A contact receiving its first lifecycle-aware bundle for a previously verified GhostID
may adopt epoch 1 if the identity key and active device certificate verify. Once adopted,
that contact cannot downgrade to legacy device-only state.

GhostNode lifecycle enforcement is activated for identities that have published lifecycle
state. A later protocol milestone may make lifecycle registration mandatory for every
persistent node.

## Security consequences

This design provides:

- stable GhostID across normal device recovery;
- cryptographic authorization of device replacement by the identity key;
- explicit monotonic stale-device detection;
- rollback/equivocation rejection in lifecycle-aware contact state;
- a basis for relay-side stale-device enforcement;
- clean separation between identity compromise and device compromise.

It does not provide:

- recovery from compromise of the long-term GhostID identity key;
- instantaneous revocation for peers that never receive newer lifecycle state;
- multi-device simultaneous authorization;
- protection against whole-host rollback when the relay/client witness rolls back with the
  protected state.

## Implementation sequence

1. implement and test the signed lifecycle primitive;
2. add profile lifecycle state and lifecycle-aware contact bundle/store semantics;
3. add explicit device recovery CLI and ratchet-state handling;
4. add GhostNode lifecycle registry and route enforcement;
5. add end-to-end recovery/revocation tests and operator/user documentation.
