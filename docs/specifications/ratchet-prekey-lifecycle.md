# Ratchet pre-key lifecycle

Status: accepted design; prepare/stage/publish/local-commit/fetch/sender bootstrap/replenishment/refresh/GC implemented

## Purpose

GhostLink already persists libsignal state, binds public pre-key material to an enrolled GhostLink device, and exposes a local Python-to-Node RPC bridge.

The bootstrap path intentionally generates one complete pre-key bundle at a time. That is sufficient for integration tests, but it is not a production lifecycle.

This specification defines the production-facing lifecycle before GhostNode receives a ratchet pre-key API.

The design follows the upstream PQXDH model:

- a periodically rotated signed elliptic-curve pre-key;
- a pool of one-time elliptic-curve pre-keys;
- a periodically rotated signed last-resort post-quantum KEM pre-key;
- a pool of signed one-time post-quantum KEM pre-keys.

GhostLink does not implement a new key-agreement construction. libsignal remains responsible for PQXDH/session processing.

## Design goals

The lifecycle must provide:

- bounded pre-key state;
- no silent reuse of one-time keys under normal relay behavior;
- deterministic crash recovery around publication;
- retention of delayed-message private material;
- explicit last-resort Kyber semantics;
- authenticated publication generations;
- a monotonic freshness signal that improves rollback detection after first observation;
- no downgrade to the static GhostLink message path.

The lifecycle is not a global transparency system. A malicious relay can still deny service, freeze a client on the newest state it has already observed, or present a still-valid generation to a first-time observer.

## Production publication generation

GhostLink publishes pre-key material as an atomic generation per DeviceID.

One active generation contains:

1. the libsignal identity public key and registration ID;
2. one current signed EC pre-key;
3. one current signed last-resort Kyber/ML-KEM pre-key;
4. a pool of pre-signed one-time bindings;
5. one pre-signed fallback binding;
6. one monotonic publication sequence shared by the generation.

The default one-time pool target is:

```text
100 bundles
```

Each one-time bundle contains:

- one unique one-time EC pre-key;
- the current signed EC pre-key;
- one unique signed one-time Kyber/ML-KEM pre-key;
- the current libsignal identity key;
- the generation publication sequence;
- a random 128-bit bundle ID;
- the normal GhostID/DeviceID binding fields and device signature.

The fallback bundle contains:

- no one-time EC pre-key;
- the current signed EC pre-key;
- the current signed last-resort Kyber/ML-KEM pre-key;
- the current libsignal identity key;
- the same generation publication sequence;
- its own random 128-bit bundle ID;
- the normal GhostID/DeviceID binding fields and device signature.

GhostNode must never construct, rewrite, merge, or re-sign a binding.

## Why GhostLink publishes complete signed bundles

The bootstrap binding signs a complete libsignal pre-key bundle.

Publishing independent EC and Kyber pools would require GhostNode to assemble fields that were not signed together, or would require a second authenticated component/proof system.

GhostLink therefore keeps the simpler trust boundary:

```text
device generates material
        |
        v
device signs complete binding
        |
        v
GhostNode stores opaque signed public binding
        |
        v
sender verifies binding
        |
        v
libsignal receives reconstructed PreKeyBundle
```

This avoids a custom Merkle/proof layer and preserves the existing GhostID -> DeviceID -> ratchet-binding trust chain.

## Binding version 2

The existing binding version 1 is a bootstrap format. It must not become the production relay-pool format.

The lifecycle implementation will introduce binding version 2.

Version 2 adds at least:

- `publication_sequence`: positive JSON-safe integer generation sequence (`1..2^53-1`);
- `bundle_kind`: `one_time` or `fallback`.

Both fields are covered by the existing GhostLink device Ed25519 signature.

### One-time binding invariants

For `bundle_kind = one_time`:

- the EC one-time pre-key must be present;
- the Kyber pre-key is one-time;
- EC pre-key ID and Kyber pre-key ID are unique inside the generation;
- the binding is expected to be handed out at most once by an honest relay.

### Fallback binding invariants

For `bundle_kind = fallback`:

- the EC one-time pre-key must be absent;
- the Kyber pre-key is the generation's last-resort key;
- the binding may be returned repeatedly while the generation is active.

A relay changing `bundle_kind` invalidates the device signature.

There is no silent acceptance of binding version 1 by the production ratchet relay path.

## Publication sequence

Each DeviceID maintains its own strictly increasing publication sequence. The wire/profile range is `1..2^53-1` so Python, TypeScript and JSON relays preserve the value exactly.

The first production generation uses sequence 1.

A new generation uses exactly:

```text
previous_sequence + 1
```

The sequence is part of the signed binding.

A sender that has already observed a sequence for a verified DeviceID stores the highest accepted value.

For a later fetch:

- a lower sequence is rejected;
- the same sequence is allowed because a generation contains multiple distinct one-time bundle IDs plus one fallback bundle;
- a higher sequence is accepted only after normal GhostID/DeviceID signature and timestamp verification.

This prevents a relay from rolling an already-observing sender back to a lower publication generation.

It does not solve:

- first-contact stale publication;
- rollback of both a local client vault and its remembered remote sequence;
- a malicious relay freezing a sender at the highest sequence it has already observed.

Those require stronger trusted monotonic state or transparency.

## Pool replenishment

The default one-time bundle pool parameters are:

```text
target = 100
replenish_threshold = 30
```

These are operational defaults, not cryptographic protocol constants.

When GhostLink learns that the active relay pool is at or below the threshold, it prepares a complete replacement generation with a fresh pool of 100 one-time bundles.

The operational maintenance path now uses an owner-authenticated relay status request to read the remaining one-time count. The local encrypted lifecycle remains authoritative for the active publication sequence and expiration. A relay sequence or expiration that differs from local active state fails closed and does not trigger rotation.

For depletion-only maintenance the default cooldown is one hour after the active publication timestamp. This limits churn if a malicious relay lies about a low remaining count. Expiration-driven refresh is never blocked by this cooldown.

The current implementation creates a fully fresh generation for every replenishment or refresh:

- publication sequence increments by exactly one;
- signed EC pre-key is fresh;
- last-resort Kyber/ML-KEM pre-key is fresh;
- all one-time EC and Kyber pairs are fresh;
- binding IDs and timestamps are fresh;
- prepare/stage/publish/commit keeps the existing crash-safe workflow.

GhostLink does not top up by mixing newly signed entries into an older publication sequence.

Replacing the whole generation keeps freshness and crash semantics simple and avoids serving multiple lifecycle epochs under one active pool.

## Rotation

The current signed EC pre-key and the current last-resort Kyber pre-key rotate together.

Default rotation interval:

```text
7 days
```

A rotation also creates a new publication generation and increments the publication sequence.

Rotation may occur earlier after:

- explicit operator/security action;
- lifecycle metadata corruption detected fail-closed;
- fallback resource limits being reached;
- a future protocol migration that requires new key material.

Identity-key replacement is not pre-key rotation. It remains a separate explicit re-verification/recovery event.

## Binding lifetime and refresh

Production relay bindings keep the existing maximum lifetime of seven days.

The production publication profile uses the full seven-day lifetime so an offline recipient does not require daily refresh merely to remain contactable.

A connected client refreshes the generation when fewer than 48 hours remain before binding expiration, even when the pool is still above the replenishment threshold.

Refresh creates a new publication sequence and, in the current conservative implementation, rotates the signed EC and last-resort Kyber pair together with a fresh one-time pool. This rotates those keys at least as often as the seven-day maximum rather than attempting conditional reuse in the first maintenance implementation.

Expired bindings are rejected. There is no fallback to static GhostLink encryption.

## Relay consumption semantics

For an honest relay:

1. a fetch atomically removes one one-time binding from the active generation and returns it;
2. if no one-time binding remains, the relay returns the reusable fallback binding;
3. the relay never synthesizes a new binding;
4. exact publication retries are idempotent;
5. replacing a generation is atomic.

A malicious relay can replay a signed one-time binding. GhostLink cannot prevent the relay from causing denial of service, but the recipient must not silently treat a replayed one-time key as a reusable last-resort key.

## Private-key consumption

### One-time EC

libsignal removes a used one-time EC private pre-key after successful pre-key message processing.

That mutation remains part of the same durable ratchet transaction as session creation.

### One-time Kyber

libsignal reports Kyber use through `markKyberPreKeyUsed`.

For a one-time Kyber binding, GhostLink may erase the corresponding private KEM record after the successful session-establishment transaction commits.

Non-secret used/base-key replay metadata is retained for the delayed-message retention window.

### Last-resort Kyber

The active last-resort Kyber private key is reusable by design and is not erased after each successful session establishment.

Its used/base-key history remains persistent so repeated base keys fail closed.

The implementation must place an explicit bound on per-key replay-history growth. The reference default is 4096 remembered base keys for one last-resort Kyber/signed-pre-key pair.

Reaching the bound triggers fail-closed behavior for additional fallback establishment and requires a fresh publication generation rather than unbounded vault growth.

Relay-side rate limiting remains required because a relay can otherwise be used to drain one-time bundles and force last-resort use.

## Delayed-message retention

Replacing a generation does not immediately delete its private key material.

A sender may fetch a binding immediately before replacement and the first encrypted message may remain valid for the full GhostLink message TTL.

Current limits are:

- binding maximum lifetime: 7 days;
- message maximum TTL: 7 days;
- accepted clock skew: 5 minutes.

GhostLink therefore retains private material from a retired generation for:

```text
15 days after confirmed replacement
```

This is a conservative rounded window covering the maximum binding lifetime plus message lifetime and clock skew.

The retention window applies to:

- retired signed EC pre-keys;
- retired last-resort Kyber pre-keys;
- unused one-time EC private keys from the retired generation;
- unused one-time Kyber private keys from the retired generation;
- replay metadata needed for retired Kyber keys.

A one-time key already destroyed by successful libsignal consumption is not recreated merely for retention.

## Garbage collection

A private pre-key record may be deleted only when it is not referenced by:

- the active generation;
- a pending publication candidate;
- a retired generation still inside the 15-day retention window.

Garbage collection is deterministic from encrypted lifecycle metadata.

GC executes through the same serialized durable state transaction as other ratchet-store mutations. A retired generation becomes eligible exactly 15 days after its recorded retirement time. Before that boundary a GC pass is a no-op and does not rewrite the vault.

For each eligible generation the engine builds protected identifier sets from every pending generation, the active generation and every retired generation still inside retention. A pre-key record is removed only when its identifier is not referenced by any protected generation. This also preserves safety if historical generations ever share an identifier.

The durable GC transaction removes:

- eligible retired lifecycle entries;
- unused EC one-time private records still present;
- retired signed EC private records;
- retired one-time and last-resort Kyber private records;
- Kyber used/base-key replay metadata associated with removed Kyber identifiers.

One-time records already consumed by libsignal may already be absent and are not recreated.

Before deleting serialized private-key records from the in-memory stores, GhostLink overwrites their current byte buffers as a best-effort reduction of residual process-memory exposure. This is not a secure-erasure guarantee: runtime copies, allocator behavior, filesystem history, storage media and whole-vault backups can retain prior bytes.

If lifecycle metadata is missing, inconsistent, the local clock predates a recorded retirement time, or ownership cannot be proven, GC fails closed and retains the key.

The lifecycle must never choose availability over uncertain secret deletion rules by guessing key ownership.

## Crash-safe publication

A new generation is a two-phase local/relay operation.

### Prepare

Before network publication GhostLink durably stores:

- the new publication sequence;
- the complete private lifecycle metadata;
- every generated private pre-key;
- the exact public bindings to publish;
- a pending-publication marker.

The public output is not considered active locally yet.

### Publish

GhostLink submits the exact prepared generation to GhostNode.

GhostNode accepts:

- the next sequence, replacing the previous generation atomically; or
- an exact byte-for-byte retry of the already accepted sequence.

A different payload for an already accepted sequence is a conflict.

### Commit

After successful relay acknowledgement GhostLink atomically marks the candidate active and records the previous generation's retirement time.

If the process crashes after relay acceptance but before local commit, restart retries the exact pending generation. It must not generate a second payload with the same sequence.

This does not protect against restoring an older valid copy of the whole local vault. That remains the documented trusted-monotonic-state/transparency limitation.

## Vault metadata

The lifecycle implementation requires encrypted metadata in addition to raw libsignal stores.

The vault schema must record at least:

- current publication sequence;
- active generation;
- pending generation when present;
- generation creation/publication/retirement timestamps;
- signed-pre-key role and generation ownership;
- Kyber role: `one_time` or `last_resort`;
- one-time bundle membership;
- replay-history ownership needed for safe GC.

Adding this metadata requires an explicit versioned vault-state migration.

Private material remains inside the existing AES-256-GCM encrypted vault.

## Current implementation status

The ratchet engine now implements the local preparation half of the lifecycle:

- one signed EC pre-key is generated for a publication generation;
- one Kyber/ML-KEM last-resort key is generated for fallback use;
- a bounded set of one-time EC + one-time Kyber pairs is generated;
- complete libsignal one-time bundles share the generation signed EC key;
- the fallback bundle contains no EC one-time key and uses the last-resort Kyber key;
- key material and the pending lifecycle generation are committed atomically to the encrypted vault;
- an existing pending generation blocks replacement;
- the pending generation survives close/reopen.

The production default pool target is 100. The generator is bounded to 256 one-time bundles.

Signed publication staging is now implemented:

- Python signs complete binding-v2 one-time/fallback publications with the enrolled DeviceID key;
- the exact canonical public payload is persisted before network use;
- pending public bundles are reconstructable from persisted libsignal records after restart;
- staged payloads are locally reverified and compared to the pending records before reuse.

Relay publication storage is now implemented:

- GhostNode authenticates control of the target self-certifying DeviceID from its signing public key;
- every binding signature is verified before storage;
- exact same-sequence retry is idempotent;
- conflicting, stale and skipped sequences fail closed;
- SQLite replacement of the active generation and one-time pool is atomic.

The relay does not receive the full GhostID contact bundle for publication authorization. GhostID trust verification remains end-to-end at the sender.

Local acknowledgement commit is now implemented:

- a matching staged pending generation is promoted atomically to active;
- the previous active generation is retained as retired;
- the acknowledgement transition is idempotent across lost RPC responses/restarts;
- unstaged, mismatched, expired or time-inconsistent acknowledgements fail closed;
- retired generations are never silently dropped when the bounded history is full.

Application HTTP publication orchestration is now implemented:

- exact staged payloads are submitted through the canonical GhostNode client;
- relay receipts are parsed with exact fields and strict bounds;
- DeviceID, publication sequence, expiration and one-time count must match local staged state;
- malformed/mismatched receipts do not commit lifecycle state;
- connection loss after relay acceptance leaves the generation pending for exact idempotent retry.

Sender-side publication continuity is now implemented before fetch/pop exposure:

- the encrypted ratchet vault persists the highest publication sequence observed per remote DeviceID;
- session establishment requires the verified binding publication sequence;
- sequence observation and libsignal session creation are one atomic durable transaction;
- equal sequence reuse is idempotent because multiple one-time bundles legitimately share one generation sequence;
- lower sequences fail closed before session state mutation;
- higher sequences become durable only if session establishment succeeds.

A rollback of the entire encrypted vault can still restore older continuity state. Preventing that requires external monotonic state or trusted hardware and remains a separate threat-model limitation.

Relay fetch/pop and anti-drain controls are now implemented:

- requester DeviceID control is proven with a target-bound Ed25519-signed fetch request;
- one authenticated requester consumes at most one one-time binding per target generation;
- retry/concurrency for the same requester is idempotent;
- SQLite one-time removal and allocation persistence are atomic;
- fallback is returned only after the one-time pool is empty;
- remaining one-time count is returned;
- new one-time allocations are rate-limited per target and time window;
- exact publication retry after consumption does not repopulate the pool.

This does not provide Sybil-resistant admission. A requester able to create many DeviceIDs can still consume multiple allocations over time.

Sender-side fetch/session orchestration is now implemented:

- the local enrolled DeviceID signs a target-bound fetch request;
- the HTTP response is parsed with exact fields and strict bounds;
- target and requester DeviceIDs must match the local request;
- the fetched binding must be canonical and verify against `VerifiedContact`;
- relay metadata must match the signed binding;
- the binding is reverified by `RatchetEngineClient`;
- highest-seen remote publication continuity and libsignal session creation commit atomically in the encrypted vault;
- failures never downgrade to static protocol-v2 encryption.

Automatic maintenance is now implemented:

- owner-authenticated relay pool status uses an operation-specific DeviceID signature domain separate from fetch;
- local sequence/expiration remains authoritative;
- the default target is 100 and replenish threshold is 30;
- depletion-only replacement is limited by a one-hour default cooldown;
- a generation with less than 48 hours remaining is refreshed regardless of cooldown;
- existing pending publication is resumed before relay status is consulted;
- each replacement uses the existing durable publication workflow;
- GC runs before maintenance decisions;
- retired generations remain protected for 15 days after confirmed replacement;
- expired retired generations and their unprotected EC/Kyber private material are removed atomically from the encrypted vault;
- Kyber used/base-key metadata is removed with the corresponding retired Kyber record;
- a no-op GC before retention expiry does not rewrite the vault;
- clock rollback before a recorded retirement timestamp fails closed;
- the bounded retired history remains capped at 32 entries after GC rather than accepting a generation that cannot be committed locally.

The following is still pending:

- ratcheted message-envelope and CLI cutover.

## RPC implications

The current `create_prekey_material` method remains a bootstrap/testing primitive.

The production implementation must expose a lifecycle-level operation that prepares a complete publication generation instead of asking Python to call the single-bundle generator 100 times independently.

Publication acknowledgement and GC are explicit lifecycle operations so crash recovery and retention decisions do not depend on process memory.

The RPC remains local stdio only.

## Relay API implications

The GhostNode pre-key API now supports:

- atomic generation replacement;
- exact-retry idempotency;
- monotonic sequence conflict detection;
- atomic pop of one-time bindings;
- reusable fallback binding;
- remaining one-time count;
- active generation sequence and expiration;
- bounded request sizes and pool sizes;
- requester DeviceID proof plus target-window allocation rate limiting.

GhostNode still stores public signed material only. It never receives private pre-key state.

## Required tests before relay cutover

Implementation is not complete until tests cover:

1. initial generation contains 100 unique one-time bindings plus one fallback;
2. every one-time binding shares the generation sequence and current signed pre-key;
3. every one-time EC and Kyber identifier is unique inside the generation;
4. fallback contains no EC one-time key and uses the designated last-resort Kyber key;
5. relay pop is atomic under concurrent fetches;
6. exact publication retry is idempotent;
7. conflicting same-sequence publication is rejected;
8. lower remote sequence is rejected after a higher sequence was observed;
9. pool threshold creates a new complete generation;
10. seven-day signed/last-resort rotation creates a new generation;
11. old private keys remain usable for delayed messages inside the retention window;
12. GC removes retired keys after the retention window;
13. GC never removes active or pending-generation keys;
14. one-time EC consumption survives restart;
15. one-time Kyber use and anti-reuse metadata survive restart;
16. last-resort Kyber can establish multiple distinct sessions without accepting repeated base keys;
17. crash after local prepare resumes the same publication;
18. crash after relay accept but before local commit retries exactly;
19. malformed lifecycle metadata fails closed;
20. existing static protocol-v2 runtime remains untouched until the later explicit ratchet cutover.

## Security notes

The relay still controls availability.

A malicious relay can:

- refuse publication;
- ignore honest allocation semantics and drain or withhold one-time bindings;
- force fallback use;
- replay a still-valid signed binding;
- freeze a first-time observer on a still-valid older generation.

The signed generation sequence improves continuity for observers that have already seen a newer sequence, but is not key transparency.

GhostLink remains pre-alpha. These lifecycle rules do not replace an independent cryptographic/protocol audit.

## Sources

Primary references:

- Signal PQXDH specification: https://signal.org/docs/specifications/pqxdh/
- Signal X3DH specification: https://signal.org/docs/specifications/x3dh/
- Official libsignal repository: https://github.com/signalapp/libsignal
