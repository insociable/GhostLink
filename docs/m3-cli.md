# GhostLink CLI — Ratcheted Protocol v3

The reference command-line runtime uses GhostLink protocol v3 for user-facing `send` and
`inbox`.

The historical static protocol-v2 message relay has been retired. Ratcheted protocol v3 is the only current network message path.

## Local prerequisites

Install the Python package and build the exact-pinned local Node/libsignal engine:

```bash
poetry install
cd ratchet-engine
npm ci
npm run build
cd ..
```

The ratchet engine is a local child process. It does not expose a network socket.

## Create profiles

```bash
ghostlink init --profile alice.ghost
ghostlink init --profile bob.ghost
```

New profiles are profile v4. Their encrypted secret payload contains independent random
32-byte keys for the ratchet vault, encrypted contact trust store and rollback-state
coordination, plus a random 128-bit client-state identifier.

Existing profile-v1/v2/v3 files remain readable. Upgrade them explicitly before using the
current rollback-aware local-state format:

```bash
ghostlink profile-upgrade --profile alice.ghost
```

Migration atomically replaces only the encrypted profile file, preserves existing
ratchet/contact-store keys, and adds only missing state-coordination material.

## Exchange and verify contacts

A Contact Bundle or QR proves cryptographic consistency only. It does not prove that the
GhostID belongs to the intended human.

Export a public bundle or its versioned QR representation:

```bash
ghostlink contact-export --profile alice.ghost --output alice.contact
ghostlink contact-export-qr --profile alice.ghost --output alice-contact.svg
```

A received bundle can be inspected without persisting human trust:

```bash
ghostlink contact-verify alice.contact
```

Persisted contacts always start as `imported`:

```bash
ghostlink contact-import \
  --profile bob.ghost \
  --label Alice \
  alice.contact
```

A desktop/mobile scanner may instead provide the decoded
`ghostlink:contact:1:...` text:

```bash
ghostlink contact-import-qr \
  --profile bob.ghost \
  --label Alice \
  --payload 'ghostlink:contact:1:...'
```

Neither path grants human trust. Show the record and compare the complete Fingerprint v2
through an authenticated out-of-band channel:

```bash
ghostlink contact-show --profile bob.ghost <contact-id>

ghostlink contact-trust \
  --profile bob.ghost \
  --fingerprint 'GLF2:....' \
  <contact-id>
```

Only that explicit successful comparison moves the local record to `verified`.

If new public material arrives later, update the same record:

```bash
ghostlink contact-update --profile bob.ghost <contact-id> alice-new.contact

ghostlink contact-update-qr \
  --profile bob.ghost \
  <contact-id> \
  --payload 'ghostlink:contact:1:...'
```

A new device under the same GhostID keeps the record `verified`. A different GhostID for
an already verified record is quarantined as `changed`: the previous identity remains
pinned, the candidate fingerprint is displayed, and trusted messaging fails closed until
the candidate is explicitly verified or rejected.

Reject a candidate identity change with:

```bash
ghostlink contact-reject-change --profile bob.ghost <contact-id>
```

## Publish/maintain pre-keys

A device must have an active relay pre-key generation before another device can establish
first contact:

```bash
ghostlink prekey-sync \
  --profile bob.ghost \
  --node https://node.example.net
```

The command uses the fail-closed maintenance flow: publication receipt validation,
sequence continuity, replenishment/refresh policy and delayed-key garbage collection.

`send` and `inbox` also maintain their own device's pre-keys, but a first-contact
recipient must already have published pre-keys before the sender fetches them.

## Send a ratcheted message

The normal trusted path uses a persisted human-verified contact ID:

```bash
ghostlink send \
  --profile alice.ghost \
  --contact-id <bob-contact-id> \
  --node https://node.example.net \
  "Hello Bob"
```

The send path is:

```text
unlock profile v4
  -> open encrypted contact store
  -> require local state = verified
  -> open encrypted ratchet vault
  -> maintain local pre-keys
  -> check durable session for the validated Bob device
  -> if absent: authenticated pre-key fetch
  -> validate GhostID/DeviceID binding and highest-seen publication sequence
  -> libsignal session establishment
  -> protocol-v3 context-bound encryption
  -> DeviceID-sign POST /v3/messages
```

An existing durable session is reused. Any bootstrap or ratchet failure aborts the
command; GhostLink does not fall back to static v2.

The legacy `--contact <bundle>` option remains a diagnostic compatibility path and prints
that it bypasses persisted human trust. It should not be used as the normal trusted
workflow.

## Receive ratcheted messages

```bash
ghostlink inbox \
  --profile bob.ghost \
  --contact-id <alice-contact-id> \
  --node https://node.example.net
```

The mailbox GET and delivered-message DELETE operations are signed by the local recipient
DeviceID before GhostNode accepts them.

For each candidate from the expected sender, the inbox:

1. suppresses an ID already retained in the authenticated replay cache without touching
   libsignal state;
2. reconstructs the canonical v3 relay context;
3. performs context-bound libsignal decryption transactionally;
4. rolls ratchet state back if ciphertext/context authentication fails;
5. validates message lifecycle;
6. atomically records the authenticated replay ID;
7. validates UTF-8 for the CLI text surface;
8. only then prints plaintext;
9. deletes the relay copy unless `--keep` is used.

A successfully authenticated incoming libsignal PreKey message creates durable session
state. A later reply reuses that persisted session across CLI process restarts.

## Replay state

The default replay database for `bob.ghost` is:

```text
bob.ghost.state.sqlite3
```

Override it with:

```bash
ghostlink inbox \
  --profile bob.ghost \
  --contact-id <alice-contact-id> \
  --node https://node.example.net \
  --state /secure/path/bob-replay.sqlite3
```

The user replay cache is rollback-aware in the current CLI runtime. Legacy replay
databases require explicit `replay-state-upgrade` migration before use. The development
SQLite witness still shares the filesystem rollback domain, so whole-snapshot protection
is not claimed.

## Local files

For a profile named `alice.ghost`, the development runtime normally uses:

- `alice.ghost` — password-encrypted profile v4;
- `alice.ghost.contacts` — authenticated-encrypted, rollback-aware local contact trust store;
- `alice.ghost.ratchet` — encrypted, rollback-aware libsignal ratchet/highest-seen vault;
- `alice.ghost.state.sqlite3` — rollback-aware replay cache;
- `alice.ghost.witness.sqlite3` — development monotonic witness for coordinated local state.

The ratchet-vault, contact-store and state-coordination keys are independent and are
stored only inside the encrypted profile.

Current contact-store opens verify revision/digest freshness against the witness and fail
closed on rollback, divergence or a missing store after witness initialization. Legacy
contact stores require explicit `contact-store-upgrade` migration.

Legacy state enrollment is explicit:

```bash
ghostlink contact-store-upgrade --profile alice.ghost
ghostlink replay-state-upgrade --profile alice.ghost
ghostlink ratchet-vault-upgrade --profile alice.ghost
```

Normal ratcheted commands refuse a legacy ratchet vault rather than silently migrating it.

The SQLite witness is development/reference protection only: a whole-filesystem snapshot
can roll it back together with the protected state. Contact, replay, and
ratchet/highest-seen component rollback detection is implemented when that witness remains
current.

## Relay access

The optional shared relay Bearer token is loaded from a local file. Set
`GHOSTLINK_NODE_TOKEN_FILE` to that file's path; the token value itself must not be
placed in argv or an environment variable.

For protocol-v3 message operations it is only an additional coarse access-control layer.
The client separately signs each POST/GET/DELETE request with the local DeviceID signing
key; GhostNode verifies method/path/body binding, freshness and request-ID replay.

The Bearer token does not replace DeviceID request authentication, end-to-end libsignal,
or local human contact verification.

## Security status

GhostLink remains pre-alpha. Relay/client anti-rollback hardening, key transparency, live
external validation of the reference TLS ingress, complete device revocation/recovery,
independent cryptographic review remain open.
