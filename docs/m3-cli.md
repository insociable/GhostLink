# GhostLink CLI — Ratcheted Protocol v3

The reference command-line runtime uses GhostLink protocol v3 for user-facing `send` and
`inbox`.

Static protocol v2 is not an automatic fallback. The retained `node-smoke` command is
explicitly a legacy static-v2 diagnostic.

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

New profiles are profile v3. Their encrypted secret payload contains independent random
32-byte keys for the ratchet vault and the encrypted contact trust store.

Existing profile-v1/v2 files remain readable. Upgrade them explicitly before using current
ratcheted/contact-trust commands:

```bash
ghostlink profile-upgrade --profile alice.ghost
```

Migration atomically replaces only the encrypted profile file and preserves an existing
v2 ratchet-vault key.

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
unlock profile v3
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

Replay-cache rollback or deletion can weaken suppression for still-valid captured
messages and remains a documented local-state limitation.

## Local files

For a profile named `alice.ghost`, the development runtime normally uses:

- `alice.ghost` — password-encrypted profile v3;
- `alice.ghost.contacts` — authenticated-encrypted local contact trust store;
- `alice.ghost.ratchet` — encrypted libsignal ratchet vault;
- `alice.ghost.state.sqlite3` — replay cache.

The ratchet-vault and contact-store keys are independent and are stored only inside the
encrypted profile.

Rollback of the complete profile/contact-store pair is not prevented by the current
format and remains separate client-state hardening work.

## Relay access

The optional shared relay Bearer token is loaded from a local file. Set
`GHOSTLINK_NODE_TOKEN_FILE` to that file's path; the token value itself must not be
placed in argv or an environment variable.

For protocol-v3 message operations it is only an additional coarse access-control layer.
The client separately signs each POST/GET/DELETE request with the local DeviceID signing
key; GhostNode verifies method/path/body binding, freshness and request-ID replay.

The Bearer token does not replace DeviceID request authentication, end-to-end libsignal,
or local human contact verification. Legacy static-v2 diagnostic routes remain
bearer-only.

## Diagnostic smoke

```bash
ghostlink node-smoke --node https://node.example.net
```

This command intentionally exercises the retained static-v2 compatibility path. It is not
called as a fallback by ratcheted `send` or `inbox`.

## Security status

GhostLink remains pre-alpha. Relay/client anti-rollback hardening, key transparency, live
external validation of the reference TLS ingress, complete device revocation/recovery,
legacy-v2 hardening/removal and independent cryptographic review remain open.
