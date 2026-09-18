# GhostLink CLI — Ratcheted Protocol v3

The reference command-line runtime now uses GhostLink protocol v3 for user-facing `send` and `inbox`.

Static protocol v2 is not an automatic fallback. The retained `node-smoke` command is explicitly a legacy static-v2 diagnostic.

## Local prerequisites

Install the Python package and build the pinned local Node/libsignal engine:

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

New profiles are profile v2 and contain an independent encrypted 32-byte ratchet-vault master key.

For an existing legacy profile:

```bash
ghostlink profile-upgrade --profile alice.ghost
```

Migration is explicit and atomically replaces only the encrypted profile file.

## Exchange verified contacts

```bash
ghostlink contact-export --profile alice.ghost --output alice.contact
ghostlink contact-export --profile bob.ghost --output bob.contact

ghostlink contact-verify bob.contact
```

The contact bundle must still be verified through the intended out-of-band human trust process. Internal bundle validity alone does not prove the human identity of the contact.

## Publish/maintain pre-keys

A device must have an active relay pre-key generation before another device can establish first contact:

```bash
ghostlink prekey-sync \
  --profile bob.ghost \
  --node https://node.example.net
```

The command uses the existing fail-closed maintenance flow: publication receipt validation, sequence continuity, replenishment/refresh policy and delayed-key garbage collection.

`send` and `inbox` also run maintenance for their own device, but a first-contact recipient must already have published pre-keys before the sender fetches them.

## Send a ratcheted message

```bash
ghostlink send \
  --profile alice.ghost \
  --contact bob.contact \
  --node https://node.example.net \
  "Hello Bob"
```

The send path is:

```text
unlock profile v2
  -> open encrypted ratchet vault
  -> maintain local pre-keys
  -> check durable session for Bob
  -> if absent: authenticated pre-key fetch
  -> VerifiedContact binding verification
  -> highest-seen sequence enforcement
  -> libsignal session establishment
  -> protocol-v3 context-bound encryption
  -> POST /v3/messages
```

An existing durable session is reused. The client does not fetch a new pre-key on every send.

Any bootstrap or ratchet failure aborts the command. It does not send a static-v2 message.

## Receive ratcheted messages

```bash
ghostlink inbox \
  --profile bob.ghost \
  --contact alice.contact \
  --node https://node.example.net
```

For each candidate from the expected sender, the inbox:

1. suppresses an ID already retained in the authenticated replay cache without touching libsignal state;
2. reconstructs the canonical v3 relay context;
3. performs context-bound libsignal decryption transactionally;
4. rolls ratchet state back if ciphertext/context authentication fails;
5. validates message lifecycle;
6. atomically records the authenticated replay ID;
7. validates UTF-8 for the CLI text surface;
8. only then prints plaintext;
9. deletes the relay copy unless `--keep` is used.

A successfully authenticated incoming libsignal PreKey message creates durable session state. A later reply reuses that persisted session across CLI process restarts.

## Replay state

The default replay database for `bob.ghost` is:

```text
bob.ghost.state.sqlite3
```

Override it with:

```bash
ghostlink inbox \
  --profile bob.ghost \
  --contact alice.contact \
  --node https://node.example.net \
  --state /secure/path/bob-replay.sqlite3
```

Replay-cache rollback or deletion can weaken suppression for still-valid captured messages and remains a documented local-state limitation.

## Local files

For a profile named `alice.ghost`, the development runtime normally uses:

- `alice.ghost` — password-encrypted profile v2;
- `alice.ghost.ratchet` — encrypted libsignal ratchet vault;
- `alice.ghost.state.sqlite3` — replay cache.

The ratchet vault master key is inside the encrypted profile, not in the vault file.

## Relay access

`GHOSTLINK_NODE_TOKEN` remains optional shared relay access control when configured by GhostNode.

It is not per-device cryptographic authentication and does not replace end-to-end verification.

## Diagnostic smoke

```bash
ghostlink node-smoke --node https://node.example.net
```

This command intentionally exercises the retained static-v2 compatibility path and prints that it is a legacy V2 smoke test. It is not called as a fallback by ratcheted `send` or `inbox`.

## Security status

The CLI cutover demonstrates the implemented v3/libsignal path across separate process invocations and persistent encrypted vault state.

GhostLink remains pre-alpha. General per-device message-relay authentication, relay/client anti-rollback hardening, key transparency, production ingress hardening, revocation/recovery and independent cryptographic review remain open.
