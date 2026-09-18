# GhostLink M3 CLI — Protocol v2

The M3 command-line client is the first user-facing path through the GhostLink protocol.

It uses protocol v2 for send, inbox, and the live GhostNode smoke test.

## Commands

Create Alice and Bob:

```bash
ghostlink init --profile alice.ghost
ghostlink init --profile bob.ghost
```

Export public contact bundles:

```bash
ghostlink contact-export --profile alice.ghost --output alice.contact
ghostlink contact-export --profile bob.ghost --output bob.contact
```

Verify a received contact bundle:

```bash
ghostlink contact-verify bob.contact
```

Check the relay:

```bash
ghostlink node-health --node https://node.example.net
```

Run an ephemeral protocol-v2 E2EE round trip:

```bash
ghostlink node-smoke --node https://node.example.net
```

Alice sends Bob a message:

```bash
ghostlink send \
  --profile alice.ghost \
  --contact bob.contact \
  --node https://node.example.net \
  "Hello Bob"
```

Bob receives it:

```bash
ghostlink inbox \
  --profile bob.ghost \
  --contact alice.contact \
  --node https://node.example.net
```

## Replay state

The inbox maintains a persistent SQLite replay cache.

For `bob.ghost`, the default state path is:

```text
bob.ghost.state.sqlite3
```

Override it when needed:

```bash
ghostlink inbox \
  --profile bob.ghost \
  --contact alice.contact \
  --node https://node.example.net \
  --state /secure/path/bob-replay.sqlite3
```

A successfully authenticated message ID is recorded atomically before plaintext is displayed. An already-recorded ID is suppressed and is never displayed twice.

After successful processing, the client deletes the relay copy unless `--keep` is supplied for development.

## Protocol-v2 validation

Before displaying text, the client:

- verifies the expected sender device;
- authenticates and decrypts the ciphertext locally;
- compares encrypted inner metadata with relay-visible outer metadata;
- validates creation time, expiration, and maximum lifetime;
- verifies text is valid UTF-8;
- atomically records the message ID in the replay cache;
- only then exposes the plaintext.

## Security boundary

The profile password is read interactively and is never accepted as a CLI argument.

The client keeps identity/device private keys local. GhostNode receives ciphertext and routing/lifecycle metadata only.

The shared GhostNode Bearer token is relay access control, not per-device cryptographic authentication.

M3 still supports one explicitly supplied contact per inbox command. Conversation history, per-device relay authentication, ratcheting, forward secrecy, notifications, desktop/mobile UX, and metadata reduction remain future work.

GhostLink is experimental and is not yet suitable for sensitive real-world communications without independent cryptographic review.