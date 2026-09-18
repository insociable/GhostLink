# GhostLink M3 CLI

The M3 command-line client is the first user-facing path through the GhostLink protocol.

It is intentionally narrow: one encrypted local profile, one verified contact bundle, one GhostNode, and encrypted text messages.

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

After a message is successfully authenticated, decrypted, and decoded as UTF-8, the M3 client deletes its relay copy. Use `--keep` during development to leave the relay copy in place.

## Security boundary

The profile password is read interactively and is never accepted as a CLI argument.

The client:

- unlocks keys locally;
- verifies the contact locally;
- encrypts plaintext locally;
- sends only ciphertext to GhostNode;
- retrieves ciphertext from GhostNode;
- decrypts locally;
- deletes the relay copy only after successful processing.

M3 still supports only one explicitly supplied contact per inbox command. A contact database, message history, replay protection, authenticated relay access, metadata reduction, ratcheting, notifications, and mobile UX remain future work.

GhostLink is experimental and not ready for sensitive real-world communications.
