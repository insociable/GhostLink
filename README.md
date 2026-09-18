# GhostLink

> Trust mathematics, not servers.

GhostLink is an open-source, self-hostable secure messaging project inspired by cypherpunk principles.

## Current milestone

**M5 — Security hardening / ratcheted transport**

GhostLink is still pre-alpha, but the repository now contains substantially more than the original two-client demonstration:

- self-certifying GhostID and DeviceID identities;
- identity-signed device authorization certificates;
- cryptographically validated public contact bundles;
- password-encrypted local profile v4 with independent ratchet/contact/rollback-coordination secrets;
- persistent replay protection for authenticated message IDs;
- ciphertext-only GhostNode relay with optional SQLite persistence;
- ratcheted protocol-v3 messaging used by the current `send` / `inbox` CLI runtime;
- retired static protocol-v2 network relay; current runtime exposes ratcheted v3 messages plus v2-namespaced pre-key APIs;
- a local Node/TypeScript ratchet engine using pinned official `@signalapp/libsignal-client`;
- encrypted persistent libsignal session and pre-key vault state;
- signed GhostID/DeviceID-to-libsignal pre-key bindings;
- crash-safe pre-key publication, fetch, highest-seen continuity, replenishment/rotation and 15-day retired-key GC;
- explicit ratcheted **message protocol v3** on separate `/v3/messages` relay routes;
- DeviceID-signed protocol-v3 relay requests with timestamp/request-ID replay protection;
- context-bound ratchet decryption that rolls session state back when relay-visible metadata is tampered with;
- real Python ↔ Node/libsignal ↔ GhostNode end-to-end tests, including restart continuity;
- reviewed Oracle public HTTPS stack with Caddy, 443-only exposure and file-backed relay-token secrets;
- Fingerprint v2 human contact verification with encrypted local `imported` / `verified` / `changed` trust state;
- versioned public contact QR payloads and standard SVG QR export.

### Runtime status

The current user-facing `send` and `inbox` commands use **ratcheted protocol v3**.

A failed ratchet bootstrap, encrypt or decrypt does not trigger static-v2 messaging. The historical `/v2/messages...` network relay and `node-smoke` command have been removed from the current runtime.

## Security status

GhostLink is **experimental and not ready for real-world sensitive communications**.

The ratchet path exercises forward-secrecy/post-compromise behavior through the pinned official libsignal implementation, but GhostLink has **not** undergone an independent cryptographic/protocol audit and does not claim production security.

Important remaining gaps include:

- relay database anti-rollback protection;
- key transparency;
- public Caddy/TLS reference deployment implemented, but live external certificate/closed-port verification is still required;
- Sybil-resistant abuse controls;
- complete device revocation/recovery;
- independent cryptographic/protocol review.

A valid contact bundle proves internal cryptographic consistency. It does not by itself prove that the GhostID belongs to the human the user intended to contact.

See [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md) for the current security boundary.

## Protocol status

| Path | Status |
| --- | --- |
| Static message protocol v2 | Historical local codec only; `/v2/messages...` runtime retired |
| Ratcheted message protocol v3 | Implemented/tested; current `send` / `inbox` CLI runtime |
| Ratchet pre-key lifecycle | Publication, fetch, continuity, maintenance and GC implemented |
| Protocol v1 | Removed from runtime |

Specifications:

- [Message v2](docs/specifications/message-v2.md)
- [Ratcheted message v3](docs/specifications/message-v3.md)
- [Relay v2](docs/specifications/relay-v2.md)
- [Ratcheted relay v3](docs/specifications/relay-v3.md)
- [Ratchet pre-key lifecycle](docs/specifications/ratchet-prekey-lifecycle.md)
- [Local ratchet RPC](docs/specifications/ratchet-local-rpc.md)
- [Client-state rollback checkpoints](docs/specifications/client-state-rollback.md)

## Principles

- privacy by design;
- security by design;
- open source;
- self-hosting;
- minimal metadata;
- documented decisions;
- fail closed;
- no custom cryptographic algorithms;
- no silent ratchet-to-static downgrade.

## Current CLI quick start

Install Python dependencies and build the pinned local ratchet engine:

```bash
poetry install
cd ratchet-engine
npm ci
npm run build
cd ..
```

Create a local encrypted profile:

```bash
poetry run ghostlink init --profile alice.ghost
```

Export the public contact bundle:

```bash
poetry run ghostlink contact-export \
  --profile alice.ghost \
  --output alice.contact
```

Export the same public contact data as a standard SVG QR code:

```bash
poetry run ghostlink contact-export-qr \
  --profile alice.ghost \
  --output alice-contact.svg
```

A scanner returns the public `ghostlink:contact:1:...` payload. Importing that payload
creates an `imported` record only; it does **not** mark the human identity as verified:

```bash
poetry run ghostlink contact-import-qr \
  --profile bob.ghost \
  --label Alice \
  --payload 'ghostlink:contact:1:...'
```

After comparing the complete Fingerprint v2 through an authenticated out-of-band channel,
record the explicit human verification with `contact-trust`.

If a later scan for that saved contact carries a different GhostID, use
`contact-update-qr`; GhostLink moves the record to `changed`, keeps the previous
identity pinned and blocks trusted messaging until the candidate is verified or rejected.

Start a local development GhostNode:

```bash
poetry run ghostnode
```

Check it:

```bash
poetry run ghostlink node-health --node http://127.0.0.1:8000
```

Before another user can bootstrap a first ratcheted session to a device, that device must publish/maintain its pre-key pool:

```bash
poetry run ghostlink prekey-sync \
  --profile alice.ghost \
  --node http://127.0.0.1:8000
```

Existing profile-v1/v2/v3 files remain readable, but the current profile-v4 state identity requires an explicit one-time migration:

```bash
poetry run ghostlink profile-upgrade --profile alice.ghost
```

`send` and `inbox` use protocol v3 only. The historical static-v2 network relay is no longer exposed.

See [docs/m3-cli.md](docs/m3-cli.md) for the current ratcheted CLI workflow and [deploy/oracle/README.md](deploy/oracle/README.md) for the container deployment runbook.

## Repository layout

```text
src/ghostlink/       Python application/protocol code
ratchet-engine/      Local TypeScript/libsignal engine
tests/               Automated Python and cross-language tests
docs/                Architecture, protocol and security documentation
deploy/              Deployment configuration and runbooks
.github/workflows/   Continuous integration
```

## Development

Requirements:

- Python 3.12+
- Poetry 1.8+
- Node.js for ratchet-engine development/tests

```bash
poetry install
poetry run pytest
poetry run ruff check .
poetry run mypy src
```

CI additionally:

- audits/builds/tests the pinned ratchet-engine dependencies;
- runs Python-to-libsignal cross-language smoke tests;
- validates Docker Compose;
- builds and exercises the GhostNode container.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
