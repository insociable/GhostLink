# GhostLink

> Trust mathematics, not servers.

GhostLink is an open-source, self-hostable secure messaging project inspired by cypherpunk principles.

## Current milestone

**M3 — Two-client demonstration**

The repository now contains a complete automated M3 path:

- self-certifying GhostID identities;
- separately authorized device identities;
- signed device certificates;
- portable verified public contact bundles;
- local end-to-end message encryption;
- a ciphertext-only GhostNode relay;
- optional persistent SQLite relay storage;
- password-encrypted local client profiles;
- a command-line client for init, contact exchange, send and inbox;
- a Docker/Compose deployment path for GhostNode;
- an integration test where two independent client profiles exchange and decrypt a message through GhostNode.

The next protocol priorities are per-device relay authentication, replay protection, timestamps/expiration, metadata reduction and a ratcheting session protocol.

## Security status

GhostLink is **experimental and not ready for real-world sensitive communications**.

It has not been independently audited and does not yet provide forward secrecy, a ratcheting session protocol, replay protection, per-device relay authentication, robust abuse controls, or a complete human contact-verification UX.

A valid contact bundle proves internal cryptographic consistency. It does not by itself prove that the GhostID belongs to the human the user intended to contact.

## Principles

- privacy by design;
- security by design;
- open source;
- self-hosting;
- minimal metadata;
- documented decisions;
- no custom cryptographic algorithms.

## M3 quick start

Install dependencies:

```bash
poetry install
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

Start a local development GhostNode:

```bash
poetry run ghostnode
```

Check it:

```bash
poetry run ghostlink node-health --node http://127.0.0.1:8000
```

See [docs/m3-cli.md](docs/m3-cli.md) for the two-client workflow and [deploy/oracle/README.md](deploy/oracle/README.md) for the container deployment runbook.

## Repository layout

```text
src/ghostlink/       Python package
tests/               Automated tests
docs/                Architecture and security documentation
deploy/              Deployment configuration and runbooks
.github/workflows/   Continuous integration
```

## Development

Requirements:

- Python 3.12+
- Poetry 1.8+

```bash
poetry install
poetry run pytest
poetry run ruff check .
poetry run mypy src
```

The CI also validates the Compose configuration and builds the GhostNode container image.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
