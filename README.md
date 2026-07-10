# GhostLink

> Trust mathematics, not servers.

GhostLink is an open-source, self-hostable secure messaging project inspired by cypherpunk principles.

## Current milestone

**M0 — Foundation**

The first technical target is deliberately narrow:

- one relay server;
- two desktop clients;
- one end-to-end encrypted text message;
- no plaintext message content available to the relay.

## Security status

GhostLink is **experimental and not ready for real-world sensitive communications**.

The project currently provides only an initial cryptographic proof of concept. It has not been independently audited and does not yet implement forward secrecy, replay protection, secure key verification, encrypted local storage, or a ratcheting protocol.

## Principles

- privacy by design;
- security by design;
- open source;
- self-hosting;
- minimal metadata;
- documented decisions;
- no custom cryptographic algorithms.

## Repository layout

```text
src/ghostlink/       Python package
tests/               Automated tests
docs/                Architecture and security documentation
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

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
