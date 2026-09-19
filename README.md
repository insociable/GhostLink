# GhostLink

**Open-source secure messaging / Messagerie sécurisée open source**

[Français](#français) · [English](#english) · [Sécurité--security](#sécurité--security) · [Démarrage--quick-start](#démarrage--quick-start)

---

## Français

GhostLink est un projet **open source de messagerie chiffrée de bout en bout et auto-hébergeable**. GhostNode n'a pas besoin d'accéder au contenu en clair des messages ; les métadonnées qu'il peut observer et les limites de cette propriété sont documentées explicitement dans le modèle de menace.

Le projet est actuellement en **pré-alpha**. Il est activement développé et testé, mais n'est pas encore destiné à des communications sensibles en production.

### État actuel

Le runtime utilisateur utilise le **protocole de messages v3 avec ratchet**. Le transport statique v2 a été retiré du runtime réseau.

Fonctionnalités déjà en place :

- identités auto-certifiantes **GhostID** et **DeviceID** ;
- autorisation des appareils signée par l'identité ;
- profils locaux v5 chiffrés par mot de passe ;
- moteur de ratchet local basé sur l'implémentation officielle `@signalapp/libsignal-client` ;
- sessions et prekeys libsignal persistantes et chiffrées ;
- publication, récupération, rotation et maintenance des prekeys ;
- relais **GhostNode** ne manipulant que du ciphertext, avec persistance SQLite optionnelle ;
- protection contre le replay et déduplication des messages, persistantes lorsque l'état SQLite correspondant est utilisé ;
- requêtes v3 signées par DeviceID avec contrôle du timestamp et des identifiants de requête ;
- coordination d'état sensible au rollback, avec détection lorsque le witness monotone reste plus récent que l'état restauré ;
- contacts publics versionnés, export/import par QR code et vérification humaine **Fingerprint v2** ;
- états de confiance locaux `imported`, `verified` et `changed` ;
- cycle de vie monotone des appareils ;
- récupération d'appareil explicite et résistante aux interruptions via `device-recover` ;
- tests de bout en bout Python ↔ Node/libsignal ↔ GhostNode, y compris la continuité après redémarrage ;
- déploiement de référence HTTPS avec Caddy.

La documentation de sécurité et le modèle de menace restent la référence pour comprendre précisément ce que GhostLink protège — et ce qu'il ne protège pas encore.

---

## English

GhostLink is an **open-source, self-hostable end-to-end encrypted messaging project**. GhostNode does not need access to message plaintext; relay-visible metadata and the limits of that property are documented explicitly in the threat model.

The project is currently **pre-alpha**. It is under active development and testing, but is not yet intended for production use with sensitive communications.

### Current status

The user-facing runtime uses **ratcheted message protocol v3**. The historical static-v2 network transport has been retired.

Implemented building blocks include:

- self-certifying **GhostID** and **DeviceID** identities;
- identity-signed device authorization;
- password-encrypted local profile v5;
- a local ratchet engine using the pinned official `@signalapp/libsignal-client`;
- encrypted persistent libsignal sessions and pre-key state;
- pre-key publication, retrieval, rotation and maintenance;
- ciphertext-only **GhostNode** relay with optional SQLite persistence;
- replay protection and message deduplication, persistent when the corresponding SQLite-backed state is used;
- DeviceID-signed v3 relay requests with timestamp/request-ID replay protection;
- rollback-aware state continuity controls that detect stale state only while the monotonic witness remains newer;
- versioned public contacts, QR import/export and **Fingerprint v2** human verification;
- local `imported` / `verified` / `changed` contact trust state;
- monotonic device lifecycle state;
- crash-resumable device recovery through `device-recover`;
- Python ↔ Node/libsignal ↔ GhostNode end-to-end tests, including restart continuity;
- a Caddy-based HTTPS reference deployment.

---

## Sécurité / Security

GhostLink est **expérimental** et n'a pas fait l'objet d'un audit cryptographique/protocolaire indépendant.

GhostLink is **experimental** and has not undergone an independent cryptographic or protocol audit.

The ratcheted messaging path uses the official libsignal implementation and is designed to fail closed: a ratchet bootstrap, encryption or decryption failure does **not** silently fall back to static-v2 messaging.

Important remaining work includes:

- production relay monotonic witnessing outside the relay host/volume snapshot domain;
- key transparency;
- Sybil-resistant abuse controls;
- independent cryptographic/protocol review;
- continued hardening and external deployment validation.

A cryptographically valid contact bundle proves internal consistency. It does not, by itself, prove that a GhostID belongs to the human the user intended to contact.

See [SECURITY.md](SECURITY.md), [docs/threat-model.md](docs/threat-model.md), [docs/security-assurance-matrix.md](docs/security-assurance-matrix.md) and [docs/roadmap.md](docs/roadmap.md).

---

## Protocol status

| Component | Status |
| --- | --- |
| Message protocol v3 | Implemented and used by current `send` / `inbox` runtime |
| Ratcheted relay v3 | Implemented and tested |
| Ratchet pre-key lifecycle | Publication, fetch, continuity, replenishment/rotation and GC implemented |
| Static message protocol v2 | Historical local codec only; network runtime retired |
| Protocol v1 | Removed from runtime |
| Device recovery / revocation | Crash-resumable recovery, relay lifecycle publication and stale-device rejection implemented; discovery remains relay-scoped rather than global |

Specifications:

- [Message v2](docs/specifications/message-v2.md)
- [Ratcheted message v3](docs/specifications/message-v3.md)
- [Relay v2](docs/specifications/relay-v2.md)
- [Ratcheted relay v3](docs/specifications/relay-v3.md)
- [Ratchet pre-key lifecycle](docs/specifications/ratchet-prekey-lifecycle.md)
- [Local ratchet RPC](docs/specifications/ratchet-local-rpc.md)
- [Client-state rollback checkpoints](docs/specifications/client-state-rollback.md)

---

## Principes / Principles

- privacy by design;
- security by design;
- open source;
- self-hosting;
- explicit documentation of relay-visible metadata and traffic-analysis limits;
- documented protocol and security decisions;
- fail-closed behavior;
- no custom cryptographic algorithms;
- no silent ratchet-to-static downgrade.

---

## Démarrage / Quick start

### Requirements

- Python 3.12+
- Poetry 1.8+
- Node.js for the local ratchet engine

Install Python dependencies and build the ratchet engine:

```bash
poetry install
cd ratchet-engine
npm ci
npm run build
cd ..
```

Create an encrypted local profile:

```bash
poetry run ghostlink init --profile alice.ghost
```

Start a local development GhostNode:

```bash
poetry run ghostnode
```

Check the node:

```bash
poetry run ghostlink node-health --node http://127.0.0.1:8000
```

Publish and maintain the local pre-key pool:

```bash
poetry run ghostlink prekey-sync \
  --profile alice.ghost \
  --node http://127.0.0.1:8000
```

Export the public contact bundle:

```bash
poetry run ghostlink contact-export \
  --profile alice.ghost \
  --output alice.contact
```

Export the same public contact as an SVG QR code:

```bash
poetry run ghostlink contact-export-qr \
  --profile alice.ghost \
  --output alice-contact.svg
```

Legacy profile v1/v2/v3/v4 files remain readable. Upgrade them explicitly to lifecycle-aware profile v5:

```bash
poetry run ghostlink profile-upgrade --profile alice.ghost
```

Rotate the DeviceID and rebuild linked local ratchet state through the crash-resumable recovery transaction:

```bash
poetry run ghostlink device-recover --profile alice.ghost --node https://your-ghostnode.example
```

For the complete CLI workflow, see [docs/m3-cli.md](docs/m3-cli.md). For deployment, see [deploy/oracle/README.md](deploy/oracle/README.md).

---

## Repository layout

```text
src/ghostlink/       Python application, protocol and CLI
ratchet-engine/      Local TypeScript/libsignal engine
tests/               Python and cross-language automated tests
docs/                Architecture, protocol and security documentation
deploy/              Deployment configuration and runbooks
.github/workflows/   Continuous integration
```

## Development

```bash
poetry install
poetry run pytest
poetry run ruff check .
poetry run mypy src
```

CI also audits/builds/tests the ratchet-engine dependencies, runs Python-to-libsignal cross-language tests, validates Docker Compose, and exercises the GhostNode container.

## License

**AGPL-3.0-only.** See [LICENSE](LICENSE).
