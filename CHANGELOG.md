# Changelog

All notable changes will be documented in this file.

The format follows Keep a Changelog and Semantic Versioning.

## [Unreleased]

### Added

- project foundation, threat model and architecture decision process;
- GhostID and DeviceID self-certifying identifiers;
- signed device authorization certificates;
- separate device signing and encryption keys;
- device-to-device authenticated encryption;
- verified public peer devices without sharing private peer keys;
- versioned public contact bundles with certificate verification;
- password-encrypted local profiles using Argon2id and PyNaCl SecretBox;
- GhostNode ciphertext relay API;
- synchronous GhostNode client transport;
- persistent SQLite relay storage;
- M3 command-line client for identity creation, contact exchange, send and inbox;
- full two-client encrypted-message integration test;
- Docker/Compose GhostNode deployment and Oracle VM runbook;\n- optional shared Bearer access control for GhostNode relay operations;\n- strict protocol-v1 relay envelope validation with a 1 MiB ciphertext cap;
- CI validation for Ruff, MyPy, pytest, Compose and container builds.

### Security

- local profile data is encrypted at rest;
- generated private profiles, local configs and relay databases are ignored by Git;
- container deployment runs as a non-root user with reduced privileges;
- raw GhostNode port is bound to host loopback by default in Compose;\n- Compose requires an explicit GhostNode relay access token.

### Known limitations

- shared relay access control exists, but no per-device relay authentication yet;
- no replay protection or message expiration yet;
- no ratcheting/forward secrecy yet;
- no independent security audit yet.
