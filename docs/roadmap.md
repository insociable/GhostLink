# Roadmap

This roadmap distinguishes implemented building blocks from security work that is still required.

## M0 — Foundation

- [x] repository structure;
- [x] charter;
- [x] threat model;
- [x] ADR process;
- [x] CI;
- [x] initial crypto proof of concept.

## M1 — Protocol skeleton

- [x] versioned encrypted message envelope;
- [x] relay message identifiers;
- [x] timestamps and expiration;
- [x] replay-protection design and implementation;
- [x] serialization and tamper-rejection tests.

## M2 — Relay

- [x] DeviceID-authenticated protocol-v3 message API with signed request replay protection; historical static-v2 message relay retired;
- [x] ciphertext-only storage;
- [x] persistent SQLite storage option;
- [ ] explicit delivery acknowledgement protocol;
- [ ] retention limits and quotas;
- [x] Docker/Compose deployment;
- [ ] production TLS ingress (Caddy/443-only reference stack implemented; live external certificate/closed-port validation pending);
- [ ] anti-abuse controls.

## M3 — Two-client demonstration

- [x] persistent encrypted local identities;
- [x] verified contact import;
- [x] encrypted send and receive;
- [x] command-line client;
- [x] end-to-end integration test;
- [x] GhostNode HTTP transport.

## M4 — Desktop/mobile client foundations

- [ ] desktop interface;
- [x] password-encrypted local profile format with encrypted ratchet-vault master key and explicit v1 migration;
- [ ] OS keychain / hardware-backed secret integration;
- [ ] contact fingerprint / QR verification UX (full fingerprint display implemented; QR/trust state pending);
- [ ] local conversation history;
- [ ] packaging for Linux and Windows;
- [ ] mobile application architecture.

## M5 — Security hardening

- [x] select maintained ratcheting implementation (official libsignal);
- [x] PQXDH + ratchet-engine bootstrap integration tests;
- [x] simulated forward-secrecy / post-compromise recovery behavior at engine level;
- [x] encrypted persistent libsignal session/pre-key stores;
- [x] GhostID/DeviceID binding to libsignal identities;
- [x] local framed Python ↔ libsignal engine RPC + cross-language restart smoke;
- [x] randomized collision-checked pre-key identifiers with persistent consumption state;
- [x] pre-key replenishment, rotation and garbage-collection policy specified;
- [x] encrypted pre-key lifecycle metadata and atomic pending generation preparation;
- [x] signed publication staging and crash-safe pending recovery;
- [x] authenticated atomic relay publication and persistent public pool state;
- [x] atomic local publication acknowledgement commit with retired-generation retention;
- [x] strict HTTP publication orchestration with receipt validation and crash-safe retry;
- [x] encrypted highest-seen remote publication sequence persistence with rollback rejection before session establishment;
- [x] authenticated atomic pre-key fetch/pop with per-requester idempotence and target-window anti-drain limiting;
- [x] rollback-aware persistent GhostNode SQLite state with shared monotonic witness coordination (ADR-0009 / #86; reference sidecar witness does not protect whole-volume/VM rollback);
- [x] sender fetch -> VerifiedContact -> highest-seen -> libsignal session orchestration;
- [x] rollback-aware client-state coordination with monotonic witness (ADR-0008 / #79; reference SQLite witness remains development-only for whole-snapshot protection);
- [x] owner-authenticated pool status with automatic replenishment and expiration refresh;
- [x] transactional 15-day delayed-key garbage collection with fail-closed lifecycle ownership checks;
- [x] context-bound ratcheted message-v3 envelope and isolated GhostNode v3 relay transport;
- [x] user-facing CLI send/inbox cutover to ratcheted v3 with no static fallback;
- [ ] external cryptographic review;
- [ ] dependency review and automated vulnerability policy;
- [ ] reproducible releases;
- [ ] signed artifacts;
- [x] recovery, rotation and device-revocation design (ADR-0010 / #92);
- [x] lifecycle-aware contact bundle/store monotonic enforcement (#92);
- [x] lifecycle-aware profile v5 and dedicated profile witness coordination (#92);
- [x] rollback-linked ratchet reset primitives for DeviceID recovery (#92);
- [x] explicit crash-resumable device recovery CLI transaction (#92);
- [x] rollback-protected GhostNode lifecycle registry and stale-device enforcement (#92);
- [x] client lifecycle publication before relay use plus fail-closed recovery publish/promote ordering (#92);
- [x] remote lifecycle refresh/contact update and durable ratchet-session invalidation after peer device replacement (#92).
