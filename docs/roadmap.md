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
- [ ] timestamps and expiration;
- [ ] replay-protection design and implementation;
- [x] serialization and tamper-rejection tests.

## M2 — Relay

- [ ] authenticated client API;
- [x] ciphertext-only storage;
- [x] persistent SQLite storage option;
- [ ] explicit delivery acknowledgement protocol;
- [ ] retention limits and quotas;
- [x] Docker/Compose deployment;
- [ ] production TLS ingress;
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
- [x] password-encrypted local profile format;
- [ ] OS keychain / hardware-backed secret integration;
- [ ] contact fingerprint / QR verification UX (full fingerprint display implemented; QR/trust state pending);
- [ ] local conversation history;
- [ ] packaging for Linux and Windows;
- [ ] mobile application architecture.

## M5 — Security hardening

- [ ] ratcheting session protocol;
- [ ] forward secrecy;
- [ ] external cryptographic review;
- [ ] dependency review and automated vulnerability policy;
- [ ] reproducible releases;
- [ ] signed artifacts;
- [ ] recovery, rotation and device-revocation design.
