# Threat Model

## Protected assets

- message plaintext;
- private identity keys;
- conversation keys;
- contact authenticity;
- local message history.

## Initial adversaries

- compromised relay operator;
- passive network observer;
- active network attacker;
- attacker replaying captured messages;
- attacker attempting public-key substitution;
- attacker with access to relay storage.

## Explicitly out of scope for the first proof of concept

- compromised client operating system;
- hardware implants;
- global traffic-correlation resistance;
- coercion of participants;
- endpoint screenshots or keyloggers;
- post-quantum security.

## Current known gaps

The initial cryptographic module does not yet provide:

- forward secrecy;
- post-compromise security;
- replay protection;
- contact-key verification workflow;
- encrypted private-key storage;
- metadata protection.

No production-security claim may be made while these gaps remain.
