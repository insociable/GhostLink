# Architecture

## Initial components

### GhostLink client

Responsible for:

- generating and storing local private keys;
- verifying contacts;
- encrypting messages before transmission;
- decrypting messages after reception.

### GhostLink relay

Responsible for:

- accepting authenticated encrypted envelopes;
- temporarily storing or forwarding ciphertext;
- deleting delivered or expired envelopes.

The relay must never receive conversation plaintext or user private keys.

## Trust boundaries

```text
Client A -- encrypted envelope --> Relay -- encrypted envelope --> Client B
```

The relay is treated as potentially compromised.

## VPN position

WireGuard is an optional network-access layer. It reduces exposure of the relay but
does not replace end-to-end encryption.
