# GhostNode Relay Protocol v2 — Retired

## Status

The historical static protocol-v2 **message relay** is retired from the reference GhostNode runtime.

The following routes are no longer exposed and must return `404`:

- `POST /v2/messages`;
- `GET /v2/messages/{recipient_device_id}`;
- `DELETE /v2/messages/{recipient_device_id}/{message_id}`.

The `/v2/prekeys/...` namespace is unrelated to this retired message transport and remains part of the current ratchet bootstrap and maintenance protocol.

## Historical behavior

Before retirement, GhostNode stored opaque protocol-v2 envelopes in an isolated `messages_v2` table, enforced structural/lifetime limits, and used the optional shared Bearer token as coarse relay access control.

That surface did not provide DeviceID-authenticated relay operations and was not used by the current ratcheted `send` / `inbox` runtime.

## Migration

GhostLink is pre-alpha and does not preserve a compatibility switch for the retired routes.

Existing SQLite databases may still contain a historical `messages_v2` table. Current GhostNode code does not read, serve, migrate or delete those rows. Leaving the table untouched avoids a destructive migration.

The retirement decision and acceptance criteria are recorded in [ADR-0007](../adr/0007-retire-static-v2-message-relay.md).
