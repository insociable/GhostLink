# ADR-0007: Retire the static protocol-v2 message relay

- Status: Accepted for implementation
- Date: 2026-09-18

## Context

GhostLink's user-facing messaging runtime has already moved to ratcheted protocol v3.
`send` and `inbox` establish and reuse official libsignal sessions and do not fall back
to static protocol v2.

The reference GhostNode nevertheless still exposes three historical static-message
endpoints:

- `POST /v2/messages`;
- `GET /v2/messages/{recipient_device_id}`;
- `DELETE /v2/messages/{recipient_device_id}/{message_id}`.

Those routes are protected only by the optional shared Bearer access token. Unlike the
ratcheted v3 routes, they do not require DeviceID request signatures. Keeping an unused
network protocol therefore preserves a weaker authorization surface and additional relay
storage/parser code without serving the current messaging path.

The `/v2/prekeys/...` namespace is unrelated to the static-message relay. It carries the
current ratchet pre-key publication/fetch/status protocol and already has device/request
proofs appropriate to those operations.

## Decision

Remove the **static protocol-v2 message transport surface** from the reference runtime.

The implementation will remove:

- all `/v2/messages...` GhostNode routes;
- static-v2 relay storage from GhostNode health and startup;
- static-v2 network methods from `GhostNodeClient`;
- the `node-smoke` CLI command;
- the container CI smoke that exercises static-v2 messaging.

The implementation will add an explicit negative assertion that the old
`/v2/messages...` routes are not exposed.

The existing `/v2/prekeys/...` endpoints MUST remain available. Their version number is
not authorization for removing them; they are part of the current libsignal bootstrap and
maintenance flow.

## Local protocol-v2 codec

The local `ghostlink.message` protocol-v2 codec is not a public network service. It is
currently also the source of shared message lifecycle constants used by ratcheted v3.

This ADR does not require deleting that module in the same change. It may remain as
non-runtime compatibility/test code until the shared lifecycle constants are separated in
a later cleanup. No user-facing command or GhostNode network route may use it after this
cutover.

## Migration and compatibility

GhostLink is pre-alpha and has no supported production protocol-v2 deployment. The
reference runtime therefore does not preserve a compatibility flag for the old static
message routes.

An existing relay database may retain a historical `messages_v2` table. The cutover does
not read, serve, migrate or delete those rows. Leaving the table untouched avoids a
destructive database migration and prevents rollback/redeployment procedures from
silently rewriting operator data.

Clients depending on `/v2/messages...` are intentionally incompatible with the new
reference runtime.

## Security consequences

Benefits:

- removes a Bearer-only message authorization surface;
- reduces public route/parser/storage attack surface;
- makes the "no static fallback" rule visible at the server boundary, not only in the CLI;
- simplifies GhostNode health to current protocol state.

Limitations:

- the shared Bearer token can still be configured as an additional coarse access-control
  layer for current endpoints;
- `/v2/prekeys/...` remains by design;
- retained local v2 codec code is not itself a production-security claim;
- relay and client anti-rollback, key transparency, abuse controls, device
  revocation/recovery and independent review remain open.

## Acceptance criteria

Implementation is complete when:

1. GhostNode OpenAPI exposes no `/v2/messages...` route;
2. `/v2/prekeys/...` remains present and its tests still pass;
3. `GhostNodeClient` has no static-v2 send/receive/delete transport methods;
4. the CLI has no `node-smoke` command;
5. GhostNode health no longer depends on a static-v2 message store;
6. container CI explicitly verifies the retired route returns 404;
7. ratcheted v3, pre-key, Python/libsignal and container test suites remain green.
