# ADR-0005: Oracle public TLS ingress with Caddy

- Status: Accepted for implementation; live external verification required before issue closure
- Date: 2026-09-18

## Context

GhostNode's existing Oracle deployment intentionally publishes TCP/8000 only on host loopback and uses an SSH tunnel for early testing.

Protocol-v3 message operations now require DeviceID-authenticated request proofs, but a public deployment still requires transport security and explicit ingress hardening.

Issue #21 requires:

- only TCP/443 publicly necessary;
- valid public TLS;
- GhostNode port 8000 not publicly exposed;
- explicit proxy/header trust;
- minimized logs;
- documented certificate renewal;
- documented rollback;
- an external-client test.

## Options reviewed

### Nginx

Nginx is a mature reverse proxy, but public certificate provisioning and renewal require a separate ACME/certificate-management workflow.

That increases operational surface for this small single-service deployment.

### Cloudflare Tunnel

Cloudflare Tunnel can publish a service without opening inbound origin ports and provides an outbound-only tunnel.

It is a valid future option, especially where hiding the origin IP is more important than minimizing external dependencies.

For the reference Oracle deployment it would place Cloudflare in the availability/traffic path and make the baseline deployment depend on an external tunnel control plane.

### Caddy

Caddy provides integrated automatic HTTPS and certificate renewal.

Its ACME TLS-ALPN challenge can validate ownership using TCP/443, so the reference configuration can disable HTTP challenge/redirect handling and leave TCP/80 closed.

Caddy also sanitizes forwarded headers as the first proxy. GhostNode does not need client-IP-derived trust for protocol authentication.

## Decision

The reference direct Oracle HTTPS ingress uses the official Caddy `2.11.4-alpine` image pinned to the reviewed OCI digest. The readable tag is retained alongside the digest for update tooling and operator context.

The existing loopback-only `compose.yaml` remains unchanged as the development/SSH-tunnel deployment.

A separate `deploy/oracle/compose.public.yaml` defines the Internet-facing stack.

## Network boundary

The public stack uses two Docker networks:

- an internal backend network containing GhostNode and Caddy;
- an edge network attached only to Caddy so it can reach public ACME infrastructure.

GhostNode publishes no host port in the public stack.

Caddy publishes only:

```text
443/tcp
```

HTTP/3 is disabled in the reference config, so UDP/443 is not required.

TCP/80 is not published.

## TLS policy

Caddy automatic certificate management is used with:

- a required public hostname;
- a required ACME account email;
- HTTP challenge disabled;
- automatic HTTP redirects disabled;
- TLS-ALPN challenge available on TCP/443;
- Caddy's maintained TLS defaults.

The configuration does not pin cipher suites or protocol versions beyond Caddy's maintained secure defaults.

The Caddy `/data` volume is persistent because it contains certificate/account state.

## Proxy trust

Caddy is the only public HTTP server in the reference stack.

Before proxying, it writes the forwarded metadata it controls:

- `X-Forwarded-For`;
- `X-Forwarded-Proto=https`;
- `X-Forwarded-Host`.

GhostNode/Uvicorn is explicitly started with proxy-header trust disabled.

GhostLink authorization does not rely on source IP or forwarded headers; protocol-v3 authorization uses DeviceID signatures.

Any future feature that consumes client IP MUST introduce a reviewed proxy-trust policy rather than silently enabling Uvicorn proxy-header trust.

## Logging

The public deployment minimizes transport metadata retention:

- no Caddy HTTP access log is enabled;
- Caddy runtime logging is limited to warning and above;
- GhostNode/Uvicorn access logging is disabled;
- GhostNode log level is warning.

Operational error logs may still contain timestamps, error categories and process/runtime metadata.

Secrets, authorization tokens, private keys and plaintext must not be logged.

## Bearer token

The shared Bearer token remains required by the reference Compose deployment as an additional coarse control.

Its value is read from a mounted secret file. The token value is not passed in argv or stored in an environment variable; only the secret-file path may be configured through `GHOSTLINK_NODE_TOKEN_FILE`.

For protocol-v3 messaging it is not the device identity mechanism; DeviceID request signatures remain mandatory.

## Certificate renewal

Caddy renews managed certificates automatically before expiration using the persistent Caddy data volume.

Operators must monitor warning/error logs and periodically test the public TLS endpoint.

No cron/Certbot workflow is required.

## Rollback

The public stack is rollback-safe operationally only if its persistent volumes are preserved.

Rollback procedure:

1. keep the Caddy and GhostNode data volumes;
2. check out the previous reviewed Git revision;
3. validate the previous Compose/Caddy configuration;
4. recreate the stack;
5. verify internal health;
6. verify the public TLS certificate and external health endpoint.

A rollback of the GhostNode SQLite database is a security-relevant state rollback and is NOT part of ordinary application rollback.

## External validation gate

Repository CI can validate:

- Compose structure;
- Caddyfile parsing;
- no public GhostNode port declaration;
- only TCP/443 exposed by the public Compose model;
- application tests.

CI cannot prove issuance of a real public certificate for the operator's DNS name.

Before issue #21 is closed, an operator MUST verify from an external client:

- the hostname resolves to the intended public IP;
- TCP/80 and TCP/8000 are unreachable;
- TCP/443 is reachable;
- certificate hostname/chain validation succeeds;
- `https://<hostname>/health` returns the expected healthy status;
- an authenticated GhostLink v3 flow works over the public HTTPS URL.

## Consequences

Advantages:

- minimal direct public network surface;
- automatic certificate lifecycle;
- no raw GhostNode host port;
- no separate Certbot lifecycle;
- no mandatory third-party tunnel provider;
- explicit proxy/logging policy.

Remaining limitations:

- the origin public IP remains visible;
- Caddy/ACME availability becomes part of certificate lifecycle operations;
- relay-database anti-rollback remains unsolved;
- device revocation/recovery remains unsolved;
- public exposure still requires monitoring, quotas/rate limiting and independent security review before production-security claims.
