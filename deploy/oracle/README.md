# Oracle VM deployment runbook

This runbook covers two deliberately separate GhostNode deployment modes:

- local/administrative testing through host loopback + SSH tunnel;
- reviewed public HTTPS ingress through Caddy.

GhostLink remains pre-alpha and is not suitable for sensitive real-world communications.

## Security boundary

The public reference deployment follows these rules:

- SSH is restricted to administrative source addresses where possible;
- GhostNode TCP/8000 is never published by the public Compose stack;
- TCP/80 is not published or required;
- Caddy is the only public service and publishes TCP/443 only;
- protocol-v3 message operations still require DeviceID signatures;
- the shared Bearer token remains an additional coarse control;
- the Bearer token is stored in a file and mounted as a Docker secret, not placed in argv or environment values;
- GhostNode does not trust proxy headers for authorization;
- HTTP access logs are disabled in the Oracle GhostNode profile;
- no Caddy HTTP access log is enabled.

The external test gate in this document must pass before issue #21 is considered verified.

## 1. Host preparation

Install Docker Engine and the Docker Compose plugin using vendor-supported packages for the VM distribution.

Verify:

```bash
docker --version
docker compose version
```

Docker access is effectively root-equivalent. Restrict membership of the Docker group accordingly.

## 2. Clone GhostLink

```bash
git clone https://github.com/insociable/GhostLink.git
cd GhostLink
git checkout main
```

## 3. Create the relay Bearer-token file

Create a private local secret directory and generate the token directly into a file:

```bash
umask 077
mkdir -p .secrets
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > .secrets/ghostlink_node_token
chmod 600 .secrets/ghostlink_node_token
```

Do not print the token, place it in shell history, pass it in argv, or store its value in an environment variable.

The repository ignores `.secrets/`.

Compose needs only the **path** of the token file:

```bash
export GHOSTLINK_NODE_TOKEN_FILE="$PWD/.secrets/ghostlink_node_token"
```

The environment variable contains a filesystem path, not the secret value.

## 4. Loopback-only deployment

The root `compose.yaml` is the retained local/SSH-tunnel mode.

Validate and start it:

```bash
docker compose config --quiet
docker compose build --pull
docker compose up -d
```

Check:

```bash
docker compose ps
curl --fail http://127.0.0.1:8000/health
```

Expected response:

```json
{"status":"ok"}
```

GhostNode is published only on host loopback in this mode.

## 5. Test loopback mode from a workstation

Create an SSH tunnel:

```bash
ssh -L 8000:127.0.0.1:8000 <user>@<oracle-vm>
```

On the workstation, create a private local copy of the same relay token through a trusted transfer channel, then point the client to its file:

```bash
export GHOSTLINK_NODE_TOKEN_FILE="$HOME/.config/ghostlink/node-token"
```

The file itself should be readable only by that user.

Check the node:

```bash
ghostlink node-health --node http://127.0.0.1:8000
```

The retained static diagnostic smoke can be run explicitly:

```bash
ghostlink node-smoke --node http://127.0.0.1:8000
```

This V2 smoke is diagnostic only. User-facing `send` / `inbox` use protocol v3 and never fall back to it automatically.

## 6. Prepare public DNS

Choose a dedicated hostname, for example:

```text
node.example.net
```

Create an A record pointing to the Oracle VM public IPv4 address.

If an AAAA record is published, IPv6 must be intentionally configured and firewalled as well. Do not publish an unusable AAAA record.

Wait until public DNS resolution is correct before starting Caddy certificate issuance.

## 7. Configure public non-secret settings

Create or update a local `.env` containing only non-secret deployment values:

```dotenv
GHOSTLINK_NODE_TOKEN_FILE=.secrets/ghostlink_node_token
GHOSTLINK_PUBLIC_HOSTNAME=node.example.net
GHOSTLINK_ACME_EMAIL=admin@example.net
```

The token **value** is not stored in `.env`.

## 8. Oracle and host firewall policy

For the public deployment:

- allow TCP/443 from intended public client networks, normally the Internet;
- keep SSH limited to administrative source addresses;
- do not allow TCP/80;
- do not allow TCP/8000;
- no UDP/443 rule is required by the reference stack because HTTP/3 is disabled.

Apply the same intent to both Oracle Security Lists/NSGs and the host firewall where one is enabled.

Before public start, verify no process is already occupying TCP/443.

## 9. Validate the public stack

Load the non-secret environment values if needed:

```bash
set -a
. ./.env
set +a
```

Validate Compose:

```bash
docker compose -f deploy/oracle/compose.public.yaml config --quiet
```

Validate the Caddyfile with the pinned image:

```bash
docker run --rm \
  --env GHOSTLINK_PUBLIC_HOSTNAME \
  --env GHOSTLINK_ACME_EMAIL \
  --volume "$PWD/deploy/oracle/Caddyfile:/etc/caddy/Caddyfile:ro" \
  caddy:2.11.4-alpine \
  caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
```

## 10. Start public HTTPS

Build GhostNode and start the public stack:

```bash
docker compose -f deploy/oracle/compose.public.yaml build --pull
docker compose -f deploy/oracle/compose.public.yaml up -d
```

Inspect service state:

```bash
docker compose -f deploy/oracle/compose.public.yaml ps
docker compose -f deploy/oracle/compose.public.yaml logs --tail=100 caddy
docker compose -f deploy/oracle/compose.public.yaml logs --tail=100 ghostnode
```

Do not enable Caddy HTTP access logging merely for routine diagnostics: request paths contain relay metadata such as DeviceIDs.

## 11. Certificate lifecycle

Caddy automatically obtains and renews the public certificate.

The persistent `caddy_data` volume stores ACME account and certificate state. Preserve that volume across container recreation and ordinary application rollback.

The reference Caddy configuration disables the HTTP challenge and uses the TLS-ALPN path on TCP/443, so TCP/80 is not required.

Operators should monitor warning/error logs and periodically re-run the external TLS checks below.

No Certbot cron job is required.

## 12. External validation gate

Run these checks from a machine **outside** the Oracle VM/network.

Resolve the hostname:

```bash
getent ahosts node.example.net
```

Verify HTTPS and certificate validation:

```bash
curl --fail --show-error --silent https://node.example.net/health
```

Expected body:

```json
{"status":"ok"}
```

Inspect certificate validation if needed:

```bash
openssl s_client \
  -connect node.example.net:443 \
  -servername node.example.net \
  -verify_return_error </dev/null
```

From the same external machine, verify that TCP/80 and TCP/8000 are not reachable. Use an external port-testing tool appropriate for that workstation/network.

Then configure the client with its local Bearer-token file path:

```bash
export GHOSTLINK_NODE_TOKEN_FILE="$HOME/.config/ghostlink/node-token"
```

Run a real protocol-v3 workflow against:

```text
https://node.example.net
```

At minimum:

1. `prekey-sync` for the destination device;
2. `send` from a verified contact/device;
3. `inbox` on the destination;
4. confirm no static-v2 fallback occurred.

Only after the certificate, closed-port and v3 tests pass should issue #21 be closed.

## 13. Rotate the relay Bearer token

Generate a replacement directly into a temporary private file, then atomically replace the mounted source:

```bash
umask 077
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > .secrets/ghostlink_node_token.new
chmod 600 .secrets/ghostlink_node_token.new
mv .secrets/ghostlink_node_token.new .secrets/ghostlink_node_token
```

Recreate GhostNode so the mounted secret is refreshed:

```bash
docker compose -f deploy/oracle/compose.public.yaml up -d --force-recreate ghostnode
```

Distribute the new token to authorized clients through a trusted channel and replace their local token files.

## 14. Update procedure

```bash
git pull --ff-only
docker compose -f deploy/oracle/compose.public.yaml config --quiet
docker compose -f deploy/oracle/compose.public.yaml build --pull
docker compose -f deploy/oracle/compose.public.yaml up -d
docker compose -f deploy/oracle/compose.public.yaml ps
```

Re-run the external HTTPS health check after every update.

## 15. Persistent state and backup

The public stack uses:

- `ghostnode_data` for the relay SQLite database;
- `caddy_data` for certificate/ACME state;
- `caddy_config` for Caddy runtime state.

Do not use `docker compose down -v` unless those states are intentionally being destroyed.

A relay-database rollback is security relevant because it can also roll back publication/request-replay state. Ordinary application rollback must preserve the current GhostNode data volume.

For an early-development offline archive, stop the relevant service before copying its volume. A production backup/anti-rollback design remains separate work.

## 16. Rollback

Application/configuration rollback:

1. preserve current `ghostnode_data`, `caddy_data` and `caddy_config`;
2. check out the previous reviewed Git revision;
3. restore compatible non-secret deployment configuration;
4. validate Compose and Caddyfile;
5. recreate the containers without replacing the data volumes;
6. verify public certificate validation and `/health`;
7. verify a v3 authenticated flow.

Do **not** restore an older GhostNode SQLite snapshot as a routine software rollback.

## 17. Stop

```bash
docker compose -f deploy/oracle/compose.public.yaml down
```

Persistent volumes are preserved unless `-v` is explicitly added.
