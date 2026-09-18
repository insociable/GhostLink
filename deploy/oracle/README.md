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

## 3. Create the relay secret files

Create a private local secret directory and generate both relay secrets directly into files:

```bash
umask 077
mkdir -p .secrets
chmod 700 .secrets
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > .secrets/ghostlink_node_token
python3 -c 'import secrets; print(secrets.token_hex(32))' > .secrets/ghostlink_relay_state_key
chmod 444 .secrets/ghostlink_node_token .secrets/ghostlink_relay_state_key
```

Do not print either secret, place secret values in shell history, pass them in argv, or store their values in environment variables.

The source files are read-only because the non-root GhostNode container must be able to read the Compose secret bind mounts. Host confidentiality comes from the parent `.secrets` directory being mode `0700`; do not move these files into a traversable shared directory.

The repository ignores `.secrets/`.

Generate one non-secret 128-bit relay-state ID and keep that exact value for the lifetime of this GhostNode database:

```bash
export GHOSTLINK_RELAY_STATE_ID="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
export GHOSTLINK_NODE_TOKEN_FILE="$PWD/.secrets/ghostlink_node_token"
export GHOSTLINK_RELAY_STATE_KEY_FILE="$PWD/.secrets/ghostlink_relay_state_key"
```

Persist the same `GHOSTLINK_RELAY_STATE_ID` in the deployment's non-secret configuration. Never generate a new ID for an already enrolled database.

The two `*_FILE` environment variables contain filesystem paths, not secret values.

## 4. Loopback-only deployment

The root `compose.yaml` is the retained local/SSH-tunnel mode.

Validate and build it:

```bash
docker compose config --quiet
docker compose build --pull
```

For a new volume or a legacy pre-ADR-0009 relay database, enroll persistent state exactly once before normal startup:

```bash
docker compose run --rm --no-deps ghostnode ghostnode --migrate-relay-state
```

Do not run the migration command as a routine update step for an already enrolled database.

Then start normally:

```bash
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

The historical static-v2 message relay is retired. A request to `/v2/messages/...` must return `404`; `/v2/prekeys/...` remains part of the current ratchet bootstrap API.

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
GHOSTLINK_RELAY_STATE_KEY_FILE=.secrets/ghostlink_relay_state_key
GHOSTLINK_RELAY_STATE_ID=00112233445566778899aabbccddeeff
GHOSTLINK_PUBLIC_HOSTNAME=node.example.net
GHOSTLINK_ACME_EMAIL=admin@example.net
```

Replace the example relay-state ID with the stable value generated for this deployment.
Neither secret **value** is stored in `.env`; only secret-file paths are.

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

Build GhostNode:

```bash
docker compose -f deploy/oracle/compose.public.yaml build --pull
```

For a new volume, or once when upgrading a legacy pre-ADR-0009 database, enroll relay rollback state before normal startup:

```bash
docker compose -f deploy/oracle/compose.public.yaml run --rm --no-deps ghostnode ghostnode --migrate-relay-state
```

Do not rerun migration for an already enrolled database.

Then start and inspect the public stack:

```bash
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

Run the transport checks from a machine **outside** the Oracle VM/network.

The repository includes a fail-closed validator that checks every A/AAAA address returned
for the hostname:

- DNS resolution succeeds;
- TCP/443 is reachable on every published address;
- the certificate chain and hostname validate through the system trust store;
- TCP/80 and TCP/8000 are unreachable on every published address;
- `HTTPS /health` returns HTTP 200 and exactly `{"status":"ok"}`.

Run:

```bash
python3 deploy/oracle/validate_external.py node.example.net
```

When the intended public address is known, pin it in the validation command so an
unexpected/stale DNS target also fails the gate:

```bash
python3 deploy/oracle/validate_external.py \
  node.example.net \
  --expect-address 203.0.113.10
```

Repeat `--expect-address` for every intentionally published A/AAAA address. If an AAAA
record exists, the validator requires its TCP/443 and TLS path to work and also verifies
that its TCP/80 and TCP/8000 are closed.

The validator contains no relay secret and does not exercise application identity. After
the transport gate passes, configure the external client's local Bearer-token file path:

```bash
export GHOSTLINK_NODE_TOKEN_FILE="$HOME/.config/ghostlink/node-token"
```

Run a real protocol-v3 workflow against:

```text
https://node.example.net
```

At minimum:

1. `prekey-sync` for the destination device;
2. `send --contact-id ...` from a persisted human-verified contact;
3. `inbox --contact-id ...` on the destination;
4. confirm no raw-contact trust bypass or static-v2 fallback was used.

Only after the DNS/address, certificate, closed-port, HTTPS health and real v3 tests pass
should issue #21 be closed.

## 13. Rotate the relay Bearer token

Generate a replacement directly into a temporary private file, then atomically replace the mounted source:

```bash
umask 077
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > .secrets/ghostlink_node_token.new
chmod 444 .secrets/ghostlink_node_token.new
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
```

If this update is the first version introducing ADR-0009 to an existing legacy database, perform the one-time migration described in section 10 before starting. Otherwise, do not rerun migration.

Recreate the already enrolled public stack normally:

```bash
docker compose -f deploy/oracle/compose.public.yaml up -d
docker compose -f deploy/oracle/compose.public.yaml ps
```

Re-run the external HTTPS health check after every update.

## 15. Persistent state and backup

The public stack uses:

- `ghostnode_data` for the relay SQLite database **and the reference relay witness sidecar**;
- `caddy_data` for certificate/ACME state;
- `caddy_config` for Caddy runtime state;
- the operator-managed relay-state ID plus `ghostlink_relay_state_key` secret as part of the relay recovery state.

Do not use `docker compose down -v` unless those states are intentionally being destroyed.

A relay-database rollback is security relevant because it can also roll back publication, one-time pre-key, anti-drain and request-replay state. Ordinary application rollback must preserve the current GhostNode data volume and the exact relay-state identity/key.

The reference witness detects restoration of an older relay database only while the witness remains newer. Because the reference Oracle layout stores the witness in the same `ghostnode_data` volume, restoring the whole volume/VM to an older snapshot can roll the witness back too and is **not** covered by the anti-rollback claim.

For an offline archive, stop GhostNode before copying coordinated state. A production whole-host anti-rollback claim requires a monotonic witness outside the restored host/volume domain.

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
