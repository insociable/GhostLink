# Oracle VM deployment runbook

This runbook deploys the current experimental GhostNode on a fresh Oracle Linux/Ubuntu-style VM using Docker Compose.

GhostLink is not yet suitable for sensitive real-world communications.

## Network stance

For the first deployment:

- keep SSH restricted to your administrative source addresses where possible;
- do **not** expose TCP/8000 in the Oracle security list/NSG;
- the Compose file publishes GhostNode only on `127.0.0.1:8000`;
- add public HTTPS only after a reverse proxy or tunnel is configured and reviewed.

## 1. Host preparation

Install Docker Engine and the Docker Compose plugin using the vendor-supported packages for the VM distribution.

Verify:

```bash
docker --version
docker compose version
```

Add the administrative user to the Docker group only if you accept that Docker access is effectively root-equivalent.

## 2. Clone GhostLink

```bash
git clone https://github.com/insociable/GhostLink.git
cd GhostLink
git checkout main
```

## 3. Build and start GhostNode

```bash
docker compose build --pull
docker compose up -d
```

Check status:

```bash
docker compose ps
docker compose logs --tail=100 ghostnode
curl --fail http://127.0.0.1:8000/health
```

Expected health response:

```json
{"status":"ok"}
```

## 4. Persistent ciphertext store

The Compose stack mounts the named volume `ghostnode_data` at `/data`.

GhostNode stores its SQLite database at:

```text
/data/messages.sqlite3
```

The database contains encrypted envelopes and routing metadata, not plaintext message bodies or client private keys.

## 5. Test from a workstation without exposing port 8000

Create an SSH tunnel:

```bash
ssh -L 8000:127.0.0.1:8000 <user>@<oracle-vm>
```

On the workstation:

```bash
ghostlink node-health --node http://127.0.0.1:8000
```

The same tunnel can be used for the first Alice/Bob M3 test.

## 6. Update procedure

```bash
git pull --ff-only
docker compose build --pull
docker compose up -d
docker compose ps
```

Run the health check after every update.

## 7. Stop

```bash
docker compose down
```

The named data volume is preserved.

Do not use `docker compose down -v` unless the encrypted relay database is intentionally being destroyed.

## 8. Backup the relay database

Create a backup directory:

```bash
mkdir -p backups
```

For an early development node, stop GhostNode before taking a simple volume archive:

```bash
docker compose stop ghostnode
docker run --rm \
  -v ghostlink_ghostnode_data:/data:ro \
  -v "$PWD/backups:/backup" \
  alpine \
  tar -czf /backup/ghostnode-data.tar.gz -C /data .
docker compose start ghostnode
```

A later production design should use a documented SQLite online-backup process and encrypted off-host backups.

## 9. Public HTTPS — later step

Do not point mobile/desktop clients at a raw public HTTP GhostNode.

The next infrastructure step is one of:

- Caddy/Nginx with a real TLS certificate;
- a reviewed Cloudflare Tunnel configuration;
- another authenticated TLS ingress.

Only TCP/443 should normally need public exposure after that layer exists.
