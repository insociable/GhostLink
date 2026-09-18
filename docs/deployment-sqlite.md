# GhostNode SQLite persistence

GhostNode can persist protocol-v3 relay messages, pre-key state and authenticated-request
replay state in SQLite.

Persistent mode is rollback-aware. A SQLite database is not served until it has been
explicitly enrolled in a relay-state witness and successfully reconciled at startup.

## Configuration

Configure the database and witness paths in `ghostlink.toml`:

```toml
[node]
host = "127.0.0.1"
port = 8000
log_level = "info"
database_path = "data/messages.sqlite3"
relay_witness_path = "data/relay-witness.sqlite3"
```

Relative paths are resolved from the directory containing the configuration file.

A stable 128-bit relay-state ID is required. It may be stored as
`relay_state_id = "<32 lowercase hex characters>"` in the node table or supplied with
`GHOSTLINK_RELAY_STATE_ID`.

The 32-byte relay-state coordination key is secret. It must not be stored in TOML, argv or
an environment variable. Put its lowercase 64-character hexadecimal value in a private
file and set only the file path through `GHOSTLINK_RELAY_STATE_KEY_FILE`.

Example:

```bash
export GHOSTLINK_RELAY_STATE_ID="$(python -c 'import secrets; print(secrets.token_hex(16))')"
mkdir -p .secrets
python -c 'import secrets; print(secrets.token_hex(32))' > .secrets/relay-state-key
chmod 600 .secrets/relay-state-key
export GHOSTLINK_RELAY_STATE_KEY_FILE="$PWD/.secrets/relay-state-key"
```

If `database_path` is omitted, GhostNode uses in-memory stores intended for tests and
short-lived development and does not require relay rollback configuration.

## Initial enrollment and legacy migration

A new or legacy SQLite database is never silently enrolled.

After configuring the state ID, witness path and key file, run exactly once:

```bash
poetry run ghostnode --migrate-relay-state
```

The command creates any missing protected tables, snapshots the exact logical protected
state, creates relay-state revision 1 and initializes the witness. It does not start the
HTTP service.

Then start normally:

```bash
poetry run ghostnode
```

Normal startup refuses:

- a legacy database with no rollback metadata;
- a rollback-aware database whose witness is missing;
- a database older than its witness;
- same-revision state divergence;
- invalid successor lineage;
- a database more than one revision ahead of the witness.

A one-revision database lead caused by a crash immediately after SQLite commit and before
witness update is recovered only when its authenticated predecessor digest exactly matches
the current witness.

## Protected state

The rollback checkpoint covers the logical rows of:

- `messages_v3`;
- `prekey_publications`;
- `prekey_one_time`;
- `prekey_allocations`;
- `prekey_fetch_events`;
- `relay_request_replay_v1`.

Historical retired tables are deliberately excluded.

GhostNode does not store message plaintext or client private keys.

## Operational behavior

All security-relevant persistent writes share one in-process relay-state coordinator. The
coordinator serializes mutations, commits the SQLite change and its next revision in one
transaction, then advances the monotonic witness. Another protected mutation is blocked
until that witness transition succeeds.

Health returns HTTP 503 if coordinated persistent state becomes unsafe.

The supported model is one writable GhostNode process per SQLite database.

## Backup and restore

Treat these as one operational state set:

- GhostNode SQLite database;
- relay witness;
- relay-state ID;
- relay-state coordination-key secret.

Do not silently delete/recreate a missing witness and do not reuse migration as a generic
reset operation.

Restoring an older database while leaving a newer witness in place is detected and rejected.

The reference SQLite witness is normally a sidecar file on the same host. If a VM,
filesystem or volume snapshot restores both the relay database and the witness to the same
old point, that whole-snapshot rollback cannot be detected. A production whole-host
anti-rollback claim therefore requires a monotonic witness outside the restored host/state
domain.

## File permissions

On POSIX systems GhostNode restricts initialized SQLite files to the process owner where
implemented. Secret key files should be mode 0600 and readable only by the GhostNode
operator/runtime identity.

## Remaining limits

Rollback coordination does not provide multi-node replication, Sybil resistance, delivery
acknowledgement, complete quotas/retention policy, key transparency or protection against
compromise of the running relay process.
