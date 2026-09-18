# GhostNode SQLite persistence

GhostNode can persist encrypted relay envelopes in SQLite.

## Configuration

Set `database_path` in `ghostlink.toml`:

```toml
[node]
host = "127.0.0.1"
port = 8000
log_level = "info"
database_path = "data/messages.sqlite3"
```

Relative database paths are resolved from the directory containing the configuration file.

If `database_path` is omitted, GhostNode keeps using the in-memory store intended for tests and short-lived development.

## Stored data

The SQLite database contains:

- relay message ID;
- protocol version;
- sender DeviceID;
- recipient DeviceID;
- Base64 ciphertext.

GhostNode does not store message plaintext or client private keys.

On POSIX systems the database file is set to mode `0600` after initialization.

## Operational behavior

The SQLite store opens a short-lived connection for each operation. This keeps the current synchronous FastAPI implementation simple and avoids sharing one SQLite connection across worker threads.

Messages survive process and VM restarts until the recipient successfully processes them and issues the relay delete request.

## Limits

This is still an M3/M2-level relay store. Retention expiry, quotas, authenticated clients, delivery acknowledgements, anti-abuse controls, backups, multi-node replication, and metadata reduction are not yet implemented.
