# Persistent Replay Cache

Protocol v2 requires recipients to remember authenticated message identifiers independently of GhostNode.

## Storage

The reference CLI uses a local SQLite database.

By default, an inbox using:

`bob.ghost`

stores replay state in:

`bob.ghost.state.sqlite3`

A different path can be supplied with `ghostlink inbox --state PATH`.

On POSIX systems the database file is forced to mode `0600`.

## Replay key

Entries are keyed by:

`(sender_device_id, message_id)`

The same random message ID from a different authenticated sender device is a different replay-cache entry.

## Atomic acceptance

Acceptance uses a SQLite `BEGIN IMMEDIATE` transaction followed by `INSERT OR IGNORE`.

This makes the check-and-record step atomic across concurrent client processes sharing the same state database.

A message is exposed to the user only after:

1. sender device selection;
2. authenticated decryption;
3. outer/inner metadata equality checks;
4. timestamp and expiration validation;
5. UTF-8 validation for the text CLI;
6. successful replay-cache insertion.

If insertion reports that the key already exists, the plaintext is not displayed again.

## Retention

Replay entries are retained for at least:

- protocol maximum message lifetime: 7 days;
- plus protocol clock tolerance: 5 minutes.

The reference cache therefore retains an accepted key for 7 days and 5 minutes from acceptance before it becomes eligible for pruning.

This is intentionally conservative.

## Relay interaction

Relay deduplication and the local replay cache solve different problems.

GhostNode rejects conflicting duplicate IDs and stores exact retries idempotently. A malicious, reset, or replaced relay can lose that history, so the recipient cache remains the security boundary for replay suppression.

A replayed message that is still present on the relay is not displayed. Unless `--keep` is being used for development, the client deletes the replayed relay copy.

## Limitations

The replay database is integrity-sensitive local state. Deleting or rolling it back can allow an otherwise valid unexpired captured message to be displayed again.

Future desktop/mobile clients should bind replay state to protected application storage and include it in rollback-aware backup/recovery design.