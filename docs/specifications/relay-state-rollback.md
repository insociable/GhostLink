# Relay-state rollback coordination

Status: design accepted; implementation pending under issue #86.

## Scope

This specification instantiates ADR-0009 for the current GhostNode SQLite schema.

It protects logical persistent relay state from restoration to an older valid database
snapshot when a monotonic witness remains newer.

It does not claim whole-VM rollback protection with a witness stored on that same VM.

## Protected tables v1

The protected table set is exactly:

```text
messages_v3
prekey_publications
prekey_one_time
prekey_allocations
prekey_fetch_events
relay_request_replay_v1
```

Indexes are not checkpoint inputs.

Historical tables are excluded.

## Canonical table order

Tables are serialized in this fixed order:

1. `messages_v3`
2. `prekey_publications`
3. `prekey_one_time`
4. `prekey_allocations`
5. `prekey_fetch_events`
6. `relay_request_replay_v1`

The canonical document is strict JSON UTF-8 using sorted object keys and compact
separators. Table rows are arrays in the exact column order below.

## Canonical rows

### messages_v3

Columns:

```text
message_id
version
sender_device_id
recipient_device_id
created_at
expires_at
ciphertext_type
ciphertext
```

Sort by:

```text
recipient_device_id, message_id
```

### prekey_publications

Columns:

```text
device_id
publication_sequence
expires_at
publication_payload
fallback_binding
```

Sort by `device_id`.

### prekey_one_time

Columns:

```text
device_id
publication_sequence
position
binding
```

Sort by:

```text
device_id, publication_sequence, position
```

### prekey_allocations

Columns:

```text
target_device_id
publication_sequence
requester_device_id
request_id
expires_at
bundle_kind
binding
remaining_one_time_count
allocated_at
```

Sort by:

```text
target_device_id, publication_sequence, requester_device_id
```

### prekey_fetch_events

Columns:

```text
event_id
target_device_id
allocated_at
```

Sort by `event_id`.

The AUTOINCREMENT event identifier is logical application state here because rollback of
that table must reproduce the exact anti-drain history being witnessed. SQLite internal
`rowid` values outside explicit columns are never checkpointed.

### relay_request_replay_v1

Columns:

```text
device_id
request_id
expires_at
```

Sort by:

```text
device_id, request_id
```

## Metadata v1

A singleton table named `relay_state_meta_v1` stores:

```text
singleton = 1
version = 1
relay_state_id
revision
previous_digest
```

Revision 1 has `previous_digest = NULL`.

Later revisions require a 64-character lowercase hexadecimal previous digest.

The metadata table is excluded from the canonical protected-table payload because its
identity/revision/lineage fields are already explicit checkpoint inputs.

## Canonical payload v1

Conceptually:

```json
{
  "tables": {
    "messages_v3": [],
    "prekey_allocations": [],
    "prekey_fetch_events": [],
    "prekey_one_time": [],
    "prekey_publications": [],
    "relay_request_replay_v1": []
  },
  "version": 1
}
```

The implementation must emit the exact strict compact representation from validated SQLite
values.

BLOBs are not currently part of protected tables. Adding a BLOB column requires an explicit
encoding rule in a future version.

## Coordinator ownership

One persistent `create_app` call constructs one coordinator for its configured SQLite
database and injects that same instance into:

- the v3 message store;
- the pre-key publication/allocation store;
- the authenticated-request replay store.

Store constructors must not create independent rollback coordinators.

## Mutation classification

The following operations can change protected state and therefore require coordinated
mutation:

- v3 message insert;
- v3 expired-message pruning;
- v3 message delete;
- pre-key publication replacement;
- one-time pre-key allocation/pop;
- expired allocation pruning;
- fetch-event pruning/insertion;
- authenticated request-replay pruning/insertion.

Idempotent calls that leave canonical protected state unchanged do not advance the relay
revision.

## Readiness

Persistent mode is not ready until the initial database/witness reconciliation succeeds.

A reconciliation or post-commit witness failure marks the coordinator unsafe. Health checks
must fail until a valid restart/reconciliation recovers the exact permitted one-step state.

## Migration and recovery

Legacy migration is explicit and only valid for a database with no
`relay_state_meta_v1` row and no existing witness record for the chosen relay-state ID.

Witness disappearance after enrollment is a hard failure, not a signal to initialize a new
record.

Restoring an older database while the witness remains current must fail before normal
persistent service begins.

A sidecar witness restored together with the database cannot detect that whole-snapshot
rollback; this limitation must remain visible in operator documentation.
