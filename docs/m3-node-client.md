# M3 GhostNode client transport — Current runtime

`ghostlink.client.GhostNodeClient` is the synchronous HTTP transport used by the current ratcheted GhostLink runtime.

## Current API

The client exposes:

- `health()`;
- `send_ratchet(...)`;
- `receive_ratchet(...)`;
- `delete_ratchet(...)`;
- `publish_prekeys(...)`;
- `fetch_prekey(...)`;
- `prekey_status(...)`;
- `publish_device_lifecycle(...)`;
- `get_device_lifecycle(...)`.

The historical static-v2 `send`, `receive` and `delete` message methods have been removed.

## Message boundary

Protocol-v3 message operations transport opaque libsignal ciphertext envelopes. Submission is authenticated by the sender DeviceID; mailbox list/delete are authenticated by the recipient DeviceID. Request proofs bind the HTTP method, canonical path, request body digest where applicable, freshness timestamp and random request ID.

The optional shared Bearer token is only an additional coarse relay access-control layer.

## Pre-key boundary

The `/v2/prekeys/...` routes remain current. Their `v2` namespace does not mean they are part of the retired static-v2 message relay.

Publication, fetch and status operations use their documented DeviceID/request proofs and strict response validation before ratchet state is mutated.

## Response validation

The client validates absolute HTTP(S) base URLs without embedded credentials, expected status codes, exact response fields, canonical DeviceIDs and message IDs, bounded integers and canonical Base64 ciphertext.

Current ratcheted message parsing is version-pinned to protocol v3.

## Security status

GhostNode remains outside the end-to-end trust boundary. Client and relay rollback detection, plus relay-scoped device revocation/recovery, are implemented with the witness and lifecycle limitations documented in the threat model. Key transparency/global lifecycle discovery, Sybil-resistant abuse controls, production-grade external witnessing and independent review remain open hardening areas.

The retired `/v2/messages...` surface is not a fallback or compatibility path.
