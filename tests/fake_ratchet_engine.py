#!/usr/bin/env python3
"""Minimal framed RPC fixture used to test the Python ratchet client only."""

from __future__ import annotations

import base64
import json
import struct
import sys
import time


def read_exact(size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sys.stdin.buffer.read(remaining)
        if not chunk:
            raise EOFError
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def write_response(document: dict[str, object]) -> None:
    payload = json.dumps(document, separators=(",", ":")).encode()
    sys.stdout.buffer.write(struct.pack(">I", len(payload)))
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def material() -> dict[str, object]:
    return {
        "version": 1,
        "registration_id": 4200,
        "signal_device_id": 1,
        "identity_key": base64.b64encode(b"\x05" + b"\x01" * 32).decode(),
        "pre_key_id": 1001,
        "pre_key": base64.b64encode(b"\x05" + b"\x02" * 32).decode(),
        "signed_pre_key_id": 2001,
        "signed_pre_key": base64.b64encode(b"\x05" + b"\x03" * 32).decode(),
        "signed_pre_key_signature": base64.b64encode(b"\x04" * 64).decode(),
        "kyber_pre_key_id": 3001,
        "kyber_pre_key": base64.b64encode(b"\x05" * 64).decode(),
        "kyber_pre_key_signature": base64.b64encode(b"\x06" * 64).decode(),
    }


def dispatch(method: str, params: object) -> object:
    if method in {"ping", "open"}:
        return {"rpc_version": 1}
    if method == "create_prekey_material":
        return material()
    if method == "establish_session":
        assert isinstance(params, dict)
        assert set(params) == {
            "remote_device_id",
            "publication_sequence",
            "material",
        }
        assert params["publication_sequence"] == 1
        return None
    if method == "encrypt":
        assert isinstance(params, dict)
        plaintext = base64.b64decode(str(params["plaintext"]), validate=True)
        return {
            "message_type": 3,
            "ciphertext": base64.b64encode(b"cipher:" + plaintext).decode(),
        }
    if method == "decrypt":
        assert isinstance(params, dict)
        ciphertext = base64.b64decode(str(params["ciphertext"]), validate=True)
        if not ciphertext.startswith(b"cipher:"):
            raise ValueError("bad fake ciphertext")
        return {
            "plaintext": base64.b64encode(ciphertext[len(b"cipher:") :]).decode()
        }
    if method == "close":
        return None
    raise KeyError(method)


while True:
    try:
        length = struct.unpack(">I", read_exact(4))[0]
        request = json.loads(read_exact(length))
    except EOFError:
        break

    request_id = request["id"]
    hang_method = sys.argv[1] if len(sys.argv) > 1 else None
    if request["method"] == hang_method:
        while True:
            time.sleep(3600)

    try:
        result = dispatch(request["method"], request["params"])
        write_response({"id": request_id, "ok": True, "result": result})
    except Exception as exc:
        write_response(
            {
                "id": request_id,
                "ok": False,
                "error": {"code": "FAKE_ERROR", "message": str(exc)},
            }
        )

    if request["method"] == "close":
        break