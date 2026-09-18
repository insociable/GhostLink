"""Local framed-RPC client for the GhostLink libsignal ratchet engine."""

from __future__ import annotations

import base64
import json
import struct
import subprocess
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import IO, Self

from ghostlink.contact import VerifiedContact
from ghostlink.device import EnrolledGhostDevice
from ghostlink.ratchet_binding import (
    RatchetPreKeyBinding,
    RatchetPreKeyMaterial,
    SignedRatchetPreKeyBinding,
    verify_ratchet_prekey_binding,
)

_RPC_VERSION = 1
_MAX_FRAME_BYTES = 2 * 1024 * 1024
_MAX_PAYLOAD_BYTES = 1024 * 1024
_SIGNAL_DEVICE_ID = 1
_MAX_REGISTRATION_ID = 16_380
_MAX_PREKEY_ID = 0x7FFF_FFFF
_EC_PUBLIC_KEY_BYTES = 33
_LIBSIGNAL_SIGNATURE_BYTES = 64
_MAX_KYBER_PUBLIC_KEY_BYTES = 4096


class RatchetEngineError(RuntimeError):
    """Base class for local ratchet-engine failures."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class RatchetEngineConnectionError(RatchetEngineError):
    """Raised when the local ratchet-engine process is unavailable."""


class RatchetEngineProtocolError(RatchetEngineError):
    """Raised when the local ratchet engine violates the RPC protocol."""


@dataclass(frozen=True, slots=True)
class RatchetCiphertext:
    """Opaque libsignal ciphertext returned by the local ratchet engine."""

    message_type: int
    ciphertext: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.message_type, int) or isinstance(
            self.message_type,
            bool,
        ):
            raise ValueError("message_type must be an integer")
        if self.message_type < 0:
            raise ValueError("message_type must be non-negative")
        if not self.ciphertext:
            raise ValueError("ciphertext must not be empty")
        if len(self.ciphertext) > _MAX_FRAME_BYTES:
            raise ValueError("ciphertext exceeds the RPC size limit")


def _require_mapping(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{context} must be a JSON object",
        )

    document: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                f"{context} contains a non-text field name",
            )
        document[key] = item
    return document


def _require_exact_fields(
    document: dict[str, object],
    expected: set[str],
    context: str,
) -> None:
    if set(document) != expected:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{context} fields do not match the RPC protocol",
        )


def _require_integer(
    document: dict[str, object],
    field: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    value = document.get(field)
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or (maximum is not None and value > maximum)
    ):
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{field} is outside the supported integer range",
        )
    return value


def _decode_base64(
    value: object,
    field: str,
    *,
    exact_size: int | None = None,
    max_size: int | None = None,
    allow_empty: bool = False,
) -> bytes:
    if not isinstance(value, str):
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{field} must be Base64 text",
        )
    if not allow_empty and not value:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{field} must not be empty",
        )

    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{field} must be valid Base64",
        ) from exc

    if base64.b64encode(decoded).decode("ascii") != value:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{field} must use canonical Base64",
        )
    if exact_size is not None and len(decoded) != exact_size:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{field} has an invalid decoded length",
        )
    if max_size is not None and len(decoded) > max_size:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            f"{field} exceeds the size limit",
        )
    return decoded


def _encode_base64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _material_to_wire(binding: RatchetPreKeyBinding) -> dict[str, object]:
    return {
        "version": 1,
        "registration_id": binding.registration_id,
        "signal_device_id": binding.signal_device_id,
        "identity_key": _encode_base64(binding.identity_key),
        "pre_key_id": binding.pre_key_id,
        "pre_key": (
            None if binding.pre_key is None else _encode_base64(binding.pre_key)
        ),
        "signed_pre_key_id": binding.signed_pre_key_id,
        "signed_pre_key": _encode_base64(binding.signed_pre_key),
        "signed_pre_key_signature": _encode_base64(
            binding.signed_pre_key_signature,
        ),
        "kyber_pre_key_id": binding.kyber_pre_key_id,
        "kyber_pre_key": _encode_base64(binding.kyber_pre_key),
        "kyber_pre_key_signature": _encode_base64(
            binding.kyber_pre_key_signature,
        ),
    }


def _material_from_wire(value: object) -> RatchetPreKeyMaterial:
    document = _require_mapping(value, "pre-key material")
    expected = {
        "version",
        "registration_id",
        "signal_device_id",
        "identity_key",
        "pre_key_id",
        "pre_key",
        "signed_pre_key_id",
        "signed_pre_key",
        "signed_pre_key_signature",
        "kyber_pre_key_id",
        "kyber_pre_key",
        "kyber_pre_key_signature",
    }
    _require_exact_fields(document, expected, "pre-key material")

    if _require_integer(document, "version", minimum=1) != 1:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            "unsupported pre-key material version",
        )
    if (
        _require_integer(document, "signal_device_id", minimum=1)
        != _SIGNAL_DEVICE_ID
    ):
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            "signal_device_id must equal 1",
        )

    registration_id = _require_integer(
        document,
        "registration_id",
        minimum=1,
        maximum=_MAX_REGISTRATION_ID,
    )

    raw_pre_key_id = document.get("pre_key_id")
    raw_pre_key = document.get("pre_key")
    if raw_pre_key_id is None and raw_pre_key is None:
        pre_key_id = None
        pre_key = None
    elif raw_pre_key_id is None or raw_pre_key is None:
        raise RatchetEngineProtocolError(
            "PROTOCOL_ERROR",
            "pre_key_id and pre_key must both be present or both be null",
        )
    else:
        if not isinstance(raw_pre_key_id, int) or isinstance(
            raw_pre_key_id,
            bool,
        ):
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                "pre_key_id must be an integer",
            )
        if raw_pre_key_id <= 0 or raw_pre_key_id > _MAX_PREKEY_ID:
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                "pre_key_id is outside the supported range",
            )
        pre_key_id = raw_pre_key_id
        pre_key = _decode_base64(
            raw_pre_key,
            "pre_key",
            exact_size=_EC_PUBLIC_KEY_BYTES,
        )

    return RatchetPreKeyMaterial(
        registration_id=registration_id,
        identity_key=_decode_base64(
            document["identity_key"],
            "identity_key",
            exact_size=_EC_PUBLIC_KEY_BYTES,
        ),
        pre_key_id=pre_key_id,
        pre_key=pre_key,
        signed_pre_key_id=_require_integer(
            document,
            "signed_pre_key_id",
            minimum=1,
            maximum=_MAX_PREKEY_ID,
        ),
        signed_pre_key=_decode_base64(
            document["signed_pre_key"],
            "signed_pre_key",
            exact_size=_EC_PUBLIC_KEY_BYTES,
        ),
        signed_pre_key_signature=_decode_base64(
            document["signed_pre_key_signature"],
            "signed_pre_key_signature",
            exact_size=_LIBSIGNAL_SIGNATURE_BYTES,
        ),
        kyber_pre_key_id=_require_integer(
            document,
            "kyber_pre_key_id",
            minimum=1,
            maximum=_MAX_PREKEY_ID,
        ),
        kyber_pre_key=_decode_base64(
            document["kyber_pre_key"],
            "kyber_pre_key",
            max_size=_MAX_KYBER_PUBLIC_KEY_BYTES,
        ),
        kyber_pre_key_signature=_decode_base64(
            document["kyber_pre_key_signature"],
            "kyber_pre_key_signature",
            exact_size=_LIBSIGNAL_SIGNATURE_BYTES,
        ),
    )


class RatchetEngineClient:
    """Own one local libsignal engine process for a GhostLink device."""

    def __init__(
        self,
        command: Sequence[str],
        local_device: EnrolledGhostDevice,
        vault_path: str | Path,
        master_key: bytes,
    ) -> None:
        if not command or any(not part for part in command):
            raise ValueError("command must contain non-empty arguments")
        if len(master_key) != 32:
            raise ValueError("master_key must contain exactly 32 bytes")

        self._lock = threading.Lock()
        self._next_request_id = 1
        self._closed = False

        try:
            process = subprocess.Popen(  # noqa: S603
                list(command),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                bufsize=0,
                close_fds=True,
            )
        except OSError as exc:
            raise RatchetEngineConnectionError(
                "START_FAILED",
                "unable to start local ratchet engine",
            ) from exc

        if process.stdin is None or process.stdout is None:
            process.kill()
            raise RatchetEngineConnectionError(
                "START_FAILED",
                "ratchet engine pipes were not created",
            )

        self._process = process
        self._stdin: IO[bytes] = process.stdin
        self._stdout: IO[bytes] = process.stdout

        key_copy = bytearray(master_key)
        try:
            pong = self._request("ping", {})
            self._require_rpc_version(pong, "ping response")

            opened = self._request(
                "open",
                {
                    "device_id": local_device.device_id,
                    "vault_path": str(vault_path),
                    "master_key": _encode_base64(bytes(key_copy)),
                },
            )
            self._require_rpc_version(opened, "open response")
        except Exception:
            self._terminate()
            raise
        finally:
            key_copy[:] = b"\x00" * len(key_copy)

    @property
    def process_id(self) -> int:
        """Return the child process ID for diagnostics/tests."""
        return self._process.pid

    def _require_rpc_version(self, value: object, context: str) -> None:
        document = _require_mapping(value, context)
        _require_exact_fields(document, {"rpc_version"}, context)
        if _require_integer(document, "rpc_version", minimum=1) != _RPC_VERSION:
            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                "unsupported ratchet RPC version",
            )

    def _read_exact(self, size: int) -> bytes:
        chunks: list[bytes] = []
        remaining = size

        while remaining:
            chunk = self._stdout.read(remaining)
            if not chunk:
                raise RatchetEngineConnectionError(
                    "ENGINE_CLOSED",
                    "ratchet engine closed its output unexpectedly",
                )
            chunks.append(chunk)
            remaining -= len(chunk)

        return b"".join(chunks)

    def _request(self, method: str, params: object) -> object:
        with self._lock:
            if self._closed:
                raise RatchetEngineConnectionError(
                    "ENGINE_CLOSED",
                    "ratchet engine client is closed",
                )
            if self._process.poll() is not None:
                raise RatchetEngineConnectionError(
                    "ENGINE_EXITED",
                    "ratchet engine process is not running",
                )

            request_id = self._next_request_id
            self._next_request_id += 1

            payload = json.dumps(
                {
                    "id": request_id,
                    "method": method,
                    "params": params,
                },
                separators=(",", ":"),
            ).encode("utf-8")

            if not payload or len(payload) > _MAX_FRAME_BYTES:
                raise RatchetEngineProtocolError(
                    "FRAME_TOO_LARGE",
                    "ratchet RPC request exceeds the frame limit",
                )

            try:
                self._stdin.write(struct.pack(">I", len(payload)))
                self._stdin.write(payload)
                self._stdin.flush()
                length = struct.unpack(">I", self._read_exact(4))[0]
                if length == 0 or length > _MAX_FRAME_BYTES:
                    raise RatchetEngineProtocolError(
                        "PROTOCOL_ERROR",
                        "ratchet RPC response frame length is invalid",
                    )
                raw_response = self._read_exact(length)
            except (BrokenPipeError, OSError) as exc:
                raise RatchetEngineConnectionError(
                    "ENGINE_IO",
                    "ratchet engine pipe failed",
                ) from exc

            try:
                parsed: object = json.loads(raw_response.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RatchetEngineProtocolError(
                    "PROTOCOL_ERROR",
                    "ratchet RPC response is not valid UTF-8 JSON",
                ) from exc

            response = _require_mapping(parsed, "RPC response")
            if response.get("id") != request_id:
                raise RatchetEngineProtocolError(
                    "PROTOCOL_ERROR",
                    "ratchet RPC response id does not match request",
                )

            ok = response.get("ok")
            if ok is True:
                _require_exact_fields(
                    response,
                    {"id", "ok", "result"},
                    "successful RPC response",
                )
                return response["result"]

            if ok is False:
                _require_exact_fields(
                    response,
                    {"id", "ok", "error"},
                    "failed RPC response",
                )
                error = _require_mapping(response["error"], "RPC error")
                _require_exact_fields(error, {"code", "message"}, "RPC error")
                code = error.get("code")
                message = error.get("message")
                if (
                    not isinstance(code, str)
                    or not code
                    or not isinstance(message, str)
                    or not message
                ):
                    raise RatchetEngineProtocolError(
                        "PROTOCOL_ERROR",
                        "ratchet RPC error fields are invalid",
                    )
                raise RatchetEngineError(code, message)

            raise RatchetEngineProtocolError(
                "PROTOCOL_ERROR",
                "ratchet RPC response has an invalid ok field",
            )

    def create_prekey_material(self) -> RatchetPreKeyMaterial:
        """Generate and persist fresh public pre-key material."""
        return _material_from_wire(
            self._request("create_prekey_material", {}),
        )

    def establish_session(
        self,
        signed_binding: SignedRatchetPreKeyBinding,
        contact: VerifiedContact,
        *,
        now: int | None = None,
    ) -> None:
        """Verify a GhostLink binding before creating a libsignal session."""
        binding = verify_ratchet_prekey_binding(
            signed_binding,
            contact,
            now=now,
        )
        self._request(
            "establish_session",
            {
                "remote_device_id": contact.device_id,
                "material": _material_to_wire(binding),
            },
        )

    def encrypt(
        self,
        contact: VerifiedContact,
        plaintext: bytes,
    ) -> RatchetCiphertext:
        """Encrypt arbitrary bytes for one already verified contact device."""
        if len(plaintext) > _MAX_PAYLOAD_BYTES:
            raise ValueError("plaintext exceeds the 1 MiB engine limit")

        result = _require_mapping(
            self._request(
                "encrypt",
                {
                    "remote_device_id": contact.device_id,
                    "plaintext": _encode_base64(plaintext),
                },
            ),
            "encrypt result",
        )
        _require_exact_fields(
            result,
            {"message_type", "ciphertext"},
            "encrypt result",
        )
        return RatchetCiphertext(
            message_type=_require_integer(
                result,
                "message_type",
                minimum=0,
            ),
            ciphertext=_decode_base64(
                result["ciphertext"],
                "ciphertext",
                max_size=_MAX_FRAME_BYTES,
            ),
        )

    def decrypt(
        self,
        contact: VerifiedContact,
        message: RatchetCiphertext,
    ) -> bytes:
        """Decrypt one libsignal ciphertext from a verified contact device."""
        result = _require_mapping(
            self._request(
                "decrypt",
                {
                    "remote_device_id": contact.device_id,
                    "message_type": message.message_type,
                    "ciphertext": _encode_base64(message.ciphertext),
                },
            ),
            "decrypt result",
        )
        _require_exact_fields(result, {"plaintext"}, "decrypt result")
        return _decode_base64(
            result["plaintext"],
            "plaintext",
            max_size=_MAX_PAYLOAD_BYTES,
            allow_empty=True,
        )

    def close(self) -> None:
        """Close the vault, erase the engine key buffer, and stop the child."""
        if self._closed:
            return

        try:
            if self._process.poll() is None:
                self._request("close", {})
        finally:
            self._closed = True
            try:
                self._stdin.close()
            except OSError:
                pass
            try:
                self._stdout.close()
            except OSError:
                pass
            if self._process.poll() is None:
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait(timeout=5)

    def _terminate(self) -> None:
        self._closed = True
        try:
            self._stdin.close()
        except OSError:
            pass
        try:
            self._stdout.close()
        except OSError:
            pass
        if self._process.poll() is None:
            self._process.kill()
            self._process.wait(timeout=5)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()