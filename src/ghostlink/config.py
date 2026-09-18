"""GhostNode configuration loading."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_ENV = "GHOSTLINK_CONFIG"
NODE_TOKEN_FILE_ENV = "GHOSTLINK_NODE_TOKEN_FILE"  # noqa: S105 -- env var name only
RELAY_STATE_ID_ENV = "GHOSTLINK_RELAY_STATE_ID"
RELAY_STATE_KEY_FILE_ENV = "GHOSTLINK_RELAY_STATE_KEY_FILE"  # noqa: S105


@dataclass(frozen=True, slots=True)
class NodeSettings:
    """Runtime settings for a GhostNode process."""

    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "info"
    access_log: bool = True
    database_path: Path | None = None
    access_token: str | None = field(default=None, repr=False)
    relay_state_id: str | None = None
    relay_witness_path: Path | None = None
    relay_state_coordination_key: bytes | None = field(default=None, repr=False)
    prekey_fetch_window_seconds: int = 60
    prekey_fetch_max_new_allocations: int = 10

    def __post_init__(self) -> None:
        if not self.host.strip():
            raise ValueError("node.host must not be empty")
        if not 1 <= self.port <= 65535:
            raise ValueError("node.port must be between 1 and 65535")
        if not isinstance(self.access_log, bool):
            raise ValueError("node.access_log must be a boolean")
        if self.log_level not in {
            "critical",
            "error",
            "warning",
            "info",
            "debug",
            "trace",
        }:
            raise ValueError("node.log_level is invalid")
        if self.access_token is not None and not self.access_token.strip():
            raise ValueError("node access token must not be empty")

        relay_values = (
            self.relay_state_id,
            self.relay_witness_path,
            self.relay_state_coordination_key,
        )
        configured_relay_values = sum(value is not None for value in relay_values)
        if configured_relay_values not in {0, 3}:
            raise ValueError(
                "relay_state_id, relay_witness_path and relay-state key "
                "must be configured together"
            )
        if configured_relay_values == 3:
            if self.database_path is None:
                raise ValueError(
                    "relay rollback state requires node.database_path"
                )
            state_id = self.relay_state_id
            if (
                not isinstance(state_id, str)
                or len(state_id) != 32
                or state_id != state_id.lower()
                or any(
                    character not in "0123456789abcdef"
                    for character in state_id
                )
            ):
                raise ValueError(
                    "node.relay_state_id must be 128-bit lowercase hexadecimal"
                )
            if (
                not isinstance(self.relay_state_coordination_key, bytes)
                or len(self.relay_state_coordination_key) != 32
            ):
                raise ValueError(
                    "relay state coordination key must contain exactly 32 bytes"
                )
            relay_witness_path = self.relay_witness_path
            if relay_witness_path is None:
                raise ValueError("node.relay_witness_path is required")
            if relay_witness_path.resolve() == self.database_path.resolve():
                raise ValueError(
                    "node.relay_witness_path must differ from database_path"
                )

        if not 1 <= self.prekey_fetch_window_seconds <= 3_600:
            raise ValueError(
                "node.prekey_fetch_window_seconds must be between 1 and 3600"
            )
        if not 1 <= self.prekey_fetch_max_new_allocations <= 256:
            raise ValueError(
                "node.prekey_fetch_max_new_allocations must be between 1 and 256"
            )


def _node_section(document: dict[str, Any]) -> dict[str, Any]:
    section = document.get("node", {})
    if not isinstance(section, dict):
        raise ValueError("[node] must be a TOML table")
    return section


def _configured_path(
    node: dict[str, Any],
    field_name: str,
    config_path: Path,
) -> Path | None:
    value = node.get(field_name)
    if value is None:
        return None

    path = Path(str(value))
    if not path.is_absolute():
        path = config_path.parent / path

    return path


def _database_path(
    node: dict[str, Any],
    config_path: Path,
) -> Path | None:
    return _configured_path(node, "database_path", config_path)


def _relay_witness_path(
    node: dict[str, Any],
    config_path: Path,
) -> Path | None:
    return _configured_path(node, "relay_witness_path", config_path)


def load_access_token_from_file(path: str | Path | None = None) -> str | None:
    """Load the relay access token from a file, never from argv or environment."""
    resolved = path
    if resolved is None:
        configured = os.environ.get(NODE_TOKEN_FILE_ENV)
        if configured is None or not configured.strip():
            return None
        resolved = configured

    token = Path(resolved).read_text(encoding="utf-8").strip()
    if not token:
        raise ValueError("node access token file must not be empty")
    return token


def load_relay_state_coordination_key_from_file(
    path: str | Path | None = None,
) -> bytes | None:
    """Load the relay-state key from a secret file containing lowercase hex."""
    resolved = path
    if resolved is None:
        configured = os.environ.get(RELAY_STATE_KEY_FILE_ENV)
        if configured is None or not configured.strip():
            return None
        resolved = configured

    encoded = Path(resolved).read_text(encoding="ascii").strip()
    if (
        len(encoded) != 64
        or encoded != encoded.lower()
        or any(character not in "0123456789abcdef" for character in encoded)
    ):
        raise ValueError(
            "relay state key file must contain exactly 32 bytes as lowercase hex"
        )
    return bytes.fromhex(encoded)


def load_settings(path: str | Path | None = None) -> NodeSettings:
    """Load node settings from TOML and secret-file references."""
    resolved_path = Path(path or os.environ.get(DEFAULT_CONFIG_ENV, "ghostlink.toml"))
    access_token = load_access_token_from_file()
    relay_state_key = load_relay_state_coordination_key_from_file()

    if not resolved_path.exists():
        return NodeSettings(
            access_token=access_token,
            relay_state_coordination_key=relay_state_key,
        )

    with resolved_path.open("rb") as config_file:
        document = tomllib.load(config_file)

    node = _node_section(document)
    if "relay_state_coordination_key" in node:
        raise ValueError(
            "relay state coordination key must not be stored in TOML"
        )
    return NodeSettings(
        host=str(node.get("host", "127.0.0.1")),
        port=int(node.get("port", 8000)),
        log_level=str(node.get("log_level", "info")).lower(),
        access_log=node.get("access_log", True),
        database_path=_database_path(node, resolved_path),
        access_token=access_token,
        relay_state_id=(
            os.environ.get(RELAY_STATE_ID_ENV)
            if os.environ.get(RELAY_STATE_ID_ENV)
            else (
                None
                if node.get("relay_state_id") is None
                else str(node["relay_state_id"])
            )
        ),
        relay_witness_path=_relay_witness_path(node, resolved_path),
        relay_state_coordination_key=relay_state_key,
        prekey_fetch_window_seconds=int(
            node.get("prekey_fetch_window_seconds", 60)
        ),
        prekey_fetch_max_new_allocations=int(
            node.get("prekey_fetch_max_new_allocations", 10)
        ),
    )
