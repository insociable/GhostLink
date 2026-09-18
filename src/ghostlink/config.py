"""GhostNode configuration loading."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_ENV = "GHOSTLINK_CONFIG"
NODE_TOKEN_FILE_ENV = "GHOSTLINK_NODE_TOKEN_FILE"


@dataclass(frozen=True, slots=True)
class NodeSettings:
    """Runtime settings for a GhostNode process."""

    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "info"
    access_log: bool = True
    database_path: Path | None = None
    access_token: str | None = None
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


def _database_path(
    node: dict[str, Any],
    config_path: Path,
) -> Path | None:
    value = node.get("database_path")
    if value is None:
        return None

    path = Path(str(value))
    if not path.is_absolute():
        path = config_path.parent / path

    return path


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


def load_settings(path: str | Path | None = None) -> NodeSettings:
    """Load node settings from TOML and secret-file references."""
    resolved_path = Path(path or os.environ.get(DEFAULT_CONFIG_ENV, "ghostlink.toml"))
    access_token = load_access_token_from_file()

    if not resolved_path.exists():
        return NodeSettings(access_token=access_token)

    with resolved_path.open("rb") as config_file:
        document = tomllib.load(config_file)

    node = _node_section(document)
    return NodeSettings(
        host=str(node.get("host", "127.0.0.1")),
        port=int(node.get("port", 8000)),
        log_level=str(node.get("log_level", "info")).lower(),
        access_log=node.get("access_log", True),
        database_path=_database_path(node, resolved_path),
        access_token=access_token,
        prekey_fetch_window_seconds=int(
            node.get("prekey_fetch_window_seconds", 60)
        ),
        prekey_fetch_max_new_allocations=int(
            node.get("prekey_fetch_max_new_allocations", 10)
        ),
    )
