"""GhostNode configuration loading."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_ENV = "GHOSTLINK_CONFIG"
NODE_TOKEN_ENV = "GHOSTLINK_NODE_TOKEN"


@dataclass(frozen=True, slots=True)
class NodeSettings:
    """Runtime settings for a GhostNode process."""

    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "info"
    database_path: Path | None = None
    access_token: str | None = None

    def __post_init__(self) -> None:
        if not self.host.strip():
            raise ValueError("node.host must not be empty")
        if not 1 <= self.port <= 65535:
            raise ValueError("node.port must be between 1 and 65535")
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


def _access_token_from_environment() -> str | None:
    value = os.environ.get(NODE_TOKEN_ENV)
    if value is None or not value.strip():
        return None
    return value


def load_settings(path: str | Path | None = None) -> NodeSettings:
    """Load node settings from TOML and secret values from the environment."""
    resolved_path = Path(path or os.environ.get(DEFAULT_CONFIG_ENV, "ghostlink.toml"))
    access_token = _access_token_from_environment()

    if not resolved_path.exists():
        return NodeSettings(access_token=access_token)

    with resolved_path.open("rb") as config_file:
        document = tomllib.load(config_file)

    node = _node_section(document)
    return NodeSettings(
        host=str(node.get("host", "127.0.0.1")),
        port=int(node.get("port", 8000)),
        log_level=str(node.get("log_level", "info")).lower(),
        database_path=_database_path(node, resolved_path),
        access_token=access_token,
    )
