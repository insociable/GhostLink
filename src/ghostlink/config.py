"""GhostNode configuration loading."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_ENV = "GHOSTLINK_CONFIG"


@dataclass(frozen=True, slots=True)
class NodeSettings:
    """Runtime settings for a GhostNode process."""

    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "info"

    def __post_init__(self) -> None:
        if not self.host.strip():
            raise ValueError("node.host must not be empty")
        if not 1 <= self.port <= 65535:
            raise ValueError("node.port must be between 1 and 65535")
        if self.log_level not in {"critical", "error", "warning", "info", "debug", "trace"}:
            raise ValueError("node.log_level is invalid")


def _node_section(document: dict[str, Any]) -> dict[str, Any]:
    section = document.get("node", {})
    if not isinstance(section, dict):
        raise ValueError("[node] must be a TOML table")
    return section


def load_settings(path: str | Path | None = None) -> NodeSettings:
    """Load node settings from TOML, or return safe local defaults."""
    resolved_path = Path(path or os.environ.get(DEFAULT_CONFIG_ENV, "ghostlink.toml"))
    if not resolved_path.exists():
        return NodeSettings()

    with resolved_path.open("rb") as config_file:
        document = tomllib.load(config_file)

    node = _node_section(document)
    return NodeSettings(
        host=str(node.get("host", "127.0.0.1")),
        port=int(node.get("port", 8000)),
        log_level=str(node.get("log_level", "info")).lower(),
    )
