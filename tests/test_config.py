from pathlib import Path

import pytest
from ghostlink.config import NodeSettings, load_settings


def test_missing_config_uses_safe_local_defaults(tmp_path: Path) -> None:
    settings = load_settings(tmp_path / "missing.toml")

    assert settings == NodeSettings()


def test_settings_are_loaded_from_toml(tmp_path: Path) -> None:
    config_path = tmp_path / "ghostlink.toml"
    config_path.write_text(
        '[node]\nhost = "0.0.0.0"\nport = 9000\nlog_level = "DEBUG"\n',  # noqa: S104
        encoding="utf-8",
    )

    settings = load_settings(config_path)

    assert settings == NodeSettings(
        host="0.0.0.0",  # noqa: S104
        port=9000,
        log_level="debug",
    )


@pytest.mark.parametrize("port", [0, 65536])
def test_invalid_port_is_rejected(port: int) -> None:
    with pytest.raises(ValueError, match="node.port"):
        NodeSettings(port=port)


def test_empty_host_is_rejected() -> None:
    with pytest.raises(ValueError, match="node.host"):
        NodeSettings(host="   ")


def test_invalid_log_level_is_rejected() -> None:
    with pytest.raises(ValueError, match="node.log_level"):
        NodeSettings(log_level="verbose")


def test_node_section_must_be_a_table(tmp_path: Path) -> None:
    config_path = tmp_path / "ghostlink.toml"
    config_path.write_text('node = "invalid"\n', encoding="utf-8")

    with pytest.raises(ValueError, match=r"\[node\]"):
        load_settings(config_path)
