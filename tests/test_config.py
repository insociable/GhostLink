from pathlib import Path

import pytest
from ghostlink.config import NODE_TOKEN_ENV, NodeSettings, load_settings


def test_missing_config_uses_safe_local_defaults(tmp_path: Path) -> None:
    settings = load_settings(tmp_path / "missing.toml")

    assert settings == NodeSettings()


def test_settings_are_loaded_from_toml(tmp_path: Path) -> None:
    config_path = tmp_path / "ghostlink.toml"
    config_path.write_text(
        (
            '[node]\n'
            'host = "0.0.0.0"\n'
            'port = 9000\n'
            'log_level = "DEBUG"\n'
            'database_path = "data/messages.sqlite3"\n'
        ),  # noqa: S104
        encoding="utf-8",
    )

    settings = load_settings(config_path)

    assert settings == NodeSettings(
        host="0.0.0.0",  # noqa: S104
        port=9000,
        log_level="debug",
        database_path=tmp_path / "data/messages.sqlite3",
    )


def test_absolute_database_path_is_preserved(tmp_path: Path) -> None:
    database_path = tmp_path / "messages.sqlite3"
    config_path = tmp_path / "ghostlink.toml"
    config_path.write_text(
        f'[node]\ndatabase_path = "{database_path}"\n',
        encoding="utf-8",
    )

    settings = load_settings(config_path)

    assert settings.database_path == database_path


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


def test_access_token_is_loaded_from_environment(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(NODE_TOKEN_ENV, "server-secret")

    settings = load_settings(tmp_path / "missing.toml")

    assert settings.access_token == "server-secret"  # noqa: S105


def test_blank_access_token_disables_authentication(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(NODE_TOKEN_ENV, "   ")

    settings = load_settings(tmp_path / "missing.toml")

    assert settings.access_token is None


def test_whitespace_access_token_is_rejected() -> None:
    with pytest.raises(ValueError, match="access token"):
        NodeSettings(access_token="   ")  # noqa: S106
