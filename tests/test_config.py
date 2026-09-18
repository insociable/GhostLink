from pathlib import Path

import pytest
from ghostlink.config import (
    NODE_TOKEN_FILE_ENV,
    NodeSettings,
    load_access_token_from_file,
    load_settings,
)


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
            'access_log = false\n'
            'database_path = "data/messages.sqlite3"\n'
            'prekey_fetch_window_seconds = 120\n'
            'prekey_fetch_max_new_allocations = 7\n'
        ),  # noqa: S104
        encoding="utf-8",
    )

    settings = load_settings(config_path)

    assert settings == NodeSettings(
        host="0.0.0.0",  # noqa: S104
        port=9000,
        log_level="debug",
        access_log=False,
        database_path=tmp_path / "data/messages.sqlite3",
        prekey_fetch_window_seconds=120,
        prekey_fetch_max_new_allocations=7,
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


def test_access_token_is_loaded_from_secret_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    token_file = tmp_path / "relay-token"
    token_file.write_text("server-secret\n", encoding="utf-8")
    monkeypatch.setenv(NODE_TOKEN_FILE_ENV, str(token_file))

    settings = load_settings(tmp_path / "missing.toml")

    assert settings.access_token == "server-secret"  # noqa: S105


def test_blank_token_file_reference_disables_authentication(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv(NODE_TOKEN_FILE_ENV, "   ")

    settings = load_settings(tmp_path / "missing.toml")

    assert settings.access_token is None


def test_empty_access_token_file_is_rejected(tmp_path: Path) -> None:
    token_file = tmp_path / "relay-token"
    token_file.write_text("\n", encoding="utf-8")

    with pytest.raises(ValueError, match="access token file"):
        load_access_token_from_file(token_file)


def test_whitespace_access_token_is_rejected() -> None:
    with pytest.raises(ValueError, match="access token"):
        NodeSettings(access_token="   ")  # noqa: S106



@pytest.mark.parametrize("window", [0, 3601])
def test_invalid_prekey_fetch_window_is_rejected(window: int) -> None:
    with pytest.raises(ValueError, match="prekey_fetch_window_seconds"):
        NodeSettings(prekey_fetch_window_seconds=window)


@pytest.mark.parametrize("limit", [0, 257])
def test_invalid_prekey_fetch_allocation_limit_is_rejected(limit: int) -> None:
    with pytest.raises(ValueError, match="prekey_fetch_max_new_allocations"):
        NodeSettings(prekey_fetch_max_new_allocations=limit)


def test_access_log_defaults_to_enabled_for_development() -> None:
    assert NodeSettings().access_log is True


def test_invalid_access_log_value_is_rejected() -> None:
    with pytest.raises(ValueError, match="node.access_log"):
        NodeSettings(access_log="false")  # type: ignore[arg-type]
