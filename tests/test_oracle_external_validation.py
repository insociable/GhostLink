from __future__ import annotations

import importlib.util
import socket
import sys
from pathlib import Path

import pytest

_VALIDATOR_PATH = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "oracle"
    / "validate_external.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "ghostlink_oracle_validate_external",
    _VALIDATOR_PATH,
)
assert _SPEC is not None
assert _SPEC.loader is not None
validator = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = validator
_SPEC.loader.exec_module(validator)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "localhost",
        "https://node.example.net",
        "127.0.0.1",
        "2001:db8::1",
        "node.example.net/path",
        "user@node.example.net",
    ],
)
def test_hostname_rejects_non_dns_hostnames(value: str) -> None:
    with pytest.raises(validator.argparse.ArgumentTypeError):
        validator._hostname(value)


def test_hostname_normalizes_case_and_trailing_dot() -> None:
    assert validator._hostname("Node.Example.NET.") == "node.example.net"


def test_expected_address_normalizes_ipv6() -> None:
    assert validator._expected_address("2001:0db8::1") == "2001:db8::1"


def test_run_validates_every_address_and_closed_ports(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    addresses = (
        validator.ResolvedAddress(socket.AF_INET, "203.0.113.10"),
        validator.ResolvedAddress(socket.AF_INET6, "2001:db8::10"),
    )
    tcp_calls: list[tuple[str, int]] = []
    tls_calls: list[str] = []
    health_calls: list[str] = []

    monkeypatch.setattr(validator, "_resolve", lambda hostname: addresses)

    def fake_tcp_open(address, port: int, timeout: float) -> bool:
        del timeout
        tcp_calls.append((address.address, port))
        return port == 443

    monkeypatch.setattr(validator, "_tcp_open", fake_tcp_open)

    def fake_validate_tls(hostname: str, address, timeout: float) -> str:
        del hostname, timeout
        tls_calls.append(address.address)
        return "TLSv1.3"

    monkeypatch.setattr(validator, "_validate_tls", fake_validate_tls)

    def fake_validate_health(hostname: str, timeout: float) -> None:
        del timeout
        health_calls.append(hostname)

    monkeypatch.setattr(validator, "_validate_health", fake_validate_health)

    result = validator.run(
        [
            "node.example.net",
            "--expect-address",
            "203.0.113.10",
            "--expect-address",
            "2001:db8::10",
        ]
    )

    assert result == 0

    assert tls_calls == ["203.0.113.10", "2001:db8::10"]
    assert health_calls == ["node.example.net"]
    for address in ("203.0.113.10", "2001:db8::10"):
        assert (address, 443) in tcp_calls
        assert (address, 80) in tcp_calls
        assert (address, 8000) in tcp_calls
    assert "External transport gate passed." in capsys.readouterr().out


def test_run_rejects_dns_address_set_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        validator,
        "_resolve",
        lambda hostname: (
            validator.ResolvedAddress(socket.AF_INET, "203.0.113.10"),
        ),
    )

    with pytest.raises(validator.ValidationError, match="DNS address set mismatch"):

        validator.run(
            [
                "node.example.net",
                "--expect-address",
                "203.0.113.11",
            ]
        )


def test_run_rejects_unreachable_tls_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    address = validator.ResolvedAddress(socket.AF_INET, "203.0.113.10")
    monkeypatch.setattr(validator, "_resolve", lambda hostname: (address,))
    monkeypatch.setattr(
        validator,
        "_tcp_open",
        lambda resolved, port, timeout: False,
    )

    with pytest.raises(validator.ValidationError, match="TCP/443 is unreachable"):
        validator.run(["node.example.net"])


def test_run_rejects_publicly_exposed_port_80(

    monkeypatch: pytest.MonkeyPatch,
) -> None:
    address = validator.ResolvedAddress(socket.AF_INET, "203.0.113.10")
    monkeypatch.setattr(validator, "_resolve", lambda hostname: (address,))
    monkeypatch.setattr(
        validator,
        "_tcp_open",
        lambda resolved, port, timeout: port in {443, 80},
    )
    monkeypatch.setattr(
        validator,
        "_validate_tls",
        lambda hostname, resolved, timeout: "TLSv1.3",
    )

    with pytest.raises(
        validator.ValidationError,
        match="TCP/80 is publicly reachable",
    ):
        validator.run(["node.example.net"])


@pytest.mark.parametrize("timeout", ["0", "0.09", "30.1"])
def test_run_rejects_timeout_outside_bounds(

    monkeypatch: pytest.MonkeyPatch,
    timeout: str,
) -> None:
    monkeypatch.setattr(validator, "_resolve", lambda hostname: ())
    with pytest.raises(validator.ValidationError, match="--timeout"):
        validator.run(["node.example.net", "--timeout", timeout])


class _FakeResponse:
    status = 200

    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, limit: int) -> bytes:
        assert limit == 4097
        return self._body


class _FakeHttpsConnection:
    body = b'{"status":"ok"}'

    def __init__(self, *args, **kwargs) -> None:
        self.closed = False

    def request(self, method: str, path: str, headers: dict[str, str]) -> None:

        assert method == "GET"
        assert path == "/health"
        assert headers["Accept"] == "application/json"

    def getresponse(self) -> _FakeResponse:
        return _FakeResponse(self.body)

    def close(self) -> None:
        self.closed = True


def test_validate_health_requires_exact_expected_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        validator.http.client,
        "HTTPSConnection",
        _FakeHttpsConnection,
    )
    validator._validate_health("node.example.net", 1.0)

    _FakeHttpsConnection.body = b'{"status":"degraded"}'
    try:
        with pytest.raises(validator.ValidationError, match="unexpected"):
            validator._validate_health("node.example.net", 1.0)
    finally:
        _FakeHttpsConnection.body = b'{"status":"ok"}'
