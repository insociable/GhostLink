#!/usr/bin/env python3
"""External transport validation gate for a public GhostLink node."""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
from dataclasses import dataclass

_DEFAULT_TIMEOUT = 5.0
_CLOSED_PORTS = (80, 8000)
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ValidationError(RuntimeError):
    """Raised when the external public-node validation gate fails."""


@dataclass(frozen=True, slots=True)
class ResolvedAddress:
    """One DNS address used for direct transport checks."""

    family: socket.AddressFamily
    address: str


def _hostname(value: str) -> str:
    candidate = value.strip().rstrip(".")
    if not candidate:
        raise argparse.ArgumentTypeError("hostname must not be empty")
    if any(character.isspace() for character in candidate):
        raise argparse.ArgumentTypeError("hostname must not contain whitespace")
    if any(marker in candidate for marker in ("://", "/", "\\", "@", ":")):
        raise argparse.ArgumentTypeError("provide a DNS hostname, not a URL or IP literal")

    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise argparse.ArgumentTypeError("provide a DNS hostname, not an IP literal")

    try:
        ascii_hostname = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise argparse.ArgumentTypeError("hostname is not valid IDNA text") from exc

    if len(ascii_hostname) > 253 or "." not in ascii_hostname:
        raise argparse.ArgumentTypeError("hostname must be a public-style DNS name")

    labels = ascii_hostname.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise argparse.ArgumentTypeError("hostname contains an invalid DNS label")
    return ascii_hostname


def _expected_address(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected address must be IPv4 or IPv6") from exc


def _resolve(hostname: str) -> tuple[ResolvedAddress, ...]:
    try:
        answers = socket.getaddrinfo(
            hostname,
            443,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValidationError(f"DNS resolution failed for {hostname}: {exc}") from exc

    resolved: dict[tuple[socket.AddressFamily, str], ResolvedAddress] = {}
    for family, _socktype, _proto, _canonname, sockaddr in answers:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        address = str(ipaddress.ip_address(sockaddr[0]))
        resolved[(family, address)] = ResolvedAddress(family, address)

    if not resolved:
        raise ValidationError(f"DNS returned no usable A/AAAA address for {hostname}")
    return tuple(sorted(resolved.values(), key=lambda item: (item.family, item.address)))


def _sockaddr(address: ResolvedAddress, port: int) -> tuple[object, ...]:
    if address.family == socket.AF_INET6:
        return (address.address, port, 0, 0)
    return (address.address, port)


def _tcp_open(address: ResolvedAddress, port: int, timeout: float) -> bool:
    with socket.socket(address.family, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        try:
            return connection.connect_ex(_sockaddr(address, port)) == 0
        except OSError:
            return False


def _validate_tls(
    hostname: str,
    address: ResolvedAddress,
    timeout: float,
) -> str:
    context = ssl.create_default_context()
    try:
        with socket.socket(address.family, socket.SOCK_STREAM) as raw_socket:
            raw_socket.settimeout(timeout)
            raw_socket.connect(_sockaddr(address, 443))
            with context.wrap_socket(
                raw_socket,
                server_hostname=hostname,
            ) as tls_socket:
                version = tls_socket.version()
                if version is None:
                    raise ValidationError(
                        f"TLS negotiation returned no protocol for {address.address}"
                    )
                return version
    except (OSError, ssl.SSLError) as exc:
        raise ValidationError(
            f"TLS hostname/chain validation failed on {address.address}: {exc}"
        ) from exc


def _validate_health(hostname: str, timeout: float) -> None:
    context = ssl.create_default_context()
    connection = http.client.HTTPSConnection(
        hostname,
        port=443,
        timeout=timeout,
        context=context,
    )
    try:
        connection.request(
            "GET",
            "/health",
            headers={
                "Accept": "application/json",
                "User-Agent": "GhostLink-external-validation/1",
            },
        )
        response = connection.getresponse()
        body = response.read(4097)
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise ValidationError(f"HTTPS /health request failed: {exc}") from exc
    finally:
        connection.close()

    if response.status != 200:
        raise ValidationError(f"HTTPS /health returned HTTP {response.status}")
    if len(body) > 4096:
        raise ValidationError("HTTPS /health response exceeded 4096 bytes")

    try:
        document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("HTTPS /health did not return valid JSON") from exc
    if document != {"status": "ok"}:
        raise ValidationError(f"unexpected HTTPS /health body: {document!r}")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate DNS, TCP/443, public TLS, closed TCP/80+8000 and HTTPS "
            "/health for a GhostLink node from an external machine."
        )
    )
    parser.add_argument("hostname", type=_hostname)
    parser.add_argument(
        "--expect-address",
        action="append",
        default=[],
        type=_expected_address,
        help=(
            "expected public IPv4/IPv6 address; repeat for every intended DNS "
            "address. When supplied, the resolved set must match exactly."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=_DEFAULT_TIMEOUT,
        help=f"per-connection timeout in seconds (default: {_DEFAULT_TIMEOUT:g})",
    )
    return parser.parse_args(argv)


def run(argv: list[str] | None = None) -> int:
    """Run the external validation gate."""
    args = _parse_args(argv)
    if not 0.1 <= args.timeout <= 30.0:
        raise ValidationError("--timeout must be between 0.1 and 30 seconds")

    addresses = _resolve(args.hostname)
    resolved_set = {item.address for item in addresses}
    expected_set = set(args.expect_address)
    if expected_set and resolved_set != expected_set:
        raise ValidationError(
            "DNS address set mismatch: "
            f"expected={sorted(expected_set)!r} resolved={sorted(resolved_set)!r}"
        )

    print(f"[ok] DNS {args.hostname} -> {', '.join(sorted(resolved_set))}")

    for address in addresses:
        if not _tcp_open(address, 443, args.timeout):
            raise ValidationError(f"TCP/443 is unreachable on {address.address}")
        tls_version = _validate_tls(args.hostname, address, args.timeout)
        print(f"[ok] {address.address}:443 reachable with valid {tls_version}")

    for port in _CLOSED_PORTS:
        for address in addresses:
            if _tcp_open(address, port, args.timeout):
                raise ValidationError(
                    f"TCP/{port} is publicly reachable on {address.address}"
                )
        print(f"[ok] TCP/{port} unreachable on every resolved address")

    _validate_health(args.hostname, args.timeout)
    print("[ok] HTTPS /health returned exactly {\"status\": \"ok\"}")
    print("External transport gate passed.")
    print(
        "Protocol-v3 prekey-sync/send/inbox validation is still required "
        "before issue #21 can close."
    )
    return 0


def main() -> None:
    """CLI entry point."""
    try:
        raise SystemExit(run())
    except ValidationError as exc:
        print(f"[fail] {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
