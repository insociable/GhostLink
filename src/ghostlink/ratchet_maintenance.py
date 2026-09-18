"""Operational ratchet pre-key replenishment and rotation orchestration."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Literal

from ghostlink.client.node_client import GhostNodeClient, GhostNodeProtocolError
from ghostlink.device import EnrolledGhostDevice
from ghostlink.ratchet_engine import RatchetEngineClient
from ghostlink.ratchet_publish import publish_prekey_generation

_DEFAULT_POOL_TARGET = 100
_DEFAULT_REPLENISH_THRESHOLD = 30
_DEFAULT_REFRESH_BEFORE_SECONDS = 48 * 60 * 60
_DEFAULT_REPLENISH_COOLDOWN_SECONDS = 60 * 60
_DEFAULT_LIFETIME_SECONDS = 7 * 24 * 60 * 60
_MAX_POOL_SIZE = 256
_MAX_RETIRED_GENERATIONS = 32

MaintenanceAction = Literal[
    "published_initial",
    "resumed_pending",
    "healthy",
    "cooldown",
    "replenished",
    "refreshed",
]


class RatchetPreKeyMaintenanceError(RuntimeError):
    """Raised when automatic pre-key maintenance cannot proceed safely."""


@dataclass(frozen=True, slots=True)
class RatchetPreKeyMaintenanceResult:
    """Result of one deterministic pre-key maintenance pass."""

    action: MaintenanceAction
    publication_sequence: int
    remaining_one_time_count: int | None


def _validate_policy(
    *,
    pool_target: int,
    replenish_threshold: int,
    refresh_before_seconds: int,
    replenish_cooldown_seconds: int,
    lifetime_seconds: int,
) -> None:
    if (
        not isinstance(pool_target, int)
        or isinstance(pool_target, bool)
        or not 1 <= pool_target <= _MAX_POOL_SIZE
    ):
        raise ValueError("pool_target must be between 1 and 256")
    if (
        not isinstance(replenish_threshold, int)
        or isinstance(replenish_threshold, bool)
        or replenish_threshold < 0
        or replenish_threshold >= pool_target
    ):
        raise ValueError(
            "replenish_threshold must be between 0 and pool_target - 1"
        )
    if (
        not isinstance(lifetime_seconds, int)
        or isinstance(lifetime_seconds, bool)
        or not 1 <= lifetime_seconds <= _DEFAULT_LIFETIME_SECONDS
    ):
        raise ValueError("lifetime_seconds must be between 1 and seven days")
    if (
        not isinstance(refresh_before_seconds, int)
        or isinstance(refresh_before_seconds, bool)
        or refresh_before_seconds < 0
        or refresh_before_seconds >= lifetime_seconds
    ):
        raise ValueError(
            "refresh_before_seconds must be non-negative and below lifetime"
        )
    if (
        not isinstance(replenish_cooldown_seconds, int)
        or isinstance(replenish_cooldown_seconds, bool)
        or replenish_cooldown_seconds < 0
        or replenish_cooldown_seconds > lifetime_seconds
    ):
        raise ValueError(
            "replenish_cooldown_seconds must be between 0 and lifetime"
        )


def maintain_prekeys(
    engine: RatchetEngineClient,
    node: GhostNodeClient,
    device: EnrolledGhostDevice,
    *,
    now: int | None = None,
    pool_target: int = _DEFAULT_POOL_TARGET,
    replenish_threshold: int = _DEFAULT_REPLENISH_THRESHOLD,
    refresh_before_seconds: int = _DEFAULT_REFRESH_BEFORE_SECONDS,
    replenish_cooldown_seconds: int = _DEFAULT_REPLENISH_COOLDOWN_SECONDS,
    lifetime_seconds: int = _DEFAULT_LIFETIME_SECONDS,
) -> RatchetPreKeyMaintenanceResult:
    """Perform one fail-closed local/relay pre-key maintenance pass."""
    _validate_policy(
        pool_target=pool_target,
        replenish_threshold=replenish_threshold,
        refresh_before_seconds=refresh_before_seconds,
        replenish_cooldown_seconds=replenish_cooldown_seconds,
        lifetime_seconds=lifetime_seconds,
    )
    current_time = int(time.time()) if now is None else now
    if (
        not isinstance(current_time, int)
        or isinstance(current_time, bool)
        or current_time < 0
    ):
        raise ValueError("now must be a non-negative integer")

    local = engine.get_prekey_lifecycle_status()

    if local.retired_count >= _MAX_RETIRED_GENERATIONS:
        raise RatchetPreKeyMaintenanceError(
            "retired generation limit reached; garbage collection is required"
        )

    if local.pending is not None:
        receipt = publish_prekey_generation(
            engine,
            node,
            device,
            one_time_count=pool_target,
            issued_at=current_time,
            lifetime_seconds=lifetime_seconds,
            acknowledged_at=current_time,
        )
        return RatchetPreKeyMaintenanceResult(
            action="resumed_pending",
            publication_sequence=receipt.publication_sequence,
            remaining_one_time_count=receipt.one_time_count,
        )

    active = local.active
    if active is None:
        receipt = publish_prekey_generation(
            engine,
            node,
            device,
            one_time_count=pool_target,
            issued_at=current_time,
            lifetime_seconds=lifetime_seconds,
            acknowledged_at=current_time,
        )
        return RatchetPreKeyMaintenanceResult(
            action="published_initial",
            publication_sequence=receipt.publication_sequence,
            remaining_one_time_count=receipt.one_time_count,
        )

    relay = node.prekey_status(device, issued_at=current_time)
    if relay.publication_sequence != active.publication_sequence:
        raise GhostNodeProtocolError(
            "relay pre-key sequence does not match the local active generation"
        )
    if relay.expires_at != active.expires_at:
        raise GhostNodeProtocolError(
            "relay pre-key expiration does not match the local active generation"
        )

    remaining = relay.remaining_one_time_count
    refresh_due = active.expires_at - current_time <= refresh_before_seconds
    replenish_due = remaining <= replenish_threshold

    if not refresh_due and not replenish_due:
        return RatchetPreKeyMaintenanceResult(
            action="healthy",
            publication_sequence=active.publication_sequence,
            remaining_one_time_count=remaining,
        )

    if replenish_due and not refresh_due:
        if active.published_at is None:
            raise RatchetPreKeyMaintenanceError(
                "active generation is missing its publication timestamp"
            )
        if current_time < active.published_at:
            raise RatchetPreKeyMaintenanceError(
                "local clock precedes the active publication timestamp"
            )
        if (
            current_time - active.published_at
            < replenish_cooldown_seconds
        ):
            return RatchetPreKeyMaintenanceResult(
                action="cooldown",
                publication_sequence=active.publication_sequence,
                remaining_one_time_count=remaining,
            )

    receipt = publish_prekey_generation(
        engine,
        node,
        device,
        one_time_count=pool_target,
        issued_at=current_time,
        lifetime_seconds=lifetime_seconds,
        acknowledged_at=current_time,
    )
    return RatchetPreKeyMaintenanceResult(
        action="refreshed" if refresh_due else "replenished",
        publication_sequence=receipt.publication_sequence,
        remaining_one_time_count=receipt.one_time_count,
    )
