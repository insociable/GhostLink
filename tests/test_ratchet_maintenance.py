from typing import cast

import pytest
from ghostlink.client.node_client import (
    GhostNodeClient,
    GhostNodeProtocolError,
    PreKeyPublicationReceipt,
)
from ghostlink.entity import GhostEntity
from ghostlink.prekey_status import PreKeyStatusResponse
from ghostlink.ratchet_engine import (
    RatchetEngineClient,
    RatchetPreKeyGenerationStatus,
    RatchetPreKeyLifecycleStatus,
)
from ghostlink.ratchet_maintenance import (
    RatchetPreKeyMaintenanceError,
    maintain_prekeys,
)


class FakeEngine:
    def __init__(self, status: RatchetPreKeyLifecycleStatus) -> None:
        self.status = status

    def get_prekey_lifecycle_status(self) -> RatchetPreKeyLifecycleStatus:
        return self.status


class FakeNode:
    def __init__(self, status: PreKeyStatusResponse | None) -> None:
        self.status_response = status
        self.status_calls = 0

    def prekey_status(
        self,
        device,
        *,
        issued_at: int | None = None,
        request_id: str | None = None,
    ) -> PreKeyStatusResponse:
        del device, issued_at, request_id
        self.status_calls += 1
        if self.status_response is None:
            raise AssertionError("relay status should not have been requested")
        return self.status_response


def generation_status(
    sequence: int,
    *,
    issued_at: int = 1_000,
    expires_at: int = 10_000,
    published_at: int | None = 1_001,
    staged: bool = True,
) -> RatchetPreKeyGenerationStatus:
    return RatchetPreKeyGenerationStatus(
        publication_sequence=sequence,
        issued_at=issued_at,
        expires_at=expires_at,
        published_at=published_at,
        staged=staged,
    )


def lifecycle_status(
    *,
    sequence: int = 1,
    pending: RatchetPreKeyGenerationStatus | None = None,
    active: RatchetPreKeyGenerationStatus | None = None,
    retired_count: int = 0,
) -> RatchetPreKeyLifecycleStatus:
    return RatchetPreKeyLifecycleStatus(
        publication_sequence=sequence,
        pending=pending,
        active=active,
        retired_count=retired_count,
    )


def relay_status(
    device_id: str,
    *,
    sequence: int = 1,
    expires_at: int = 10_000,
    remaining: int = 100,
) -> PreKeyStatusResponse:
    return PreKeyStatusResponse(
        version=1,
        device_id=device_id,
        publication_sequence=sequence,
        expires_at=expires_at,
        remaining_one_time_count=remaining,
    )


def test_maintenance_leaves_healthy_generation_untouched(monkeypatch) -> None:
    device = GhostEntity.generate().enroll_device()
    engine = FakeEngine(
        lifecycle_status(active=generation_status(1))
    )
    node = FakeNode(
        relay_status(device.device_id, remaining=31)
    )

    def unexpected_publish(*args, **kwargs):
        del args, kwargs
        raise AssertionError("healthy generation must not be republished")

    monkeypatch.setattr(
        "ghostlink.ratchet_maintenance.publish_prekey_generation",
        unexpected_publish,
    )

    result = maintain_prekeys(
        cast(RatchetEngineClient, engine),
        cast(GhostNodeClient, node),
        device,
        now=2_000,
        replenish_threshold=30,
        refresh_before_seconds=1_000,
    )

    assert result.action == "healthy"
    assert result.publication_sequence == 1
    assert result.remaining_one_time_count == 31
    assert node.status_calls == 1


def test_maintenance_applies_cooldown_to_depletion_only(monkeypatch) -> None:
    device = GhostEntity.generate().enroll_device()
    engine = FakeEngine(
        lifecycle_status(
            active=generation_status(
                1,
                published_at=1_900,
            )
        )
    )
    node = FakeNode(
        relay_status(device.device_id, remaining=5)
    )

    def unexpected_publish(*args, **kwargs):
        del args, kwargs
        raise AssertionError("cooldown must prevent depletion-triggered publish")

    monkeypatch.setattr(
        "ghostlink.ratchet_maintenance.publish_prekey_generation",
        unexpected_publish,
    )

    result = maintain_prekeys(
        cast(RatchetEngineClient, engine),
        cast(GhostNodeClient, node),
        device,
        now=2_000,
        replenish_threshold=30,
        replenish_cooldown_seconds=3_600,
        refresh_before_seconds=1_000,
    )

    assert result.action == "cooldown"
    assert result.remaining_one_time_count == 5


@pytest.mark.parametrize(
    ("remaining", "expires_at", "expected_action"),
    [
        (5, 10_000, "replenished"),
        (100, 2_500, "refreshed"),
        (5, 2_500, "refreshed"),
    ],
)
def test_maintenance_publishes_for_depletion_or_expiration(
    monkeypatch,
    remaining: int,
    expires_at: int,
    expected_action: str,
) -> None:
    device = GhostEntity.generate().enroll_device()
    engine = FakeEngine(
        lifecycle_status(
            active=generation_status(
                1,
                expires_at=expires_at,
                published_at=1_000,
            )
        )
    )
    node = FakeNode(
        relay_status(
            device.device_id,
            expires_at=expires_at,
            remaining=remaining,
        )
    )
    calls: list[dict[str, object]] = []

    def publish(*args, **kwargs):
        del args
        calls.append(dict(kwargs))
        return PreKeyPublicationReceipt(
            version=1,
            device_id=device.device_id,
            publication_sequence=2,
            expires_at=9_999,
            one_time_count=100,
        )

    monkeypatch.setattr(
        "ghostlink.ratchet_maintenance.publish_prekey_generation",
        publish,
    )

    result = maintain_prekeys(
        cast(RatchetEngineClient, engine),
        cast(GhostNodeClient, node),
        device,
        now=2_000,
        replenish_threshold=30,
        replenish_cooldown_seconds=100,
        refresh_before_seconds=1_000,
    )

    assert result.action == expected_action
    assert result.publication_sequence == 2
    assert result.remaining_one_time_count == 100
    assert calls == [
        {
            "one_time_count": 100,
            "issued_at": 2_000,
            "lifetime_seconds": 7 * 24 * 60 * 60,
            "acknowledged_at": 2_000,
        }
    ]


@pytest.mark.parametrize(
    ("relay_sequence", "relay_expires", "message"),
    [
        (2, 10_000, "sequence does not match"),
        (1, 10_001, "expiration does not match"),
    ],
)
def test_maintenance_rejects_relay_local_divergence(
    monkeypatch,
    relay_sequence: int,
    relay_expires: int,
    message: str,
) -> None:
    device = GhostEntity.generate().enroll_device()
    engine = FakeEngine(
        lifecycle_status(active=generation_status(1))
    )
    node = FakeNode(
        relay_status(
            device.device_id,
            sequence=relay_sequence,
            expires_at=relay_expires,
            remaining=0,
        )
    )

    def unexpected_publish(*args, **kwargs):
        del args, kwargs
        raise AssertionError("divergent relay state must not trigger publish")

    monkeypatch.setattr(
        "ghostlink.ratchet_maintenance.publish_prekey_generation",
        unexpected_publish,
    )

    with pytest.raises(GhostNodeProtocolError, match=message):
        maintain_prekeys(
            cast(RatchetEngineClient, engine),
            cast(GhostNodeClient, node),
            device,
            now=2_000,
        )


def test_maintenance_resumes_pending_before_reading_relay(monkeypatch) -> None:
    device = GhostEntity.generate().enroll_device()
    pending = generation_status(
        2,
        published_at=None,
        staged=True,
    )
    engine = FakeEngine(
        lifecycle_status(
            sequence=2,
            pending=pending,
            active=generation_status(1),
        )
    )
    node = FakeNode(None)

    def publish(*args, **kwargs):
        del args, kwargs
        return PreKeyPublicationReceipt(
            version=1,
            device_id=device.device_id,
            publication_sequence=2,
            expires_at=10_000,
            one_time_count=100,
        )

    monkeypatch.setattr(
        "ghostlink.ratchet_maintenance.publish_prekey_generation",
        publish,
    )

    result = maintain_prekeys(
        cast(RatchetEngineClient, engine),
        cast(GhostNodeClient, node),
        device,
        now=2_000,
    )

    assert result.action == "resumed_pending"
    assert result.publication_sequence == 2
    assert node.status_calls == 0


def test_maintenance_blocks_new_publish_when_retired_history_is_full(
    monkeypatch,
) -> None:
    device = GhostEntity.generate().enroll_device()
    engine = FakeEngine(
        lifecycle_status(
            active=generation_status(1),
            retired_count=32,
        )
    )
    node = FakeNode(None)

    def unexpected_publish(*args, **kwargs):
        del args, kwargs
        raise AssertionError("full retired history must block publication")

    monkeypatch.setattr(
        "ghostlink.ratchet_maintenance.publish_prekey_generation",
        unexpected_publish,
    )

    with pytest.raises(
        RatchetPreKeyMaintenanceError,
        match="garbage collection is required",
    ):
        maintain_prekeys(
            cast(RatchetEngineClient, engine),
            cast(GhostNodeClient, node),
            device,
            now=2_000,
        )
