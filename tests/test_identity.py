import pytest
from ghostlink.identity import (
    Identity,
    derive_ghost_id,
    format_ghost_id_fingerprint,
)


def test_identity_generates_a_versioned_ghost_id() -> None:
    identity = Identity.generate()

    assert identity.ghost_id.startswith("ghost1:")
    assert len(identity.ghost_id) == 59


def test_same_public_key_always_produces_same_ghost_id() -> None:
    identity = Identity.generate()
    public_key = bytes(identity.verify_key)

    first = derive_ghost_id(public_key)
    second = derive_ghost_id(public_key)

    assert first == second
    assert first == identity.ghost_id


def test_distinct_identities_have_distinct_ghost_ids() -> None:
    alice = Identity.generate()
    bob = Identity.generate()

    assert alice.ghost_id != bob.ghost_id


def test_invalid_public_key_length_is_rejected() -> None:
    with pytest.raises(
        ValueError,
        match="Ed25519 public key must contain exactly 32 bytes",
    ):
        derive_ghost_id(b"invalid")


def test_fingerprint_is_full_grouped_ghost_id_payload() -> None:
    identity = Identity.generate()

    fingerprint = format_ghost_id_fingerprint(identity.ghost_id)

    assert fingerprint.replace("-", "") == identity.ghost_id.removeprefix(
        "ghost1:"
    ).upper()
    assert len(fingerprint.split("-")) == 13
    assert all(len(group) == 4 for group in fingerprint.split("-"))


@pytest.mark.parametrize(
    "ghost_id",
    [
        "invalid",
        "ghost1:short",
        "ghost1:" + ("A" * 52),
        "ghost1:" + ("0" * 52),
    ],
)
def test_fingerprint_rejects_invalid_ghost_ids(ghost_id: str) -> None:
    with pytest.raises(ValueError):
        format_ghost_id_fingerprint(ghost_id)
