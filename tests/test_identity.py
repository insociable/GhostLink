import pytest
from ghostlink.identity import Identity, derive_ghost_id


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