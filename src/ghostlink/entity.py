"""GhostLink cryptographic entity."""

from __future__ import annotations

from dataclasses import dataclass

from nacl.signing import SigningKey, VerifyKey

from ghostlink.identity import derive_ghost_id


@dataclass(frozen=True, slots=True)
class GhostEntity:
    """A GhostLink entity controlled by a long-term Ed25519 key."""

    signing_key: SigningKey

    @classmethod
    def generate(cls) -> GhostEntity:
        """Generate a new GhostEntity locally."""
        return cls(signing_key=SigningKey.generate())

    @property
    def verify_key(self) -> VerifyKey:
        """Return the public identity verification key."""
        return self.signing_key.verify_key

    @property
    def ghost_id(self) -> str:
        """Return the entity's self-certifying GhostID."""
        return derive_ghost_id(bytes(self.verify_key))