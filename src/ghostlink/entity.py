"""GhostLink cryptographic entity."""

from __future__ import annotations

from dataclasses import dataclass

from nacl.signing import SigningKey, VerifyKey

from ghostlink.device import EnrolledGhostDevice, GhostDevice
from ghostlink.device_certificate import (
    GhostDeviceCertificate,
    SignedGhostDeviceCertificate,
    sign_device_certificate,
)
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

    def authorize_device(
        self,
        device: GhostDevice,
    ) -> SignedGhostDeviceCertificate:
        """Authorize a device by signing its certificate."""
        certificate = GhostDeviceCertificate(
            ghost_id=self.ghost_id,
            device_id=device.device_id,
            signing_public_key=bytes(device.signing_verify_key),
            encryption_public_key=bytes(device.encryption_public_key),
        )

        return sign_device_certificate(
            certificate,
            self.signing_key,
        )

    def enroll_device(self) -> EnrolledGhostDevice:
        """Generate and authorize a new GhostLink device."""
        device = GhostDevice.generate()
        certificate = self.authorize_device(device)

        return EnrolledGhostDevice(
            device=device,
            certificate=certificate,
        )