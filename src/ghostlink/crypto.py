"""Minimal cryptographic proof of concept.

This module is intentionally small and is not a complete secure-messaging protocol.
"""

from dataclasses import dataclass

from nacl.encoding import Base64Encoder
from nacl.public import Box, PrivateKey, PublicKey


@dataclass(frozen=True, slots=True)
class Identity:
    """A local Curve25519 identity used only by the initial proof of concept."""

    private_key: PrivateKey

    @classmethod
    def generate(cls) -> "Identity":
        """Generate a new local identity using libsodium secure randomness."""
        return cls(private_key=PrivateKey.generate())

    @property
    def public_key(self) -> PublicKey:
        """Return the public key corresponding to the private identity key."""
        return self.private_key.public_key

    def export_public_key(self) -> str:
        """Export the public key as Base64 text."""
        return self.public_key.encode(encoder=Base64Encoder).decode("ascii")


def import_public_key(encoded_key: str) -> PublicKey:
    """Import a Base64-encoded Curve25519 public key."""
    return PublicKey(encoded_key.encode("ascii"), encoder=Base64Encoder)


def encrypt_message(
    sender: Identity,
    recipient_public_key: PublicKey,
    plaintext: bytes,
) -> bytes:
    """Encrypt and authenticate a message for the recipient.

    The returned value contains the nonce and ciphertext as produced by PyNaCl.
    """
    if not plaintext:
        raise ValueError("plaintext must not be empty")

    box = Box(sender.private_key, recipient_public_key)
    return bytes(box.encrypt(plaintext))


def decrypt_message(
    recipient: Identity,
    sender_public_key: PublicKey,
    encrypted_message: bytes,
) -> bytes:
    """Authenticate and decrypt a message received from the sender."""
    if not encrypted_message:
        raise ValueError("encrypted_message must not be empty")

    box = Box(recipient.private_key, sender_public_key)
    return bytes(box.decrypt(encrypted_message))
