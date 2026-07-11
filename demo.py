"""Minimal end-to-end GhostLink demonstration."""

import base64

from ghostlink.entity import GhostEntity
from ghostlink.message import decrypt_message, encrypt_message


def main() -> None:
    """Run a local encrypted message exchange between Alice and Bob."""
    alice = GhostEntity.generate()
    bob = GhostEntity.generate()

    alice_device = alice.enroll_device()
    bob_device = bob.enroll_device()

    message = encrypt_message(
        sender=alice_device,
        recipient=bob_device,
        plaintext=b"Hello GhostLink!",
    )

    plaintext = decrypt_message(
        recipient=bob_device,
        sender=alice_device,
        message=message,
    )

    print("=== GhostLink Demo ===")
    print()
    print("Alice GhostID:")
    print(alice.ghost_id)
    print()
    print("Bob GhostID:")
    print(bob.ghost_id)
    print()
    print("Alice Device:")
    print(alice_device.device_id)
    print()
    print("Bob Device:")
    print(bob_device.device_id)
    print()
    print("Encrypted message:")
    print(base64.b64encode(message.ciphertext).decode("ascii"))
    print()
    print("Bob received:")
    print(plaintext.decode("utf-8"))


if __name__ == "__main__":
    main()