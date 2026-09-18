import pytest
from ghostlink.contact import ContactBundleError, export_contact_qr_payload
from ghostlink.contact_qr import render_contact_qr_svg
from ghostlink.entity import GhostEntity


def test_contact_qr_svg_is_deterministic_standard_svg() -> None:
    alice = GhostEntity.generate()
    device = alice.enroll_device()
    payload = export_contact_qr_payload(alice, device)

    first = render_contact_qr_svg(payload)
    second = render_contact_qr_svg(payload)

    assert first == second
    assert first.startswith("<svg")
    assert first.endswith("</svg>")
    assert "<path " in first
    assert 'class="segno"' in first
    assert "ghostlink:contact:" not in first


def test_contact_qr_svg_rejects_invalid_payload_before_rendering() -> None:
    with pytest.raises(ContactBundleError, match="invalid GhostLink contact QR prefix"):
        render_contact_qr_svg("https://example.invalid/contact")
