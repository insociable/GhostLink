"""QR rendering for public GhostLink contact payloads."""

from __future__ import annotations

import segno

from ghostlink.contact import import_contact_qr_payload


def render_contact_qr_svg(payload: str) -> str:
    """Render one validated GhostLink contact payload as a standard SVG QR code."""
    import_contact_qr_payload(payload)
    qr = segno.make_qr(payload, error="M", boost_error=False)
    return qr.svg_inline(scale=6, border=4)
