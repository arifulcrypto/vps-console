"""QR codes as inline SVG data URIs (no image files, no external service)."""

from __future__ import annotations

import base64
import io

import segno

MAX_QR_BYTES = 2000


def svg_data_uri(text: str, scale: int = 4) -> str | None:
    if len(text.encode()) > MAX_QR_BYTES:
        return None
    qr = segno.make(text, error="m", micro=False)
    buf = io.BytesIO()
    qr.save(buf, kind="svg", scale=scale, border=2, dark="#111", light="#fff", xmldecl=False)
    return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode()
