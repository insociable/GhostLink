"""Shared GhostNode relay access-control helper."""

from __future__ import annotations

import secrets

from fastapi import HTTPException, status

from ghostlink.config import NodeSettings


def require_relay_access(
    settings: NodeSettings,
    authorization: str | None,
) -> None:
    """Require the configured shared Bearer token for relay operations."""
    if settings.access_token is None:
        return

    expected = f"Bearer {settings.access_token}"
    if authorization is None or not secrets.compare_digest(authorization, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )