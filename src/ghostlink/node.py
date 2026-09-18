"""GhostNode ratcheted relay application."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, status

from ghostlink.config import NodeSettings, load_settings
from ghostlink.prekey_relay import (
    PreKeyPublicationStore,
    create_prekey_publication_router,
    create_prekey_publication_store,
)
from ghostlink.relay_request_auth import (
    RelayRequestReplayStore,
    create_relay_request_replay_store,
)
from ghostlink.relay_v3 import (
    V3MessageStore,
    create_v3_message_store,
    create_v3_router,
)


def create_app(
    settings: NodeSettings | None = None,
    prekey_store: PreKeyPublicationStore | None = None,
    ratchet_store: V3MessageStore | None = None,
    request_replay_store: RelayRequestReplayStore | None = None,
) -> FastAPI:
    """Create GhostNode with ratcheted-v3 message and pre-key routes."""
    node_settings = settings or NodeSettings()
    publication_store = (
        prekey_store
        if prekey_store is not None
        else create_prekey_publication_store(node_settings)
    )
    v3_message_store = (
        ratchet_store
        if ratchet_store is not None
        else create_v3_message_store(node_settings)
    )
    relay_request_replay_store = (
        request_replay_store
        if request_replay_store is not None
        else create_relay_request_replay_store(node_settings)
    )

    app = FastAPI(
        title="GhostNode",
        version="0.3.0",
        description="Ciphertext-only relay for GhostLink ratcheted v3.",
    )
    app.state.settings = node_settings
    app.include_router(
        create_v3_router(
            node_settings,
            v3_message_store,
            relay_request_replay_store,
        )
    )
    app.include_router(
        create_prekey_publication_router(node_settings, publication_store)
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        """Return node health status for current relay storage."""
        if (
            not v3_message_store.is_healthy()
            or not publication_store.is_healthy()
            or not relay_request_replay_store.is_healthy()
        ):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="storage unavailable",
            )
        return {"status": "ok"}

    return app


def main() -> None:
    """Run GhostNode using settings from ghostlink.toml."""
    import uvicorn

    settings = load_settings()
    application = create_app(settings=settings)
    uvicorn.run(
        application,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        access_log=settings.access_log,
        proxy_headers=False,
    )


app = create_app(settings=load_settings())


if __name__ == "__main__":
    main()
