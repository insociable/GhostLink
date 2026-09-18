"""GhostNode protocol-v2 relay application."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, status

from ghostlink.config import NodeSettings, load_settings
from ghostlink.prekey_relay import (
    PreKeyPublicationStore,
    create_prekey_publication_router,
    create_prekey_publication_store,
)
from ghostlink.relay_v2 import (
    V2MessageStore,
    create_v2_message_store,
    create_v2_router,
)


def create_app(
    store: V2MessageStore | None = None,
    settings: NodeSettings | None = None,
    prekey_store: PreKeyPublicationStore | None = None,
) -> FastAPI:
    """Create the GhostNode application with protocol-v2 relay routes."""
    node_settings = settings or NodeSettings()
    message_store = (
        store
        if store is not None
        else create_v2_message_store(node_settings)
    )

    publication_store = (
        prekey_store
        if prekey_store is not None
        else create_prekey_publication_store(node_settings)
    )

    app = FastAPI(
        title="GhostNode",
        version="0.2.0",
        description="Ciphertext-only relay for GhostLink protocol v2.",
    )
    app.state.settings = node_settings
    app.include_router(create_v2_router(node_settings, message_store))
    app.include_router(
        create_prekey_publication_router(node_settings, publication_store)
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        """Return node health status, including relay storage availability."""
        if (
            not message_store.is_healthy()
            or not publication_store.is_healthy()
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
    )


app = create_app(settings=load_settings())


if __name__ == "__main__":
    main()