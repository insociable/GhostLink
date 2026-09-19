"""GhostNode ratcheted relay application."""

from __future__ import annotations

import argparse

from fastapi import FastAPI, HTTPException, status

from ghostlink.config import NodeSettings, load_settings
from ghostlink.prekey_relay import (
    PreKeyPublicationStore,
    create_prekey_publication_router,
    create_prekey_publication_store,
)
from ghostlink.relay_device_lifecycle import (
    DeviceLifecycleStore,
    create_device_lifecycle_router,
    create_device_lifecycle_store,
)
from ghostlink.relay_request_auth import (
    RelayRequestReplayStore,
    create_relay_request_replay_store,
)
from ghostlink.relay_state import (
    RelayStateCoordinator,
    SQLiteRelayMonotonicWitness,
)
from ghostlink.relay_v3 import (
    V3MessageStore,
    create_v3_message_store,
    create_v3_router,
)


def _create_relay_state_coordinator(
    settings: NodeSettings,
) -> RelayStateCoordinator | None:
    if settings.database_path is None:
        return None

    if (
        settings.relay_state_id is None
        or settings.relay_witness_path is None
        or settings.relay_state_coordination_key is None
    ):
        raise ValueError(
            "persistent GhostNode requires relay_state_id, relay_witness_path "
            "and GHOSTLINK_RELAY_STATE_KEY_FILE"
        )

    witness = SQLiteRelayMonotonicWitness(
        settings.relay_witness_path,
        settings.relay_state_id,
        settings.relay_state_coordination_key,
    )
    return RelayStateCoordinator(
        settings.database_path,
        settings.relay_state_id,
        settings.relay_state_coordination_key,
        witness,
    )


def migrate_relay_state(settings: NodeSettings) -> int:
    """Explicitly enroll one legacy persistent GhostNode database."""
    coordinator = _create_relay_state_coordinator(settings)
    if coordinator is None or settings.database_path is None:
        raise ValueError("relay-state migration requires node.database_path")

    # Ensure the exact protected schema exists before computing revision 1.
    create_v3_message_store(settings)
    create_prekey_publication_store(settings)
    create_relay_request_replay_store(settings)
    create_device_lifecycle_store(settings)

    checkpoint = coordinator.migrate_legacy()
    return checkpoint.revision


def create_app(
    settings: NodeSettings | None = None,
    prekey_store: PreKeyPublicationStore | None = None,
    ratchet_store: V3MessageStore | None = None,
    request_replay_store: RelayRequestReplayStore | None = None,
    device_lifecycle_store: DeviceLifecycleStore | None = None,
) -> FastAPI:
    """Create GhostNode with ratcheted-v3 message and pre-key routes."""
    node_settings = settings or NodeSettings()
    coordinator = _create_relay_state_coordinator(node_settings)

    if coordinator is not None and any(
        store is not None
        for store in (
            prekey_store,
            ratchet_store,
            request_replay_store,
            device_lifecycle_store,
        )
    ):
        raise ValueError(
            "persistent GhostNode store overrides are incompatible with "
            "runtime relay-state coordination"
        )

    publication_store = (
        prekey_store
        if prekey_store is not None
        else create_prekey_publication_store(node_settings, coordinator)
    )
    v3_message_store = (
        ratchet_store
        if ratchet_store is not None
        else create_v3_message_store(node_settings, coordinator)
    )
    relay_request_replay_store = (
        request_replay_store
        if request_replay_store is not None
        else create_relay_request_replay_store(node_settings, coordinator)
    )
    lifecycle_store = (
        device_lifecycle_store
        if device_lifecycle_store is not None
        else create_device_lifecycle_store(node_settings, coordinator)
    )

    if coordinator is not None:
        coordinator.reconcile()

    app = FastAPI(
        title="GhostNode",
        version="0.3.0",
        description="Ciphertext-only relay for GhostLink ratcheted v3.",
    )
    app.state.settings = node_settings
    app.state.relay_state_coordinator = coordinator
    app.include_router(
        create_v3_router(
            node_settings,
            v3_message_store,
            relay_request_replay_store,
            lifecycle_store,
        )
    )
    app.include_router(
        create_prekey_publication_router(
            node_settings,
            publication_store,
            lifecycle_store,
        )
    )
    app.include_router(
        create_device_lifecycle_router(node_settings, lifecycle_store)
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        """Return node health status for current relay storage."""
        if (
            (coordinator is not None and not coordinator.is_healthy())
            or not v3_message_store.is_healthy()
            or not publication_store.is_healthy()
            or not relay_request_replay_store.is_healthy()
            or not lifecycle_store.is_healthy()
        ):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="storage unavailable",
            )
        return {"status": "ok"}

    return app


def main() -> None:
    """Run GhostNode or explicitly migrate its persistent relay state."""
    import uvicorn

    parser = argparse.ArgumentParser(prog="ghostnode")
    parser.add_argument(
        "--migrate-relay-state",
        action="store_true",
        help="enroll a legacy SQLite relay database in rollback coordination",
    )
    args = parser.parse_args()

    settings = load_settings()
    if args.migrate_relay_state:
        revision = migrate_relay_state(settings)
        print(f"Relay state enrolled at revision {revision}.")
        return

    application = create_app(settings=settings)
    uvicorn.run(
        application,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        access_log=settings.access_log,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
