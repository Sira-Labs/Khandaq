"""Khandaq API application.

Bootable R1 skeleton: health and version endpoints behind a fail-closed configuration check, so a
CapRover/compose deployment comes up green before the domain features (engagements, scope lock,
findings) land per docs/specs/. Endpoints are added spec by spec.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI

from . import __version__
from .db import schema_revision
from .routers import (
    adapters,
    alerts,
    auth,
    campaigns,
    deployment,
    engagements,
    evidence,
    ledger,
    reports,
    runs,
)
from .settings import get_settings

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("khandaq.api")


def create_app() -> FastAPI:
    settings = get_settings()
    settings.validate_runtime()  # fail closed in prod before serving a single request

    app = FastAPI(
        title="Khandaq API",
        version=__version__,
        description="A command post for authorised AI red-team engagements.",
    )

    @app.get("/api/health")
    def health() -> dict[str, str]:
        """Liveness probe — always cheap, no external dependencies."""
        return {"status": "ok", "role": settings.role, "env": settings.env}

    @app.get("/api/version")
    def version() -> dict[str, str]:
        """App version and the applied database schema revision (see db.schema_revision)."""
        return {"app": __version__, "schema_revision": schema_revision(settings)}

    @app.get("/")
    def root() -> dict[str, str]:
        return {
            "name": "Khandaq",
            "status": "ok",
            "note": "authorised AI red-team orchestration — see /api/version",
        }

    app.include_router(auth.router)
    app.include_router(deployment.router)
    app.include_router(engagements.router)
    app.include_router(ledger.router)
    app.include_router(evidence.router)
    app.include_router(runs.router)
    app.include_router(reports.router)
    app.include_router(campaigns.router)
    app.include_router(alerts.router)
    app.include_router(adapters.router)

    log.info("khandaq-api %s starting (env=%s, role=%s)", __version__, settings.env, settings.role)
    return app


app = create_app()
