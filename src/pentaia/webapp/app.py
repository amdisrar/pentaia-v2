"""FastAPI application factory for the Phase 4 web layer.

P4-02 establishes the application boundary and nothing behind it. There is no
authentication, no session store, no accounting store and no conversation service
yet; those arrive in P4-04/P4-08, P4-09 and P4-11.

The boundary this package exists to enforce:

    web application layer  --->  existing PentAiA core
    existing PentAiA core  -X->  web application layer

Nothing here imports the Kali executor, the tool wrappers or any command-building
code, and no route accepts tool parameters. ``tests/test_webapp_boundaries.py``
enforces both directions of the dependency rule.

Starting the application does import the existing ``pentaia`` package, which builds
the Phase 1-3 graph and LLM client at import time. That is inherited from the current
package layout and is not changed here; see the P4-02 handoff notes.
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from pentaia.webapp.api import API_ROUTERS
from pentaia.webapp.config import WebAppConfig, load_webapp_config
from pentaia.webapp.gui import mount_gui

logger = logging.getLogger(__name__)

APPLICATION_TITLE = "PentAiA web application"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Own the application lifecycle.

    Startup does only what the foundation needs: the configuration has already been
    validated before the server binds, and the resolved settings are logged so a
    start-up problem is visible. There is deliberately no database, identity provider
    or connection pool to open yet, and shutdown has nothing to release.
    """
    config: WebAppConfig = app.state.config

    logger.info(
        "PentAiA web application starting host=%s port=%s docs_enabled=%s",
        config.host,
        config.port,
        config.docs_enabled,
    )

    try:
        yield
    finally:
        logger.info("PentAiA web application stopped")


def create_app(config: WebAppConfig | None = None) -> FastAPI:
    """Build the Phase 4 web application.

    A factory rather than a module-level application object, so importing this
    package has no startup side effects and tests can build an application with
    explicit configuration. When no configuration is supplied it is loaded from the
    environment and validated before anything is served.
    """
    resolved = config if config is not None else load_webapp_config()

    app = FastAPI(
        title=APPLICATION_TITLE,
        lifespan=lifespan,
        # The interactive documentation describes the whole browser-facing surface, so
        # it is opt-in. See WebAppConfig.docs_enabled.
        docs_url="/docs" if resolved.docs_enabled else None,
        redoc_url="/redoc" if resolved.docs_enabled else None,
        openapi_url="/openapi.json" if resolved.docs_enabled else None,
    )

    app.state.config = resolved

    for router in API_ROUTERS:
        app.include_router(router)

    mount_gui(app)

    return app
