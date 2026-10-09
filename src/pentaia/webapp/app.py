"""FastAPI application factory for the Phase 4 web layer.

P4-02 establishes the application boundary and nothing behind it. Authentication is
now selected here (P4-07) but there is still no login route, no accounting store and
no conversation service; those arrive in P4-08, P4-09 and P4-11.

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
from pentaia.webapp.auth.base import AuthProvider
from pentaia.webapp.auth.selection import build_auth_provider
from pentaia.webapp.config import WebAppConfig, load_webapp_config
from pentaia.webapp.gui import mount_gui
from pentaia.webapp.sessions import InMemorySessionStore, SessionStore

logger = logging.getLogger(__name__)

APPLICATION_TITLE = "PentAiA web application"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Own the application lifecycle.

    Startup does only what the foundation needs: the configuration has already been
    validated and the authentication provider already built before the server binds,
    and the resolved settings are logged so a start-up problem is visible. There is
    deliberately no database or connection pool to open yet, and shutdown has nothing
    to release.
    """
    config: WebAppConfig = app.state.config
    provider: AuthProvider | None = app.state.auth_provider

    logger.info(
        "PentAiA web application starting host=%s port=%s docs_enabled=%s "
        "auth_provider=%s",
        config.host,
        config.port,
        config.docs_enabled,
        provider.name if provider is not None else "none",
    )

    try:
        yield
    finally:
        logger.info("PentAiA web application stopped")


def create_app(
    config: WebAppConfig | None = None,
    *,
    session_store: SessionStore | None = None,
    auth_provider: AuthProvider | None = None,
) -> FastAPI:
    """Build the Phase 4 web application.

    A factory rather than a module-level application object, so importing this
    package has no startup side effects and tests can build an application with
    explicit configuration. When no configuration is supplied it is loaded from the
    environment and validated before anything is served.

    ``session_store`` is the seam P4-09 uses to replace the process-local store with a
    durable repository, and it lets tests create sessions without going through a login
    route that does not exist yet.

    ``auth_provider`` is the matching seam for authentication: an explicitly supplied
    provider is used as-is and no provider is built from the configuration. Otherwise
    the configured provider is built *here*, before the server binds, so an unusable
    selection stops the application instead of failing on someone's first login. When
    neither is present the application runs with no provider at all: nothing can
    authenticate, which is not the same as anyone being allowed in.
    """
    resolved = config if config is not None else load_webapp_config()

    provider = auth_provider

    if provider is None and resolved.auth_provider is not None:
        # Fails closed: an unimplemented or unusable selection raises out of this
        # factory rather than degrading to a different authentication mechanism.
        provider = build_auth_provider(resolved.auth_provider)

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
    app.state.session_store = (
        session_store if session_store is not None else InMemorySessionStore()
    )
    app.state.auth_provider = provider

    for router in API_ROUTERS:
        app.include_router(router)

    mount_gui(app)

    return app
