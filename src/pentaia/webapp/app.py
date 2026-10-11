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
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from pentaia.appstore.connection import SqliteAppStore
from pentaia.appstore.recorder import (
    AccountingRecorder,
    NullAccountingRecorder,
    RepositoryAccountingRecorder,
)
from pentaia.appstore.repository import SqliteAccountingRepository
from pentaia.webapp.api import API_ROUTERS
from pentaia.webapp.api.login import (
    LOGIN_PATH,
    MAX_LOGIN_BODY_BYTES,
    LoginBodyLimitMiddleware,
)
from pentaia.webapp.auth.base import AuthProvider
from pentaia.webapp.auth.client_ip import TrustedProxySet
from pentaia.webapp.auth.csrf import InMemoryPreAuthTokenStore, PreAuthTokenStore
from pentaia.webapp.auth.login import LoginService
from pentaia.webapp.auth.selection import build_auth_provider
from pentaia.webapp.auth.throttle import InMemoryLoginThrottle, LoginThrottle
from pentaia.webapp.config import WebAppConfig, load_webapp_config
from pentaia.webapp.gui import mount_gui
from pentaia.webapp.persistence import SqliteLoginThrottle, SqliteSessionStore
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
        "auth_provider=%s public_origin=%s store=%s accounting=%s",
        config.host,
        config.port,
        config.docs_enabled,
        provider.name if provider is not None else "none",
        config.public_origin if config.public_origin is not None else "unset",
        config.store.mode,
        app.state.accounting.state.value,
    )

    try:
        yield
    finally:
        # Release the database handle. A checkpoint runs first so the main file is
        # complete for a copy taken after shutdown, which is the WAL-aware backup rule.
        store_handle = getattr(app.state, "app_store", None)

        if store_handle is not None:
            store_handle.close()

        logger.info("PentAiA web application stopped")


def _safe_validation_errors(exc: RequestValidationError) -> list[dict[str, object]]:
    """Validation errors with the submitted value removed.

    ``input`` and ``ctx`` are dropped deliberately: they carry the value that failed, and
    a value that failed validation may be a password the caller mistyped into the wrong
    shape. The remaining fields describe the problem without ever carrying it.
    """
    return [
        {
            "type": error.get("type"),
            "loc": [str(part) for part in error.get("loc", ())],
            "msg": error.get("msg"),
        }
        for error in exc.errors()
    ]


def create_app(
    config: WebAppConfig | None = None,
    *,
    session_store: SessionStore | None = None,
    auth_provider: AuthProvider | None = None,
    login_throttle: LoginThrottle | None = None,
    pre_auth_tokens: PreAuthTokenStore | None = None,
    accounting: AccountingRecorder | None = None,
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    """Build the Phase 4 web application.

    A factory rather than a module-level application object, so importing this
    package has no startup side effects and tests can build an application with
    explicit configuration. When no configuration is supplied it is loaded from the
    environment and validated before anything is served.

    The keyword arguments are injection seams, not configuration:

    * ``session_store`` and ``login_throttle`` are the two pieces of state P4-09 moves
      onto durable storage, so they must be replaceable without touching the routes.
    * ``auth_provider`` lets tests exercise the login flow against a stand-in provider.
      It is never reachable from a browser request: the provider is chosen by
      configuration before the server binds, and no route parameter selects one.
    * ``pre_auth_tokens`` and ``clock`` exist so time-dependent behaviour is testable
      without sleeping. One clock drives session creation, session expiry and the
      throttling window, so advancing it advances all three together.

    When no provider is injected, the configured one is built *here*, before the server
    binds, so an unusable selection stops the application instead of failing on someone's
    first login. When no provider is configured at all the application runs, but nothing
    can authenticate: that is not the same as anyone being allowed in.
    """
    resolved = config if config is not None else load_webapp_config()

    moment: Callable[[], datetime] = (
        clock if clock is not None else (lambda: datetime.now(UTC))
    )

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

    # The durable store is opened and migrated before anything is served, so an unusable
    # data directory, a corrupt database or a failed migration stops the application
    # instead of surfacing on someone's first request.
    app_store = (
        SqliteAppStore.open(resolved.store) if resolved.store.durable else None
    )

    if app_store is not None:
        app_store.migrate()

    recorder = accounting

    if recorder is None:
        recorder = (
            RepositoryAccountingRecorder(SqliteAccountingRepository(app_store))
            if app_store is not None
            else NullAccountingRecorder()
        )

    store = session_store

    if store is None:
        store = (
            SqliteSessionStore(
                app_store,
                idle_timeout_seconds=resolved.session_idle_timeout,
                absolute_lifetime_seconds=resolved.session_absolute_lifetime,
                recorder=recorder,
                clock=moment,
            )
            if app_store is not None
            else InMemorySessionStore(
                idle_timeout_seconds=resolved.session_idle_timeout,
                absolute_lifetime_seconds=resolved.session_absolute_lifetime,
                clock=moment,
            )
        )

    throttle = login_throttle

    if throttle is None:
        throttle = (
            SqliteLoginThrottle(
                app_store,
                max_attempts=resolved.login_max_attempts,
                window_seconds=resolved.login_window_seconds,
                max_keys=resolved.login_max_keys,
                clock=moment,
            )
            if app_store is not None
            else InMemoryLoginThrottle(
                max_attempts=resolved.login_max_attempts,
                window_seconds=resolved.login_window_seconds,
                max_keys=resolved.login_max_keys,
                clock=moment,
            )
        )

    app.state.config = resolved
    app.state.session_store = store
    app.state.accounting = recorder
    app.state.app_store = app_store
    # Built once from validated configuration, so the trust decision is not remade from
    # raw strings on every request. An empty set trusts no peer's forwarded headers.
    app.state.trusted_proxies = TrustedProxySet.parse(resolved.trusted_proxies)
    # None means no public origin was declared, so Origin is compared against the request
    # host only. Set it to compare the full origin, scheme and port included.
    app.state.public_origin = resolved.public_origin
    app.state.auth_provider = provider
    app.state.login_throttle = throttle
    app.state.pre_auth_tokens = (
        pre_auth_tokens
        if pre_auth_tokens is not None
        else InMemoryPreAuthTokenStore(clock=moment)
    )
    app.state.login_service = LoginService(
        provider=provider,
        throttle=throttle,
        session_store=store,
        recorder=recorder,
        clock=moment,
    )

    # Registered before the middleware below so that the cache directive, which is added
    # on the way out, also covers a refusal produced here.
    app.add_middleware(
        LoginBodyLimitMiddleware,
        path=LOGIN_PATH,
        limit=MAX_LOGIN_BODY_BYTES,
    )

    @app.middleware("http")
    async def no_store_for_the_api(request: Request, call_next: Callable) -> Response:
        """Keep authenticated payloads and tokens out of caches.

        Applied to the whole ``/api`` prefix rather than route by route, so a new route
        cannot omit it. ``/healthz`` and the static shell are unaffected.
        """
        response = await call_next(request)

        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"

        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Answer a validation failure without echoing what was submitted.

        Pydantic reports the value that failed, and one of the values this application
        accepts is a password. A wrongly typed credential — a password sent as an object
        or an array, for instance — would otherwise be reflected straight back in the
        response body and from there into a proxy log or a client-side error report. Only
        the location, error type and message are returned, which is everything a caller
        needs and nothing that could be a credential.
        """
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": _safe_validation_errors(exc)},
            headers={"Cache-Control": "no-store"},
        )

    for router in API_ROUTERS:
        app.include_router(router)

    mount_gui(app)

    return app
