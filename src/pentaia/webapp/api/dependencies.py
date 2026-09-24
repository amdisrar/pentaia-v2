"""Session resolution for the browser-facing API.

P4-02 shipped a placeholder here that refused every request, because there was no way
to resolve an identity at all. This module now resolves identity from the authoritative
server-side session record. The router-level dependency name is unchanged, so every
route that was protected before is still protected and the upgrade stays a single
dependency swap.

Identity is never taken from the request. The only browser input consulted is the
session cookie, and the cookie is only a pointer: the identity it resolves to comes
from the session record. Headers, query parameters and bodies carrying a user id, a
username or an auth source are ignored entirely, so there is no way for a client to
assert who it is. Phase 4 has no trusted-proxy identity model, and this module does not
introduce one.

Raw session identifiers are treated as bearer credentials: they are read into a local
variable, handed to the store for digest lookup, and never logged, echoed or returned.
"""

import logging
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from pentaia.webapp.identity import AuthenticatedIdentity
from pentaia.webapp.sessions import SESSION_COOKIE_NAME, SessionStore, WebSession

logger = logging.getLogger(__name__)

AUTHENTICATION_REQUIRED_DETAIL = "Authentication required."


def session_store(request: Request) -> SessionStore:
    """Return the application's session store.

    A missing store is a wiring fault, not an unauthenticated request, so it surfaces
    as a server error rather than being mistaken for "no session". Failing closed
    either way: no request reaches a protected route.
    """
    store = getattr(request.app.state, "session_store", None)

    if store is None:
        raise RuntimeError(
            "The web application has no session store configured; build it with "
            "create_app()."
        )

    return store


def resolve_session(request: Request) -> WebSession | None:
    """Resolve the caller's session, or ``None`` when there is not a valid one.

    Absent, unknown, invalid and expired sessions are indistinguishable to the caller
    and all yield ``None``.
    """
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    if not session_id:
        return None

    return session_store(request).resolve(session_id)


def require_authenticated_session(
    request: Request,
) -> WebSession:
    """Dependency: return the caller's live session, or refuse with 401.

    Routes that need the safe session label (accounting correlation, session
    visibility) depend on this. The returned record holds no session identifier.
    """
    session = resolve_session(request)

    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=AUTHENTICATION_REQUIRED_DETAIL,
        )

    return session


def require_authenticated_identity(
    session: Annotated[WebSession, Depends(require_authenticated_session)],
) -> AuthenticatedIdentity:
    """Dependency: return the authenticated identity, or refuse with 401.

    Keeps the name P4-02 introduced, so the routes that were already protected by it
    keep working unchanged.
    """
    return session.identity
