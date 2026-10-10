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
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request, status

from pentaia.webapp.auth.base import AuthProvider
from pentaia.webapp.auth.client_ip import TrustedProxySet, resolve_client_ip
from pentaia.webapp.auth.csrf import (
    CSRF_HEADER_NAME,
    PreAuthTokenStore,
    tokens_match,
)
from pentaia.webapp.auth.login import LoginService
from pentaia.webapp.auth.throttle import LoginThrottle
from pentaia.webapp.config import normalize_origin
from pentaia.webapp.identity import AuthenticatedIdentity
from pentaia.webapp.sessions import SESSION_COOKIE_NAME, SessionStore, WebSession

logger = logging.getLogger(__name__)

AUTHENTICATION_REQUIRED_DETAIL = "Authentication required."

#: The one answer a caller gets when CSRF verification fails. It says nothing about
#: which check failed, so it cannot be used to probe the token comparison.
CSRF_REFUSED_DETAIL = "Request could not be verified."

#: Methods that change state and therefore require a CSRF token. Everything else is
#: safe to repeat, so requiring a token for it would add friction without protection.
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def authentication_provider(request: Request) -> AuthProvider | None:
    """Return the deployment's active authentication provider, if it has one.

    An application built without a configured provider is a valid deployment, so a
    missing provider is reported as ``None`` rather than raising. Nothing here creates
    a provider on demand: selection happens once, before the server binds, and this
    only reads the result. The absence of a provider is therefore never mistaken for
    an authentication success.
    """
    return getattr(request.app.state, "auth_provider", None)


def client_ip(request: Request) -> str:
    """Resolve the caller's address for throttling, honouring the trust boundary.

    The forwarded header is only consulted when the TCP peer is a configured trusted
    proxy; an untrusted caller cannot choose its own identity. A missing trust set
    trusts nobody, which is the safe direction.
    """
    trusted = getattr(request.app.state, "trusted_proxies", None)

    if not isinstance(trusted, TrustedProxySet):
        trusted = TrustedProxySet()

    return resolve_client_ip(
        peer_host=request.client.host if request.client is not None else None,
        forwarded_for=request.headers.get("x-forwarded-for"),
        trusted=trusted,
    )


def login_throttle(request: Request) -> LoginThrottle:
    """Return the application's login throttle.

    A missing throttle is a wiring fault, not a failed login, so it surfaces as a server
    error rather than being treated as "not throttled".
    """
    throttle = getattr(request.app.state, "login_throttle", None)

    if throttle is None:
        raise RuntimeError(
            "The web application has no login throttle configured; build it with "
            "create_app()."
        )

    return throttle


def pre_auth_tokens(request: Request) -> PreAuthTokenStore:
    """Return the store of pre-authentication CSRF tokens."""
    store = getattr(request.app.state, "pre_auth_tokens", None)

    if store is None:
        raise RuntimeError(
            "The web application has no pre-authentication token store; build it with "
            "create_app()."
        )

    return store


def login_service(request: Request) -> LoginService:
    """Return the application's login service."""
    service = getattr(request.app.state, "login_service", None)

    if service is None:
        raise RuntimeError(
            "The web application has no login service configured; build it with "
            "create_app()."
        )

    return service


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


# --- CSRF enforcement ------------------------------------------------------
#
# Both dependencies live at the end of this module because they depend on the session
# resolution above; FastAPI evaluates ``Depends(...)`` when the function is defined.
# ``require_csrf`` is attached to routers rather than to individual routes, so a future
# state-changing route cannot become reachable without it by forgetting a decorator.


def request_is_same_origin(request: Request) -> bool:
    """True unless the browser tells us this request came from another site.

    A secondary control, not the primary one: the CSRF token is what actually authorises
    a state-changing request. This exists because the two headers below are cheap for a
    browser to send and hard for another origin to forge.

    * ``Sec-Fetch-Site: cross-site`` is a positive statement that the request came from a
      different site, so it is refused outright.
    * An ``Origin`` header is compared against ``PENTAIA_PUBLIC_ORIGIN`` — the origin this
      deployment declares it is reachable at — including the scheme and the port. Nothing
      is inferred from ``Host`` and nothing at all is read from a forwarded header, so a
      client cannot influence the comparison by sending one.

    Without a declared public origin the scheme and port cannot be checked without
    trusting a client-supplied header, so only the host is compared against the ``Host``
    the request was actually addressed to. That is weaker, not absent, and the application
    logs which mode it is in at startup; a deployment should set the setting.

    A request with neither header is allowed to proceed to the token check. Scripts,
    command-line clients and some privacy configurations send neither, and refusing them
    would not add protection: they still cannot produce a valid token.
    """
    fetch_site = (request.headers.get("sec-fetch-site") or "").strip().lower()

    if fetch_site == "cross-site":
        return False

    origin = request.headers.get("origin")

    if origin is None:
        return True

    declared = getattr(request.app.state, "public_origin", None)

    if declared is not None:
        return normalize_origin(origin) == declared

    host = request.headers.get("host")

    if not host:
        return False

    expected = urlsplit(f"//{host}").hostname
    submitted = urlsplit(origin).hostname

    if expected is None or submitted is None:
        return False

    return submitted == expected


def require_login_csrf(request: Request) -> None:
    """Dependency: require proof that a same-origin client is submitting the login.

    Login is reachable without a session, so there is usually no session token to compare
    against and the proof is a live *server-issued* pre-authentication token instead.
    Either token is accepted, which is what lets a caller who already holds a session
    re-authenticate without fetching a second kind of token: both are unguessable values
    this server issued to this client, and neither is available to a page on another
    origin, which can neither read the response that carries one nor set the header that
    presents it.

    Three things must hold, in order of importance:

    1. the presented token is one this server issued to **this client** (the store binds
       each token to the client address it was issued to, so a leaked token is useless
       elsewhere) and has not expired;
    2. the request is not declared cross-site by ``Origin``/``Sec-Fetch-Site``;
    3. both of the above are checked before the provider is reached, so a forged login
       cannot even cost a directory lookup.

    That is the login-CSRF control: a cross-site form post cannot set the header that
    carries the token, so it cannot make a victim's browser authenticate as somebody
    else, and it cannot obtain a token bound to the victim's client address.
    """
    if not request_is_same_origin(request):
        logger.warning("Login refused reason=cross_site path=%s", request.url.path)

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=CSRF_REFUSED_DETAIL,
        )

    presented = request.headers.get(CSRF_HEADER_NAME)
    address = client_ip(request)
    session = resolve_session(request)

    if session is not None and tokens_match(session.csrf_token, presented):
        return

    if pre_auth_tokens(request).is_live(presented, client_ip=address):
        return

    logger.warning("Login CSRF check refused path=%s", request.url.path)

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=CSRF_REFUSED_DETAIL,
    )


def require_csrf(
    request: Request,
    session: Annotated[WebSession, Depends(require_authenticated_session)],
) -> None:
    """Dependency: require the session's own CSRF token on state-changing requests.

    Method-driven, so safe requests pass through and every state-changing one is covered.
    The session is resolved first, which means an unauthenticated request is still
    answered with 401 rather than a CSRF refusal: only an authenticated caller learns
    anything about the token.

    The origin check is defence in depth on top of the token, exactly as it is for login.
    Unlike the login token, the session token is *not* bound to a client address: a
    session outlives a single request and must survive a client's address changing, so
    binding it would break legitimate use for no gain — an attacker cannot read it.
    """
    if request.method.upper() not in UNSAFE_METHODS:
        return

    if not request_is_same_origin(request):
        logger.warning(
            "CSRF check refused path=%s method=%s reason=cross_site",
            request.url.path,
            request.method,
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=CSRF_REFUSED_DETAIL,
        )

    presented = request.headers.get(CSRF_HEADER_NAME)

    if not tokens_match(session.csrf_token, presented):
        logger.warning(
            "CSRF check refused path=%s method=%s session_label=%s",
            request.url.path,
            request.method,
            session.label,
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=CSRF_REFUSED_DETAIL,
        )
