"""The unauthenticated authentication routes: login, and CSRF token bootstrapping.

This router is deliberately separate from :mod:`pentaia.webapp.api.auth`, which carries
the session dependency for the whole authenticated surface. A route that must be
reachable without an identity cannot live behind that dependency, so it lives here and
the separation is a visible decision rather than an omission.

Responses follow one reviewed taxonomy, and nothing outside it is ever returned:

* ``200`` with the caller's own identity projection when the credentials are proven;
* ``401`` with one fixed message for a refused credential — a wrong password and an
  unknown username are byte-identical, so the endpoint is not an account oracle;
* ``503`` with one fixed message when authentication cannot be attempted at all: the
  provider is unreachable, misconfigured, or not configured for this deployment. These
  three share a single answer so a caller cannot map the deployment's authentication
  state;
* ``429`` with ``Retry-After`` when the attempt is refused before any provider call.

Rejections and outages are deliberately distinguishable — an operator needs to tell a
wrong password from a down directory controller — but within each class the answer never
varies, and the distinctions themselves live only in the server-side log, in
``LoginOutcome``, and later in accounting (P4-09). No response body ever echoes the
submitted username or password, no failure path creates a session, and validation
failures are answered without the submitted value (see ``create_app``).

Credentials are accepted only as a JSON body. They are never read from a query
parameter, a path segment or a header, so they cannot end up in a URL, an access log or
browser history.
"""

import logging

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from pentaia.webapp.api.dependencies import (
    client_ip,
    login_service,
    pre_auth_tokens,
    require_login_csrf,
    resolve_session,
)
from pentaia.webapp.api.identity import IdentityResponse, build_identity_payload
from pentaia.webapp.auth.csrf import CSRF_HEADER_NAME
from pentaia.webapp.auth.login import LoginOutcome, LoginResult
from pentaia.webapp.sessions import SESSION_COOKIE_NAME, session_cookie_settings

logger = logging.getLogger(__name__)

#: Full path of the login route. Named here so the application can bound the one
#: unauthenticated body it accepts without repeating the prefix, and so a test can assert
#: this constant still matches the advertised route.
LOGIN_PATH = "/api/auth/login"

#: Largest body accepted on the one unauthenticated route that takes one. Anything larger
#: cannot be a credential this application verifies.
MAX_LOGIN_BODY_BYTES = 64 * 1024

router = APIRouter(prefix="/api/auth", tags=["auth"])

#: One answer for every rejected credential. It never varies with the reason, so it
#: cannot be used to tell a wrong password from an unknown account. The throttled answer
#: uses the same text: a caller learns that it should wait from the status code and
#: ``Retry-After``, and nothing about the account is disclosed either way.
LOGIN_FAILED_DETAIL = "Authentication failed."

#: Answer for a login body larger than the application accepts. It describes the request,
#: not the credentials, and is returned before the body is parsed.
LOGIN_BODY_TOO_LARGE_DETAIL = "Request body is too large."

#: One answer for every condition where authentication cannot be performed at all.
AUTHENTICATION_UNAVAILABLE_DETAIL = "Authentication is temporarily unavailable."

#: Shared by every response from this module: credentials and tokens must not be cached.
NO_STORE_HEADERS = {"Cache-Control": "no-store"}


class LoginBodyLimitMiddleware:
    """Bound the login request body whatever the client declares.

    A declared ``Content-Length`` over the limit is refused before a byte is read, but that
    alone is not a bound: a client can omit the header and stream the body with chunked
    encoding. The body is therefore also counted as it arrives, and the request is refused
    the moment it passes the limit, so neither a declared nor an undeclared body can cross
    the boundary. Both paths answer with the same generic ``413``.

    Written as raw ASGI rather than an ``http`` middleware so the ``receive`` callable can
    be wrapped directly: that is the only place the bytes pass through before the
    application parses them. The refusal is raised as an ``HTTPException`` rather than a
    private exception because FastAPI's body-parsing guard re-raises ``HTTPException``
    unchanged and converts anything else into a generic ``400``.
    """

    def __init__(self, app: object, *, path: str, limit: int) -> None:
        self.app = app
        self.path = path
        self.limit = limit

    async def __call__(self, scope: dict, receive: object, send: object) -> None:
        if scope.get("type") != "http" or scope.get("path") != self.path:
            await self.app(scope, receive, send)  # type: ignore[operator]

            return

        declared = self._declared_length(scope)

        if declared is not None and declared > self.limit:
            await self._refuse(scope, receive, send)

            return

        seen = 0

        async def limited_receive() -> dict:
            nonlocal seen

            message = await receive()  # type: ignore[operator]

            if message.get("type") == "http.request":
                seen += len(message.get("body", b""))

                if seen > self.limit:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=LOGIN_BODY_TOO_LARGE_DETAIL,
                    )

            return message

        await self.app(scope, limited_receive, send)  # type: ignore[operator]

    @staticmethod
    def _declared_length(scope: dict) -> int | None:
        for name, value in scope.get("headers", ()):
            if name == b"content-length":
                try:
                    return int(value)
                except ValueError:
                    return None

        return None

    @staticmethod
    async def _refuse(scope: dict, receive: object, send: object) -> None:
        response = JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": LOGIN_BODY_TOO_LARGE_DETAIL},
            headers=dict(NO_STORE_HEADERS),
        )

        await response(scope, receive, send)


class LoginRequest(BaseModel):
    """Submitted credentials.

    Neither field carries a validation constraint on purpose. A pydantic constraint
    failure produces a 422 body that echoes the value that failed, and one of these
    values is a password, so length is checked in the login service where the answer can
    stay generic. Because the only way to fail validation here is to send a non-string,
    that echo can never contain a real password.
    """

    username: str
    password: str


class CsrfTokenResponse(BaseModel):
    """The CSRF token the browser must echo on state-changing requests.

    Delivered in a response body, never in a cookie the client could choose and never in
    a URL. The browser holds it in memory only.
    """

    csrf_token: str


@router.get("/csrf", response_model=CsrfTokenResponse)
async def csrf_token(request: Request, response: Response) -> CsrfTokenResponse:
    """Hand the caller the CSRF token for its current state.

    With a live session the answer is that session's own authoritative token, which never
    changes for the life of the session, so a reloaded page recovers it here. Without a
    session the answer is a fresh pre-authentication token, which is what the login form
    needs before any identity exists.

    A cross-origin caller cannot read this response, which is the point of carrying the
    token in a header rather than a cookie.
    """
    response.headers.update(NO_STORE_HEADERS)

    session = resolve_session(request)

    if session is not None:
        return CsrfTokenResponse(csrf_token=session.csrf_token)

    return CsrfTokenResponse(
        csrf_token=pre_auth_tokens(request).issue(client_ip=client_ip(request))
    )


@router.post("/login", response_model=IdentityResponse)
async def login(
    request: Request,
    response: Response,
    payload: LoginRequest,
) -> IdentityResponse | JSONResponse:
    """Authenticate the supplied credentials and, on success, start a session.

    The order of the checks is the security design: the CSRF token is verified before any
    credential is examined, throttling is consulted before the provider is called, and a
    session is created only for an explicit success.
    """
    response.headers.update(NO_STORE_HEADERS)

    # Reachable without a session, so its own CSRF check runs here rather than at router
    # level. A cross-site form post cannot present this header.
    require_login_csrf(request)

    result = login_service(request).authenticate(
        username=payload.username,
        password=payload.password,
        client_ip=client_ip(request),
        # Whatever session the caller already holds is destroyed on success, which is what
        # makes a planted identifier useless.
        presented_session_id=request.cookies.get(SESSION_COOKIE_NAME),
    )

    if result.outcome is not LoginOutcome.SUCCESS or result.issued is None:
        return _failure_response(result)

    # The pre-authentication token has done its job; the session's own token now governs.
    pre_auth_tokens(request).consume(
        request.headers.get(CSRF_HEADER_NAME), client_ip=client_ip(request)
    )

    settings = session_cookie_settings()

    response.set_cookie(
        key=settings["key"],
        value=result.issued.session_id,
        path=settings["path"],
        httponly=settings["httponly"],
        secure=settings["secure"],
        samesite=settings["samesite"],
        # No Max-Age: this stays a browser-session cookie. The authoritative expiry is
        # server-side, and a cookie that outlives its record is worthless anyway.
    )

    return build_identity_payload(result.issued.session.identity)


def _failure_response(result: LoginResult) -> JSONResponse:
    """Translate a non-success outcome into one of exactly three client answers.

    The login service has already logged the detail, so nothing here names the reason.
    """
    if result.outcome is LoginOutcome.THROTTLED:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": LOGIN_FAILED_DETAIL},
            headers={
                **NO_STORE_HEADERS,
                "Retry-After": str(result.retry_after_seconds or 1),
            },
        )

    if result.outcome is LoginOutcome.REJECTED:
        code = status.HTTP_401_UNAUTHORIZED
        detail = LOGIN_FAILED_DETAIL
    else:
        # UNAVAILABLE, MISCONFIGURED and PROVIDER_NOT_CONFIGURED share one answer, so a
        # caller cannot map the deployment's authentication state.
        code = status.HTTP_503_SERVICE_UNAVAILABLE
        detail = AUTHENTICATION_UNAVAILABLE_DETAIL

    return JSONResponse(
        status_code=code,
        content={"detail": detail},
        headers=dict(NO_STORE_HEADERS),
    )
