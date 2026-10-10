"""P4-08 login: the HTTP surface, session issuance, rotation and failure handling.

Everything here runs against an injected provider and an injected clock, so no test
touches a directory, opens a socket or sleeps. The provider records its calls, which is
what lets these tests assert that a refused request never reached it at all.
"""

import logging
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from pentaia.webapp import WebAppConfig, create_app
from pentaia.webapp.api.login import LOGIN_PATH, MAX_LOGIN_BODY_BYTES
from pentaia.webapp.auth.base import AuthOutcome, AuthResult, ProviderUnavailable
from pentaia.webapp.auth.csrf import (
    CSRF_HEADER_NAME,
    MAX_CSRF_TOKEN_LENGTH,
    token_is_well_formed,
)
from pentaia.webapp.auth.login import MAX_PASSWORD_LENGTH
from pentaia.webapp.identity import AUTH_SOURCE_AD, AuthenticatedIdentity
from pentaia.webapp.sessions import SESSION_COOKIE_NAME

START = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
USERNAME = "admin@example.test"
PASSWORD = "not-a-real-password"
PEER = "203.0.113.7"
PROXY_PEER = "127.0.0.1"


class Clock:
    """A clock the test advances by hand."""

    def __init__(self, start: datetime = START) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class RecordingProvider:
    """A provider that proves one credential and records every call."""

    def __init__(
        self,
        *,
        outcome: AuthOutcome | None = None,
        raises: Exception | None = None,
        name: str = AUTH_SOURCE_AD,
    ) -> None:
        self.name = name
        self.attempts: list[tuple[object, object]] = []
        self._outcome = outcome
        self._raises = raises

    def authenticate(self, username: object, password: object) -> AuthResult:
        self.attempts.append((username, password))

        if self._raises is not None:
            raise self._raises

        if self._outcome is not None:
            return AuthResult(self._outcome)

        if username == USERNAME and password == PASSWORD:
            return AuthResult(
                AuthOutcome.SUCCESS,
                AuthenticatedIdentity.from_provider(
                    auth_source=self.name,
                    username=USERNAME,
                    display_name="Admin User",
                ),
            )

        return AuthResult(AuthOutcome.REJECTED)


def build(
    *,
    provider: RecordingProvider | None = None,
    clock: Clock | None = None,
    client_address: str = PEER,
    **config: object,
):
    settings = {"auth_provider": "ad", **config}
    app = create_app(
        WebAppConfig(**settings),  # type: ignore[arg-type]
        auth_provider=provider if provider is not None else RecordingProvider(),
        clock=clock,
    )

    # ``https`` is deliberate: the session cookie is ``Secure``, so a browser-like client
    # will not send it back over plain HTTP. Testing over http would silently skip every
    # cookie, which is why these tests would otherwise pass while proving nothing.
    return app, TestClient(app, base_url="https://testserver", client=(client_address, 4321))


def csrf_token(client: TestClient, headers: dict | None = None) -> str:
    response = client.get("/api/auth/csrf", headers=headers or {})

    assert response.status_code == 200

    return response.json()["csrf_token"]


def sign_in(client: TestClient, *, username: str = USERNAME, password: str = PASSWORD):
    return client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
        headers={CSRF_HEADER_NAME: csrf_token(client)},
    )


def issued_session_id(response) -> str:
    """Read the session identifier out of a ``Set-Cookie`` header.

    Read from the response rather than the test client's jar: a test that plants a cookie
    by hand puts it in a different jar domain than the server's own cookie, and httpx then
    refuses to choose between the two.
    """
    header = response.headers["set-cookie"]
    prefix = f"{SESSION_COOKIE_NAME}="
    start = header.index(prefix) + len(prefix)

    return header[start:].split(";", 1)[0]


# --- the CSRF token bootstrap ---------------------------------------------


def test_the_csrf_bootstrap_issues_a_well_formed_token() -> None:
    _, client = build()

    response = client.get("/api/auth/csrf")

    assert response.status_code == 200
    assert token_is_well_formed(response.json()["csrf_token"])
    assert set(response.json()) == {"csrf_token"}
    assert response.headers["cache-control"] == "no-store"


def test_the_csrf_token_is_not_delivered_in_a_cookie() -> None:
    """A cookie the client cannot be tricked into setting is the point of the design."""
    _, client = build()

    response = client.get("/api/auth/csrf")

    assert "set-cookie" not in response.headers


def test_each_bootstrap_call_issues_a_fresh_token() -> None:
    _, client = build()

    assert csrf_token(client) != csrf_token(client)


# --- login is gated on the pre-authentication token ------------------------


def test_a_login_without_a_token_is_refused_before_the_provider(recording=None) -> None:
    provider = RecordingProvider()
    _, client = build(provider=provider)

    response = client.post(
        "/api/auth/login", json={"username": USERNAME, "password": PASSWORD}
    )

    assert response.status_code == 403
    assert set(response.json()) == {"detail"}
    assert provider.attempts == [], "the provider must not be called at all"
    assert "set-cookie" not in response.headers


@pytest.mark.parametrize(
    "token",
    [
        "not-a-real-token",
        "a" * (MAX_CSRF_TOKEN_LENGTH + 1),
        "token with spaces",
        "!@#$%^&*()",
    ],
)
def test_a_token_the_server_never_issued_is_refused(token: str) -> None:
    provider = RecordingProvider()
    _, client = build(provider=provider)

    response = client.post(
        "/api/auth/login",
        json={"username": USERNAME, "password": PASSWORD},
        headers={CSRF_HEADER_NAME: token},
    )

    assert response.status_code == 403
    assert provider.attempts == []


def test_a_consumed_token_cannot_be_replayed() -> None:
    """A successful login spends the pre-authentication token."""
    provider = RecordingProvider()
    app, client = build(provider=provider)
    token = csrf_token(client)

    first = client.post(
        "/api/auth/login",
        json={"username": USERNAME, "password": PASSWORD},
        headers={CSRF_HEADER_NAME: token},
    )
    assert first.status_code == 200

    client.cookies.clear()
    replay = client.post(
        "/api/auth/login",
        json={"username": USERNAME, "password": PASSWORD},
        headers={CSRF_HEADER_NAME: token},
    )

    assert replay.status_code == 403
    assert app.state.session_store.active_count == 1, "only the first login created one"


def test_a_failed_login_does_not_consume_the_token() -> None:
    """A typo must not force the browser to fetch a new token before retrying."""
    _, client = build()
    token = csrf_token(client)

    for password in ("wrong", "still-wrong", PASSWORD):
        response = client.post(
            "/api/auth/login",
            json={"username": USERNAME, "password": password},
            headers={CSRF_HEADER_NAME: token},
        )

    assert response.status_code == 200


# --- a successful login ----------------------------------------------------


def test_a_successful_login_returns_the_identity_projection() -> None:
    _, client = build()

    response = sign_in(client)

    assert response.status_code == 200
    assert set(response.json()) == {
        "user_id",
        "username",
        "display_name",
        "auth_source",
        "authenticated_at",
    }
    assert response.json()["user_id"] == f"ad:{USERNAME}"
    assert response.headers["cache-control"] == "no-store"


def test_a_successful_login_sets_exactly_the_reviewed_cookie() -> None:
    _, client = build()

    response = sign_in(client)
    cookie = response.headers["set-cookie"]

    assert SESSION_COOKIE_NAME in cookie
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=lax" in cookie.replace("samesite", "SameSite")
    assert "Path=/" in cookie
    assert "Domain" not in cookie
    # No Max-Age: the authoritative lifetime is server-side, not in the cookie.
    assert "Max-Age" not in cookie


def test_the_session_cookie_opens_the_authenticated_surface() -> None:
    _, client = build()

    assert sign_in(client).status_code == 200
    assert client.get("/api/me").status_code == 200
    assert client.get("/api/status").status_code == 200


def test_the_response_body_never_carries_a_session_or_a_token() -> None:
    app, client = build()

    response = sign_in(client)
    body = response.text.lower()

    for forbidden in ("session", "csrf", "token", "cookie", "password"):
        assert forbidden not in body

    issued = app.state.session_store
    assert issued.active_count == 1


# --- the failure taxonomy --------------------------------------------------


def test_a_wrong_password_and_an_unknown_user_are_indistinguishable() -> None:
    _, client = build()

    wrong = sign_in(client, password="wrong")
    unknown = sign_in(client, username="nobody@example.test")

    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()
    assert wrong.text == unknown.text


@pytest.mark.parametrize(
    "outcome",
    [AuthOutcome.UNAVAILABLE, AuthOutcome.MISCONFIGURED],
)
def test_an_unusable_provider_is_answered_generically(outcome: AuthOutcome) -> None:
    _, client = build(provider=RecordingProvider(outcome=outcome))

    response = sign_in(client)

    assert response.status_code == 503
    assert set(response.json()) == {"detail"}
    assert "set-cookie" not in response.headers


def test_unavailable_and_misconfigured_are_indistinguishable() -> None:
    _, unavailable = build(provider=RecordingProvider(outcome=AuthOutcome.UNAVAILABLE))
    _, misconfigured = build(provider=RecordingProvider(outcome=AuthOutcome.MISCONFIGURED))

    assert sign_in(unavailable).text == sign_in(misconfigured).text


def test_a_deployment_with_no_provider_refuses_login() -> None:
    app = create_app(WebAppConfig(), clock=Clock())

    with TestClient(app, base_url="https://testserver", client=(PEER, 4321)) as client:
        token = csrf_token(client)
        response = client.post(
            "/api/auth/login",
            json={"username": USERNAME, "password": PASSWORD},
            headers={CSRF_HEADER_NAME: token},
        )

    assert response.status_code == 503
    assert app.state.session_store.active_count == 0


def test_a_provider_that_raises_fails_closed() -> None:
    """A provider bug must not produce a 500 that could describe its own internals."""
    provider = RecordingProvider(raises=ProviderUnavailable("directory detail"))

    _, client = build(provider=provider, docs_enabled=True)

    response = sign_in(client)

    assert response.status_code == 503
    assert "directory detail" not in response.text
    assert "set-cookie" not in response.headers


@pytest.mark.parametrize(
    "password", ["wrong", "", " ", "x" * (MAX_PASSWORD_LENGTH + 1)]
)
def test_no_failure_path_creates_a_session(password: str) -> None:
    app, client = build()

    response = sign_in(client, password=password)

    assert response.status_code in (401, 429)
    assert "set-cookie" not in response.headers
    assert app.state.session_store.active_count == 0


def test_an_oversized_password_is_refused_without_touching_the_directory() -> None:
    provider = RecordingProvider()
    _, client = build(provider=provider)

    response = sign_in(client, password="x" * (MAX_PASSWORD_LENGTH + 1))

    assert response.status_code == 401
    assert provider.attempts == []


def test_a_non_string_password_cannot_echo_a_real_password() -> None:
    """The model has no constraints, so a 422 body can never carry a password."""
    app = build(docs_enabled=True)[0]

    with TestClient(app, base_url="https://testserver", client=(PEER, 4321)) as client:
        token = csrf_token(client)
        response = client.post(
            "/api/auth/login",
            json={"username": USERNAME, "password": {"nested": "value"}},
            headers={CSRF_HEADER_NAME: token},
        )

    assert response.status_code == 422
    assert PASSWORD not in response.text


# --- throttling ------------------------------------------------------------


def test_repeated_failures_are_throttled_with_retry_after() -> None:
    provider = RecordingProvider()
    _, client = build(provider=provider, login_max_attempts=3)

    for _ in range(3):
        assert sign_in(client, password="wrong").status_code == 401

    calls_before = len(provider.attempts)
    throttled = sign_in(client, password="wrong")

    assert throttled.status_code == 429
    assert int(throttled.headers["retry-after"]) > 0
    assert len(provider.attempts) == calls_before, "no provider call while throttled"


def test_a_throttled_response_is_generic() -> None:
    _, client = build(login_max_attempts=1)

    assert sign_in(client, password="wrong").status_code == 401
    throttled = sign_in(client, password="wrong")

    assert set(throttled.json()) == {"detail"}
    assert "wrong" not in throttled.text


def test_a_successful_login_clears_the_pair() -> None:
    _, client = build(login_max_attempts=2)

    assert sign_in(client, password="wrong").status_code == 401
    assert sign_in(client).status_code == 200

    # The pair is clear again, so a later typo is a normal 401 rather than a lockout.
    assert sign_in(client, password="wrong").status_code == 401


def test_throttling_follows_the_address() -> None:
    app = build(login_max_attempts=1)[0]

    with TestClient(app, base_url="https://testserver", client=(PEER, 4321)) as first:
        assert sign_in(first, password="wrong").status_code == 401

    with TestClient(app, base_url="https://testserver", client=("198.51.100.9", 4321)) as second:
        assert sign_in(second, password="wrong").status_code == 401


def test_a_spoofed_forwarded_header_cannot_choose_a_throttle_bucket() -> None:
    """An untrusted peer cannot escape its own bucket by sending a header."""
    app = build(login_max_attempts=1)[0]

    with TestClient(app, base_url="https://testserver", client=(PEER, 4321)) as client:
        token = csrf_token(client)
        headers = {CSRF_HEADER_NAME: token, "X-Forwarded-For": "198.51.100.9"}

        first = client.post(
            "/api/auth/login",
            json={"username": USERNAME, "password": "wrong"},
            headers=headers,
        )
        assert first.status_code == 401

    with TestClient(app, base_url="https://testserver", client=(PEER, 4321)) as client:
        token = csrf_token(client)
        second = client.post(
            "/api/auth/login",
            json={"username": USERNAME, "password": "wrong"},
            headers={CSRF_HEADER_NAME: token, "X-Forwarded-For": "198.51.100.10"},
        )

    assert second.status_code == 429, "the peer's bucket, not the header's"


def test_a_trusted_proxy_header_selects_the_client_bucket() -> None:
    """Behind the configured proxy the forwarded address is the client."""
    app = build(login_max_attempts=1, trusted_proxies=("127.0.0.1",))[0]

    # Each request carries the same forwarding header a real browser would: the token is
    # bound to the resolved client address, so fetching it under one address and using it
    # under another is correctly refused rather than silently re-bucketed.
    with TestClient(app, base_url="https://testserver", client=(PROXY_PEER, 4321)) as proxied:
        forwarding = {"X-Forwarded-For": "198.51.100.9"}
        one = proxied.post(
            "/api/auth/login",
            json={"username": USERNAME, "password": "wrong"},
            headers={CSRF_HEADER_NAME: csrf_token(proxied, forwarding), **forwarding},
        )
        assert one.status_code == 401

    with TestClient(app, base_url="https://testserver", client=(PROXY_PEER, 4321)) as proxied:
        other_forwarding = {"X-Forwarded-For": "198.51.100.10"}
        other = proxied.post(
            "/api/auth/login",
            json={"username": USERNAME, "password": "wrong"},
            headers={
                CSRF_HEADER_NAME: csrf_token(proxied, other_forwarding),
                **other_forwarding,
            },
        )

    assert other.status_code == 401, "a different forwarded client is a different bucket"


# --- fixation and rotation -------------------------------------------------


def test_a_planted_session_is_destroyed_at_login() -> None:
    """Fixation: an identifier the caller already holds never survives authentication."""
    app, client = build()
    planted = app.state.session_store.create(
        AuthenticatedIdentity.from_provider(
            auth_source=AUTH_SOURCE_AD, username="planted@example.test"
        )
    ).session_id

    client.cookies.set(SESSION_COOKIE_NAME, planted)
    assert client.get("/api/me").status_code == 200

    response = sign_in(client)

    assert response.status_code == 200

    new_cookie = issued_session_id(response)
    assert new_cookie != planted

    # The planted identifier is dead server-side, not merely replaced in the browser.
    with TestClient(app, base_url="https://testserver", client=(PEER, 4321)) as replay:
        replay.cookies.set(SESSION_COOKIE_NAME, planted)
        assert replay.get("/api/me").status_code == 401

    with TestClient(app, base_url="https://testserver", client=(PEER, 4321)) as fresh:
        fresh.cookies.set(SESSION_COOKIE_NAME, new_cookie)
        assert fresh.get("/api/me").status_code == 200


def test_every_login_issues_a_new_identifier_and_token() -> None:
    app, client = build()

    assert sign_in(client).status_code == 200
    first_cookie = client.cookies.get(SESSION_COOKIE_NAME)
    first_token = client.get("/api/auth/csrf").json()["csrf_token"]

    client.cookies.clear()
    assert sign_in(client).status_code == 200
    second_cookie = client.cookies.get(SESSION_COOKIE_NAME)
    second_token = client.get("/api/auth/csrf").json()["csrf_token"]

    assert first_cookie != second_cookie
    assert first_token != second_token
    assert app.state.session_store.active_count == 2


def test_a_failed_re_authentication_leaves_the_session_untouched() -> None:
    """A wrong password must not disturb a session the caller already holds."""
    app, client = build()

    assert sign_in(client).status_code == 200
    session_cookie = client.cookies.get(SESSION_COOKIE_NAME)
    session_token = client.get("/api/auth/csrf").json()["csrf_token"]

    assert sign_in(client, password="wrong").status_code == 401

    assert client.cookies.get(SESSION_COOKIE_NAME) == session_cookie
    assert client.get("/api/me").status_code == 200
    assert client.get("/api/auth/csrf").json()["csrf_token"] == session_token
    assert app.state.session_store.active_count == 1


# --- token recovery after a refresh ----------------------------------------


def test_the_session_token_is_recovered_after_a_reload() -> None:
    """A reload loses the in-memory token; the bootstrap hands back the same one."""
    _, client = build()
    assert sign_in(client).status_code == 200

    first = client.get("/api/auth/csrf").json()["csrf_token"]
    second = client.get("/api/auth/csrf").json()["csrf_token"]

    assert first == second, "the session's token is authoritative and stable"


def test_the_session_token_is_not_the_pre_authentication_token() -> None:
    _, client = build()

    pre_auth = csrf_token(client)
    assert sign_in(client).status_code == 200

    assert client.get("/api/auth/csrf").json()["csrf_token"] != pre_auth


# --- expiry, driven by the injected clock ----------------------------------


def test_the_session_expires_after_the_idle_timeout() -> None:
    clock = Clock()
    app, client = build(clock=clock, session_idle_timeout=60, session_absolute_lifetime=600)

    assert sign_in(client).status_code == 200

    clock.advance(61)

    assert client.get("/api/me").status_code == 401
    assert app.state.session_store.active_count == 0, "the record is destroyed, not just refused"


def test_activity_refreshes_the_idle_timer() -> None:
    clock = Clock()
    _, client = build(clock=clock, session_idle_timeout=60, session_absolute_lifetime=600)

    assert sign_in(client).status_code == 200

    for _ in range(5):
        clock.advance(50)
        assert client.get("/api/me").status_code == 200


def test_activity_never_extends_the_absolute_lifetime() -> None:
    clock = Clock()
    _, client = build(clock=clock, session_idle_timeout=60, session_absolute_lifetime=300)

    assert sign_in(client).status_code == 200

    # Stay continuously active, never idling past the timeout.
    for _ in range(5):
        clock.advance(59)
        assert client.get("/api/me").status_code == 200

    clock.advance(59)
    assert client.get("/api/me").status_code == 401, "600s of activity cannot outlast 300s"


# --- cross-user isolation --------------------------------------------------


def test_two_users_hold_independent_sessions() -> None:
    class TwoUserProvider(RecordingProvider):
        def authenticate(self, username: object, password: object) -> AuthResult:
            self.attempts.append((username, password))

            return AuthResult(
                AuthOutcome.SUCCESS,
                AuthenticatedIdentity.from_provider(
                    auth_source=AUTH_SOURCE_AD, username=str(username)
                ),
            )

    app = create_app(
        WebAppConfig(auth_provider="ad"), auth_provider=TwoUserProvider(), clock=Clock()
    )

    with TestClient(app, base_url="https://testserver", client=(PEER, 4321)) as first:
        assert sign_in(first, username="user.one@example.test").status_code == 200
        first_token = first.get("/api/auth/csrf").json()["csrf_token"]

    with TestClient(app, base_url="https://testserver", client=("198.51.100.9", 4321)) as second:
        assert sign_in(second, username="user.two@example.test").status_code == 200
        second_token = second.get("/api/auth/csrf").json()["csrf_token"]

        assert second.get("/api/me").json()["user_id"] == "ad:user.two@example.test"
        assert first_token != second_token

    assert first.get("/api/me").json()["user_id"] == "ad:user.one@example.test"


def test_invalidating_one_user_leaves_another_alone() -> None:
    """The administrative hook #64 will use destroys exactly one user's sessions."""
    app, client = build()
    assert sign_in(client).status_code == 200

    other = app.state.session_store.create(
        AuthenticatedIdentity.from_provider(
            auth_source=AUTH_SOURCE_AD, username="other@example.test"
        )
    ).session_id

    assert app.state.session_store.invalidate_user(f"ad:{USERNAME}") == 1

    assert client.get("/api/me").status_code == 401
    assert app.state.session_store.resolve(other) is not None


# --- hygiene ---------------------------------------------------------------


def test_no_password_session_or_token_reaches_the_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    _, client = build()

    with caplog.at_level(logging.DEBUG):
        assert sign_in(client).status_code == 200
        session_id = client.cookies.get(SESSION_COOKIE_NAME)
        session_token = client.get("/api/auth/csrf").json()["csrf_token"]

    logged = "\n".join(record.getMessage() for record in caplog.records)

    assert PASSWORD not in logged
    assert session_id not in logged
    assert session_token not in logged


def test_a_failed_login_does_not_log_the_attempted_username(
    caplog: pytest.LogCaptureFixture,
) -> None:
    _, client = build()

    with caplog.at_level(logging.DEBUG):
        assert sign_in(client, username="victim@example.test", password="wrong").status_code == 401

    logged = "\n".join(record.getMessage() for record in caplog.records)

    assert "victim" not in logged
    assert "wrong" not in logged


# --- input safety: nothing submitted is ever reflected back ----------------
#
# Pydantic reports the value that failed validation, and one of the values this endpoint
# accepts is a password. Without the application's validation handler a wrongly typed
# credential would be echoed straight back in the 422 body, and from there into a proxy
# log or a client-side error report. These tests pin that it is not.

#: Distinctive enough that finding it anywhere is unambiguous.
SUBMITTED_SECRET = "SuperSecretPassword-do-not-echo"


def _login_raw(client: TestClient, body: bytes, headers: dict | None = None):
    return client.post(
        "/api/auth/login",
        content=body,
        headers={"Content-Type": "application/json", **(headers or {})},
    )


def _assert_no_leak(response, *, label: str) -> None:
    """A response may describe the request, never repeat what was submitted."""
    body = response.text

    assert response.status_code < 500, (label, response.status_code, body[:200])
    assert SUBMITTED_SECRET not in body, label

    for internal in ("Traceback", "site-packages", "pentaia.webapp", "/home/"):
        assert internal not in body, (label, internal)


@pytest.mark.parametrize(
    ("label", "body"),
    [
        ("malformed json", b'{"username": "u", "password": "' + SUBMITTED_SECRET.encode()),
        ("trailing garbage", b'{"username": "u", "password": "x"} garbage'),
        ("not an object", b'["' + SUBMITTED_SECRET.encode() + b'"]'),
        ("empty body", b""),
        ("missing fields", b"{}"),
        (
            "password is an object",
            b'{"username": "u", "password": {"inner": "' + SUBMITTED_SECRET.encode() + b'"}}',
        ),
        (
            "password is an array",
            b'{"username": "u", "password": ["' + SUBMITTED_SECRET.encode() + b'"]}',
        ),
        (
            "password is a number",
            b'{"username": "u", "password": 12345}',
        ),
        (
            "username is an object",
            b'{"username": {"inner": "' + SUBMITTED_SECRET.encode() + b'"}, "password": "x"}',
        ),
        (
            "username is an array",
            b'{"username": ["' + SUBMITTED_SECRET.encode() + b'"], "password": "x"}',
        ),
        (
            "extra unexpected fields",
            b'{"username": "u", "password": "x", "provider": "' + SUBMITTED_SECRET.encode() + b'"}',
        ),
    ],
)
def test_a_malformed_login_body_never_reflects_what_was_submitted(
    label: str, body: bytes
) -> None:
    app = build(docs_enabled=True)[0]

    with TestClient(app, base_url="https://testserver", client=(PEER, 4321)) as client:
        token = csrf_token(client)
        response = _login_raw(client, body, {CSRF_HEADER_NAME: token})

    _assert_no_leak(response, label=label)
    assert app.state.session_store.active_count == 0


def test_a_validation_failure_returns_only_safe_error_fields() -> None:
    """No ``input`` and no ``ctx``: the two places a submitted value would appear."""
    app = build()[0]

    with TestClient(app, base_url="https://testserver", client=(PEER, 4321)) as client:
        token = csrf_token(client)
        response = _login_raw(
            client,
            b'{"username": "u", "password": {"inner": "' + SUBMITTED_SECRET.encode() + b'"}}',
            {CSRF_HEADER_NAME: token},
        )

    assert response.status_code == 422

    for error in response.json()["detail"]:
        assert set(error) == {"type", "loc", "msg"}
        assert "input" not in error
        assert "ctx" not in error


def test_an_oversized_username_is_answered_generically() -> None:
    _, client = build()

    response = sign_in(client, username="u" * 5000 + "@example.test")

    assert response.status_code == 401
    assert set(response.json()) == {"detail"}
    assert "u" * 100 not in response.text


def test_an_oversized_body_is_refused_before_it_is_parsed() -> None:
    """The one unauthenticated body is bounded, and the refusal says nothing."""
    app, client = build()

    response = _login_raw(
        client,
        b'{"username": "u", "password": "' + b"p" * 300_000 + b'"}',
        {CSRF_HEADER_NAME: csrf_token(client)},
    )

    assert response.status_code == 413
    assert set(response.json()) == {"detail"}
    assert app.state.session_store.active_count == 0


def test_a_body_within_the_bound_is_still_processed() -> None:
    _, client = build()

    response = sign_in(client, password="p" * 900)

    assert response.status_code == 401, "parsed and refused as a credential, not as a size"


@pytest.mark.parametrize(
    "body",
    [
        b'{"username": "u", "password": "' + SUBMITTED_SECRET.encode(),
        b'{"username": ["' + SUBMITTED_SECRET.encode() + b'"], "password": "x"}',
        b'{"username": "u", "password": {"inner": "' + SUBMITTED_SECRET.encode() + b'"}}',
        b'{"username": "u", "password": "' + b"p" * 300_000 + b'"}',
    ],
    ids=["malformed-json", "username-array", "password-object", "oversized-body"],
)
def test_a_rejected_body_never_reaches_the_log(
    body: bytes, caplog: pytest.LogCaptureFixture
) -> None:
    app = build(docs_enabled=True)[0]

    with (
        caplog.at_level(logging.DEBUG),
        TestClient(app, base_url="https://testserver", client=(PEER, 4321)) as client,
    ):
        token = csrf_token(client)
        _login_raw(client, body, {CSRF_HEADER_NAME: token})

    logged = "\n".join(record.getMessage() for record in caplog.records)

    assert SUBMITTED_SECRET not in logged
    assert "Traceback" not in logged


def test_a_body_without_a_content_length_is_still_bounded() -> None:
    """The bound cannot be bypassed by omitting Content-Length.

    httpx sends an iterable body with chunked transfer encoding and no declared length,
    which is exactly the case a header-only check would miss.
    """
    app, client = build()

    def chunks():
        for _ in range(20):
            yield b"p" * 8192  # 160 KiB in total, never declared

    response = client.post(
        "/api/auth/login",
        content=chunks(),
        headers={
            CSRF_HEADER_NAME: csrf_token(client),
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 413
    assert set(response.json()) == {"detail"}
    assert app.state.session_store.active_count == 0


def test_a_single_oversized_chunk_without_a_content_length_is_bounded() -> None:
    _, client = build()

    response = client.post(
        "/api/auth/login",
        content=iter([b"p" * (MAX_LOGIN_BODY_BYTES + 1)]),
        headers={
            CSRF_HEADER_NAME: csrf_token(client),
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 413
    assert set(response.json()) == {"detail"}


def test_a_streamed_body_within_the_bound_is_still_processed() -> None:
    """The bound must refuse only what is oversized, not everything undeclared."""
    _, client = build()

    response = client.post(
        "/api/auth/login",
        content=iter([b'{"username": "u", "password": "x"}']),
        headers={
            CSRF_HEADER_NAME: csrf_token(client),
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 401, "parsed and refused as a credential"


def test_a_refused_streamed_body_never_reaches_the_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = build()[0]

    with (
        caplog.at_level(logging.DEBUG),
        TestClient(app, base_url="https://testserver", client=(PEER, 4321)) as client,
    ):
        response = client.post(
            "/api/auth/login",
            content=iter([SUBMITTED_SECRET.encode() * 9000]),
            headers={
                CSRF_HEADER_NAME: csrf_token(client),
                "Content-Type": "application/json",
            },
        )

    assert response.status_code == 413

    logged = "\n".join(record.getMessage() for record in caplog.records)

    assert SUBMITTED_SECRET not in logged
    assert "Traceback" not in logged


def test_the_body_bound_is_keyed_on_the_advertised_login_path() -> None:
    """The middleware bounds LOGIN_PATH; if that constant drifted the bound would not apply."""
    app = build(docs_enabled=True)[0]

    with TestClient(app, base_url="https://testserver", client=(PEER, 4321)) as client:
        spec = client.get("/openapi.json").json()

    assert LOGIN_PATH in spec["paths"]
    assert LOGIN_PATH == "/api/auth/login"
