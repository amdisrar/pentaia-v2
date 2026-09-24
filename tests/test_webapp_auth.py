"""P4-04 session resolution over the HTTP surface.

Covers the dependency that replaced the P4-02 placeholder, the spoofing resistance the
task requires, logout, and the guarantees that P4-02/P4-03 behaviour is unchanged.

Cookies are set on the client cookie jar rather than passed per request, because the
per-request form is deprecated and its persistence semantics are ambiguous.
"""

import logging
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from pentaia.webapp import WebAppConfig, create_app
from pentaia.webapp.identity import AuthenticatedIdentity
from pentaia.webapp.sessions import SESSION_COOKIE_NAME

START = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)

#: Headers a client might use to try to assert an identity. Phase 4 has no
#: trusted-proxy identity model, so all of these must be ignored.
SPOOFING_HEADERS = {
    "X-User-ID": "ad:attacker@example.com",
    "X-Username": "attacker@example.com",
    "X-Auth-Source": "radius",
    "X-Forwarded-User": "attacker@example.com",
}
SPOOFING_QUERY = "?user_id=ad:attacker@example.com&auth_source=radius&username=attacker"


def build_app() -> tuple[object, TestClient]:
    app = create_app(WebAppConfig(docs_enabled=True))

    return app, TestClient(app)


def identity(username: str = "user@example.com") -> AuthenticatedIdentity:
    return AuthenticatedIdentity.from_provider(
        auth_source="ad", username=username, display_name="Example User"
    )


@pytest.fixture()
def app_and_client():
    app, client = build_app()

    with client:
        yield app, client


def issue(app, username: str = "user@example.com"):
    return app.state.session_store.create(identity(username))


def sign_in(client: TestClient, session_id: str) -> None:
    """Present an opaque session identifier to the application."""
    client.cookies.set(SESSION_COOKIE_NAME, session_id)


def forget_cookie(client: TestClient) -> None:
    client.cookies.clear()


# --- the surface is authenticated by default -------------------------------


#: The methods and paths of the authenticated API surface.
#:
#: Kept static rather than derived from a freshly built application. Building an app
#: at collection time emits startup records before the session-scoped conftest fixture
#: can redirect the application log, which wrote test noise into the developer's
#: production log. ``test_the_schema_advertises_the_reviewed_api_surface`` fails if a
#: route is added or removed without updating this list, so the parametrised test below
#: still covers every route.
API_OPERATIONS = [
    ("GET", "/api/me"),
    ("GET", "/api/status"),
    ("POST", "/api/auth/logout"),
]


def test_the_schema_advertises_the_reviewed_api_surface(app_and_client) -> None:
    """Every advertised /api route must appear in API_OPERATIONS and vice versa."""
    _, client = app_and_client

    spec = client.get("/openapi.json").json()
    advertised = sorted(
        (method.upper(), path)
        for path, operations in spec["paths"].items()
        if path.startswith("/api")
        for method in operations
    )

    assert advertised == API_OPERATIONS


@pytest.mark.parametrize(("method", "path"), API_OPERATIONS)
def test_every_api_route_refuses_an_unauthenticated_request(
    app_and_client, method: str, path: str
) -> None:
    """A future route added without the dependency fails this test."""
    _, client = app_and_client

    response = client.request(method, path)

    assert response.status_code == 401, f"{method} {path} did not require a session"


# --- resolution through the dependency ------------------------------------


def test_a_valid_session_resolves_identity_through_the_dependency(app_and_client) -> None:
    app, client = app_and_client
    sign_in(client, issue(app).session_id)

    response = client.get("/api/me")

    assert response.status_code == 200
    body = response.json()
    assert body["user_id"] == "ad:user@example.com"
    assert body["username"] == "user@example.com"
    assert body["display_name"] == "Example User"
    assert body["auth_source"] == "ad"
    assert datetime.fromisoformat(body["authenticated_at"]).tzinfo is not None


def test_the_identity_projection_is_exactly_the_safe_field_set(app_and_client) -> None:
    app, client = app_and_client
    sign_in(client, issue(app).session_id)

    body = client.get("/api/me").json()

    assert set(body) == {
        "user_id",
        "username",
        "display_name",
        "auth_source",
        "authenticated_at",
    }

    for forbidden in ("session", "token", "password", "cookie", "secret", "label"):
        assert not [key for key in body if forbidden in key]


def test_the_projection_does_not_expose_the_session_label(app_and_client) -> None:
    """The label is for accounting correlation, not for the browser."""
    app, client = app_and_client
    issued = issue(app)
    sign_in(client, issued.session_id)

    response = client.get("/api/me")

    assert issued.session.label not in response.text
    assert issued.session_id not in response.text


def test_a_session_also_opens_the_status_route(app_and_client) -> None:
    app, client = app_and_client
    sign_in(client, issue(app).session_id)

    assert client.get("/api/status").status_code == 200


def test_an_unknown_cookie_fails_closed(app_and_client) -> None:
    _, client = app_and_client

    for value in ("", "unknown", "a" * 100):
        sign_in(client, value)
        assert client.get("/api/me").status_code == 401, value


def test_a_cookie_claiming_an_identity_is_meaningless(app_and_client) -> None:
    """The cookie is a pointer, so it cannot carry an identity claim."""
    app, client = app_and_client

    sign_in(client, "ad:second@example.com")
    assert client.get("/api/me").status_code == 401

    sign_in(client, issue(app, "first@example.com").session_id)
    assert client.get("/api/me").json()["user_id"] == "ad:first@example.com"


# --- spoofing resistance ---------------------------------------------------


@pytest.mark.parametrize("with_session", [False, True])
def test_identity_headers_are_ignored(app_and_client, with_session: bool) -> None:
    app, client = app_and_client

    if with_session:
        sign_in(client, issue(app, "real@example.com").session_id)

    response = client.get("/api/me", headers=SPOOFING_HEADERS)

    if not with_session:
        assert response.status_code == 401
        return

    assert response.status_code == 200
    assert response.json()["user_id"] == "ad:real@example.com"
    assert response.json()["auth_source"] == "ad"


def test_identity_query_parameters_are_ignored(app_and_client) -> None:
    app, client = app_and_client

    assert client.get(f"/api/me{SPOOFING_QUERY}").status_code == 401

    sign_in(client, issue(app, "real@example.com").session_id)

    assert client.get(f"/api/me{SPOOFING_QUERY}").json()["user_id"] == "ad:real@example.com"


def test_the_raw_session_id_is_not_accepted_outside_the_cookie(app_and_client) -> None:
    """Accepting it from a header or a URL would widen the attack surface."""
    app, client = app_and_client
    issued = issue(app)

    assert client.get("/api/me", headers={"X-Session-Id": issued.session_id}).status_code == 401
    assert client.get(f"/api/me?session_id={issued.session_id}").status_code == 401
    assert client.get(f"/api/me?session={issued.session_id}").status_code == 401


def test_a_body_cannot_establish_identity(app_and_client) -> None:
    _, client = app_and_client

    assert client.post("/api/auth/logout", json={"user_id": "ad:attacker"}).status_code == 401


# --- logout ----------------------------------------------------------------


def test_logout_destroys_the_server_side_session(app_and_client) -> None:
    app, client = app_and_client
    issued = issue(app)
    sign_in(client, issued.session_id)
    assert app.state.session_store.active_count == 1

    response = client.post("/api/auth/logout")

    assert response.status_code == 204
    assert app.state.session_store.active_count == 0

    # Re-presenting the identifier must fail, which proves the record is gone rather
    # than only the browser cookie having been cleared.
    sign_in(client, issued.session_id)
    assert client.get("/api/me").status_code == 401


def test_logout_clears_the_cookie_with_the_session_attributes(app_and_client) -> None:
    app, client = app_and_client
    sign_in(client, issue(app).session_id)

    response = client.post("/api/auth/logout")

    set_cookie = response.headers.get("set-cookie", "")

    assert SESSION_COOKIE_NAME in set_cookie
    assert "Max-Age=0" in set_cookie or "expires=" in set_cookie.lower()
    assert "HttpOnly" in set_cookie
    assert "Secure" in set_cookie
    assert "Path=/" in set_cookie


def test_logout_leaves_other_sessions_alone(app_and_client) -> None:
    app, client = app_and_client
    first = issue(app)
    second = issue(app)

    sign_in(client, first.session_id)
    client.post("/api/auth/logout")

    sign_in(client, second.session_id)
    assert client.get("/api/me").status_code == 200


def test_logging_out_twice_fails_closed(app_and_client) -> None:
    app, client = app_and_client
    sign_in(client, issue(app).session_id)

    assert client.post("/api/auth/logout").status_code == 204

    forget_cookie(client)
    assert client.post("/api/auth/logout").status_code == 401


def test_logout_does_not_log_the_raw_identifier(
    app_and_client, caplog: pytest.LogCaptureFixture
) -> None:
    app, client = app_and_client
    issued = issue(app)
    sign_in(client, issued.session_id)

    with caplog.at_level(logging.INFO, logger="pentaia.webapp.api.auth"):
        client.post("/api/auth/logout")

    logged = "\n".join(record.getMessage() for record in caplog.records)

    assert issued.session_id not in logged
    assert issued.session.label in logged


# --- no fake authentication surface ---------------------------------------


def test_there_is_no_login_route(app_and_client) -> None:
    """P4-04 must not invent a login; providers arrive in P4-05/P4-06."""
    _, client = app_and_client

    assert (
        client.post("/api/auth/login", json={"username": "u", "password": "p"}).status_code
        == 404
    )
    assert client.get("/api/auth/login").status_code == 404


def test_the_browser_shell_cannot_obtain_or_assert_a_session(app_and_client) -> None:
    """Preview is a client-side layout state only: it never authenticates."""
    _, client = app_and_client

    for path in ("/", "/static/js/app.js", "/static/css/app.css"):
        body = client.get(path).text
        assert SESSION_COOKIE_NAME not in body, path
        assert "api/auth" not in body, path


# --- P4-02 / P4-03 behaviour is unchanged ---------------------------------


def test_healthz_is_unchanged(app_and_client) -> None:
    _, client = app_and_client

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_status_still_refuses_an_unauthenticated_caller(app_and_client) -> None:
    _, client = app_and_client

    response = client.get("/api/status")

    assert response.status_code == 401
    assert set(response.json()) == {"detail"}


def test_the_refusal_reveals_nothing_about_the_session(app_and_client) -> None:
    _, client = app_and_client
    sign_in(client, "some-unknown-value")

    body = client.get("/api/me").text.lower()

    assert "unknown" not in body
    assert "expired" not in body
    assert "invalid" not in body


def test_the_gui_shell_still_loads(app_and_client) -> None:
    _, client = app_and_client

    response = client.get("/")

    assert response.status_code == 200
    assert "Preview" in response.text
