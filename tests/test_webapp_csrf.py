"""P4-08 CSRF primitives: token shape, constant-time comparison, pre-auth store.

The pre-authentication token is server-bound: the store keeps digests, so a leaked dump
of the store yields nothing usable, and a token the server never issued is refused no
matter how well formed it looks.
"""

import re
from datetime import UTC, datetime, timedelta

import pytest

from pentaia.webapp.auth.csrf import (
    CSRF_HEADER_NAME,
    MAX_CSRF_TOKEN_LENGTH,
    InMemoryPreAuthTokenStore,
    generate_csrf_token,
    token_is_well_formed,
    tokens_match,
)

START = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
TOKEN_ALPHABET = re.compile(r"^[A-Za-z0-9_-]+$")


@pytest.fixture()
def store() -> InMemoryPreAuthTokenStore:
    return InMemoryPreAuthTokenStore()


# --- token generation ------------------------------------------------------


def test_a_generated_token_carries_256_bits_and_is_url_safe() -> None:
    token = generate_csrf_token()

    assert len(token) >= 43, "32 bytes of entropy, URL-safe encoded"
    assert TOKEN_ALPHABET.match(token)
    assert token_is_well_formed(token)


def test_generated_tokens_are_unique() -> None:
    tokens = {generate_csrf_token() for _ in range(200)}

    assert len(tokens) == 200


def test_the_token_travels_in_a_header_not_a_cookie_or_url() -> None:
    assert CSRF_HEADER_NAME == "X-PentAiA-CSRF"
    assert " " not in CSRF_HEADER_NAME
    assert "=" not in CSRF_HEADER_NAME


# --- shape validation ------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        None,
        0,
        True,
        b"bytes",
        "",
        "short token with spaces",
        "token,with,commas",
        "token=with=padding",
        "a" * (MAX_CSRF_TOKEN_LENGTH + 1),
    ],
)
def test_a_malformed_token_is_never_accepted(value: object) -> None:
    assert token_is_well_formed(value) is False
    assert tokens_match(generate_csrf_token(), value) is False


def test_the_longest_allowed_token_is_accepted() -> None:
    assert token_is_well_formed("a" * MAX_CSRF_TOKEN_LENGTH) is True


# --- comparison ------------------------------------------------------------


def test_matching_tokens_compare_equal() -> None:
    token = generate_csrf_token()

    assert tokens_match(token, token) is True


def test_a_different_token_never_matches() -> None:
    assert tokens_match(generate_csrf_token(), generate_csrf_token()) is False


def test_an_empty_expected_token_never_matches() -> None:
    """A session whose token is missing must not accept an empty header."""
    assert tokens_match("", "") is False
    assert tokens_match("", generate_csrf_token()) is False


# --- pre-authentication store ---------------------------------------------

CLIENT = "203.0.113.7"
OTHER_CLIENT = "198.51.100.9"


def issue(store: InMemoryPreAuthTokenStore, *, client_ip: str = CLIENT, now=START) -> str:
    return store.issue(client_ip=client_ip, now=now)


def test_an_issued_token_is_live_and_can_be_consumed_once(
    store: InMemoryPreAuthTokenStore,
) -> None:
    token = issue(store)

    assert store.is_live(token, client_ip=CLIENT, now=START) is True
    assert store.consume(token, client_ip=CLIENT, now=START) is True
    assert store.is_live(token, client_ip=CLIENT, now=START) is False
    assert store.consume(token, client_ip=CLIENT, now=START) is False


def test_a_token_the_server_never_issued_is_refused(
    store: InMemoryPreAuthTokenStore,
) -> None:
    assert store.is_live(generate_csrf_token(), client_ip=CLIENT, now=START) is False
    assert store.consume(generate_csrf_token(), client_ip=CLIENT, now=START) is False


@pytest.mark.parametrize("value", [None, "", "a" * (MAX_CSRF_TOKEN_LENGTH + 1), 42, b"x"])
def test_a_malformed_token_is_refused_without_comparison(
    store: InMemoryPreAuthTokenStore, value: object
) -> None:
    assert store.is_live(value, client_ip=CLIENT, now=START) is False
    assert store.consume(value, client_ip=CLIENT, now=START) is False


# --- the token is bound to the client it was issued to ---------------------


def test_a_token_is_not_live_for_another_client(
    store: InMemoryPreAuthTokenStore,
) -> None:
    """The binding: a value that leaks is useless from anywhere else."""
    token = issue(store, client_ip=CLIENT)

    assert store.is_live(token, client_ip=OTHER_CLIENT, now=START) is False
    assert store.consume(token, client_ip=OTHER_CLIENT, now=START) is False


def test_a_refused_consume_leaves_the_token_live_for_its_own_client(
    store: InMemoryPreAuthTokenStore,
) -> None:
    """Another client's attempt must not be able to destroy the real client's token."""
    token = issue(store, client_ip=CLIENT)

    assert store.consume(token, client_ip=OTHER_CLIENT, now=START) is False
    assert store.is_live(token, client_ip=CLIENT, now=START) is True
    assert store.consume(token, client_ip=CLIENT, now=START) is True


def test_each_client_gets_its_own_token(store: InMemoryPreAuthTokenStore) -> None:
    first = issue(store, client_ip=CLIENT)
    second = issue(store, client_ip=OTHER_CLIENT)

    assert first != second
    assert store.is_live(first, client_ip=CLIENT, now=START) is True
    assert store.is_live(first, client_ip=OTHER_CLIENT, now=START) is False
    assert store.is_live(second, client_ip=OTHER_CLIENT, now=START) is True
    assert store.is_live(second, client_ip=CLIENT, now=START) is False


def test_an_unknown_client_address_still_binds_consistently(
    store: InMemoryPreAuthTokenStore,
) -> None:
    """Two unidentifiable clients share one binding; neither can use the other's token."""
    token = issue(store, client_ip="unknown")

    assert store.is_live(token, client_ip="unknown", now=START) is True
    assert store.is_live(token, client_ip=CLIENT, now=START) is False


def test_a_token_expires(store: InMemoryPreAuthTokenStore) -> None:
    token = issue(store)

    assert store.is_live(token, client_ip=CLIENT, now=START) is True
    assert store.is_live(token, client_ip=CLIENT, now=START + timedelta(minutes=16)) is False


def test_is_live_does_not_consume_so_a_failed_login_can_retry(
    store: InMemoryPreAuthTokenStore,
) -> None:
    token = issue(store)

    assert store.is_live(token, client_ip=CLIENT, now=START) is True
    assert store.is_live(token, client_ip=CLIENT, now=START) is True
    assert store.consume(token, client_ip=CLIENT, now=START) is True


def test_the_store_holds_digests_not_tokens(store: InMemoryPreAuthTokenStore) -> None:
    token = issue(store)

    assert token not in repr(store.__dict__)
    assert store.active_count == 1


def test_the_store_uses_an_injected_clock() -> None:
    moment = [START]
    store = InMemoryPreAuthTokenStore(ttl_seconds=60, clock=lambda: moment[0])

    token = store.issue(client_ip=CLIENT)
    assert store.is_live(token, client_ip=CLIENT) is True

    moment[0] = START + timedelta(seconds=61)
    assert store.is_live(token, client_ip=CLIENT) is False


def test_expired_tokens_are_purged_when_a_new_one_is_issued() -> None:
    store = InMemoryPreAuthTokenStore(ttl_seconds=60)

    store.issue(client_ip=CLIENT, now=START)
    assert store.active_count == 1

    store.issue(client_ip=CLIENT, now=START + timedelta(seconds=61))
    assert store.active_count == 1, "the expired token was dropped, not accumulated"


def test_the_store_is_bounded_and_evicts_the_entry_closest_to_expiry() -> None:
    """Unbounded issuance must not be able to grow memory without limit."""
    store = InMemoryPreAuthTokenStore(ttl_seconds=600, max_tokens=2)

    first = store.issue(client_ip=CLIENT, now=START)
    second = store.issue(client_ip=CLIENT, now=START + timedelta(seconds=1))
    third = store.issue(client_ip=CLIENT, now=START + timedelta(seconds=2))
    later = START + timedelta(seconds=2)

    assert store.active_count == 2
    assert store.is_live(first, client_ip=CLIENT, now=later) is False
    assert store.is_live(second, client_ip=CLIENT, now=later) is True
    assert store.is_live(third, client_ip=CLIENT, now=later) is True


def test_the_store_configuration_is_validated() -> None:
    for kwargs in ({"ttl_seconds": 0}, {"ttl_seconds": True}, {"max_tokens": 0}):
        with pytest.raises(ValueError):
            InMemoryPreAuthTokenStore(**kwargs)  # type: ignore[arg-type]


# --- CSRF over the HTTP surface --------------------------------------------
#
# Authenticated requests are exercised through a real login, because the token that
# matters is the one inside the server-side session record; a test that fabricated it
# would not be testing the wiring.


class _Provider:
    """A provider that always succeeds, so these tests are about CSRF only."""

    name = "ad"

    def __init__(self) -> None:
        self.calls = 0

    def authenticate(self, username: object, password: object):
        self.calls += 1
        from pentaia.webapp.auth.base import AuthOutcome, AuthResult
        from pentaia.webapp.identity import AuthenticatedIdentity

        return AuthResult(
            AuthOutcome.SUCCESS,
            AuthenticatedIdentity.from_provider(
                auth_source="ad", username="user@example.test"
            ),
        )


def _signed_in():
    from fastapi.testclient import TestClient

    from pentaia.webapp import WebAppConfig, create_app
    from pentaia.webapp.auth.csrf import CSRF_HEADER_NAME

    app = create_app(WebAppConfig(auth_provider="ad"), auth_provider=_Provider())
    client = TestClient(
        app, base_url="https://testserver", client=("203.0.113.7", 4321)
    )

    token = client.get("/api/auth/csrf").json()["csrf_token"]
    response = client.post(
        "/api/auth/login",
        json={"username": "user@example.test", "password": "x"},
        headers={CSRF_HEADER_NAME: token},
    )
    assert response.status_code == 200

    return app, client, response


def test_logout_without_the_token_is_refused_and_does_not_end_the_session() -> None:
    """The important half: a refused logout must not be a usable logout."""
    app, client, _ = _signed_in()

    response = client.post("/api/auth/logout")

    assert response.status_code == 403
    assert app.state.session_store.active_count == 1
    assert client.get("/api/me").status_code == 200


@pytest.mark.parametrize(
    "token",
    [None, "", "not-a-token", "a" * (MAX_CSRF_TOKEN_LENGTH + 1), "wrong-but-well-formed"],
)
def test_logout_refuses_every_unusable_token(token) -> None:
    app, client, _ = _signed_in()

    headers = {} if token is None else {CSRF_HEADER_NAME: token}
    response = client.post("/api/auth/logout", headers=headers)

    assert response.status_code == 403
    assert set(response.json()) == {"detail"}
    assert app.state.session_store.active_count == 1


def test_logout_with_the_session_token_succeeds() -> None:
    app, client, _ = _signed_in()
    session_token = client.get("/api/auth/csrf").json()["csrf_token"]

    response = client.post(
        "/api/auth/logout", headers={CSRF_HEADER_NAME: session_token}
    )

    assert response.status_code == 204
    assert app.state.session_store.active_count == 0
    assert client.get("/api/me").status_code == 401


def test_the_token_is_recovered_from_the_bootstrap_after_a_reload() -> None:
    """A reloaded page has no token in memory and must be able to log out again."""
    app, client, _ = _signed_in()

    refreshed = client.get("/api/auth/csrf").json()["csrf_token"]
    response = client.post("/api/auth/logout", headers={CSRF_HEADER_NAME: refreshed})

    assert response.status_code == 204
    assert app.state.session_store.active_count == 0


def test_another_sessions_token_is_refused() -> None:
    """One session's token is worthless against another session."""
    from fastapi.testclient import TestClient

    from pentaia.webapp import WebAppConfig, create_app
    from pentaia.webapp.auth.csrf import CSRF_HEADER_NAME

    app = create_app(WebAppConfig(auth_provider="ad"), auth_provider=_Provider())

    with TestClient(app, base_url="https://testserver", client=("203.0.113.7", 4321)) as first:
        token = first.get("/api/auth/csrf").json()["csrf_token"]
        first.post(
            "/api/auth/login",
            json={"username": "user@example.test", "password": "x"},
            headers={CSRF_HEADER_NAME: token},
        )
        first_token = first.get("/api/auth/csrf").json()["csrf_token"]

    with TestClient(app, base_url="https://testserver", client=("198.51.100.9", 4321)) as second:
        token = second.get("/api/auth/csrf").json()["csrf_token"]
        second.post(
            "/api/auth/login",
            json={"username": "user@example.test", "password": "x"},
            headers={CSRF_HEADER_NAME: token},
        )

        response = second.post(
            "/api/auth/logout", headers={CSRF_HEADER_NAME: first_token}
        )

    assert response.status_code == 403
    assert app.state.session_store.active_count == 2


def test_a_token_in_a_query_parameter_is_not_accepted() -> None:
    """Only the header counts, so a token cannot be leaked through a URL either."""
    app, client, _ = _signed_in()
    session_token = client.get("/api/auth/csrf").json()["csrf_token"]

    response = client.post(f"/api/auth/logout?csrf_token={session_token}")

    assert response.status_code == 403
    assert app.state.session_store.active_count == 1


def test_safe_methods_do_not_require_a_token() -> None:
    _, client, _ = _signed_in()

    assert client.get("/api/me").status_code == 200
    assert client.get("/api/status").status_code == 200
    assert client.get("/api/auth/csrf").status_code == 200


def test_every_state_changing_route_requires_the_token() -> None:
    """A future state-changing route cannot be added without CSRF coverage.

    The sweep reads the advertised schema rather than a hand-written list, and it runs
    authenticated so that authentication cannot be what refuses the request: every
    recorded answer must be a CSRF refusal.
    """
    from fastapi.testclient import TestClient

    from pentaia.webapp import WebAppConfig, create_app

    app = create_app(WebAppConfig(docs_enabled=True), auth_provider=_Provider())

    with TestClient(
        app, base_url="https://testserver", client=("203.0.113.7", 4321)
    ) as client:
        spec = client.get("/openapi.json").json()

        unsafe = sorted(
            (method.upper(), path)
            for path, operations in spec["paths"].items()
            if path.startswith("/api/")
            for method in operations
            if method.upper() not in {"GET", "HEAD", "OPTIONS"}
        )

        assert unsafe, "the sweep must find at least one state-changing route"

        token = client.get("/api/auth/csrf").json()["csrf_token"]
        signed_in = client.post(
            "/api/auth/login",
            json={"username": "user@example.test", "password": "x"},
            headers={CSRF_HEADER_NAME: token},
        )
        assert signed_in.status_code == 200, "the sweep must run authenticated"

        for method, path in unsafe:
            body = (
                {"username": "user@example.test", "password": "x"}
                if path == "/api/auth/login"
                else None
            )

            for headers in ({}, {CSRF_HEADER_NAME: "wrong-but-well-formed"}):
                response = client.request(method, path, headers=headers, json=body)

                assert response.status_code == 403, (method, path, headers)


# --- the pre-authentication token is bound to the client -------------------


def _app(provider=None, **config):
    from pentaia.webapp import WebAppConfig, create_app

    return create_app(WebAppConfig(**config), auth_provider=provider or _Provider())


def _client(app, address: str = "203.0.113.7"):
    from fastapi.testclient import TestClient

    return TestClient(app, base_url="https://testserver", client=(address, 4321))


def test_a_token_issued_to_one_client_is_refused_from_another() -> None:
    """The binding, over HTTP: a token that leaks elsewhere authenticates nothing."""
    provider = _Provider()
    app = _app(provider)

    with _client(app, "203.0.113.7") as first:
        token = first.get("/api/auth/csrf").json()["csrf_token"]

    with _client(app, "198.51.100.9") as second:
        response = second.post(
            "/api/auth/login",
            json={"username": "user@example.test", "password": "x"},
            headers={CSRF_HEADER_NAME: token},
        )

    assert response.status_code == 403
    assert provider.calls == 0, "a refused CSRF check must not reach the provider"
    assert "set-cookie" not in response.headers


def test_a_token_still_works_for_the_client_it_was_issued_to() -> None:
    provider = _Provider()
    app = _app(provider)

    with _client(app, "203.0.113.7") as client:
        token = client.get("/api/auth/csrf").json()["csrf_token"]
        response = client.post(
            "/api/auth/login",
            json={"username": "user@example.test", "password": "x"},
            headers={CSRF_HEADER_NAME: token},
        )

    assert response.status_code == 200
    assert provider.calls == 1


def test_binding_follows_the_forwarded_client_behind_a_trusted_proxy() -> None:
    """The address that counts is the resolved one, not the proxy's own address."""
    provider = _Provider()
    app = _app(provider, trusted_proxies=("127.0.0.1",))

    with _client(app, "127.0.0.1") as proxied:
        issued = proxied.get(
            "/api/auth/csrf", headers={"X-Forwarded-For": "198.51.100.9"}
        ).json()["csrf_token"]

    with _client(app, "127.0.0.1") as same_client:
        refused = same_client.post(
            "/api/auth/login",
            json={"username": "user@example.test", "password": "x"},
            headers={
                CSRF_HEADER_NAME: issued,
                "X-Forwarded-For": "198.51.100.10",
            },
        )

    assert refused.status_code == 403
    assert provider.calls == 0

    with _client(app, "127.0.0.1") as real_client:
        accepted = real_client.post(
            "/api/auth/login",
            json={"username": "user@example.test", "password": "x"},
            headers={
                CSRF_HEADER_NAME: issued,
                "X-Forwarded-For": "198.51.100.9",
            },
        )

    assert accepted.status_code == 200
    assert provider.calls == 1


# --- origin and fetch-metadata enforcement ---------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "https://evil.example"},
        {"Origin": "null"},
        {"Sec-Fetch-Site": "cross-site"},
        {"Sec-Fetch-Site": "CROSS-SITE"},
        {"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
    ],
)
def test_a_cross_site_login_is_refused_even_with_a_valid_token(headers: dict) -> None:
    """Defence in depth: the browser's own statement is honoured as well as the token."""
    provider = _Provider()
    app = _app(provider)

    with _client(app) as client:
        token = client.get("/api/auth/csrf").json()["csrf_token"]
        response = client.post(
            "/api/auth/login",
            json={"username": "user@example.test", "password": "x"},
            headers={CSRF_HEADER_NAME: token, **headers},
        )

    assert response.status_code == 403
    assert set(response.json()) == {"detail"}
    assert provider.calls == 0


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Origin": "https://testserver"},
        {"Sec-Fetch-Site": "same-origin"},
        {"Sec-Fetch-Site": "none"},
        {"Origin": "https://testserver", "Sec-Fetch-Site": "same-origin"},
    ],
)
def test_a_same_origin_login_is_accepted(headers: dict) -> None:
    provider = _Provider()
    app = _app(provider)

    with _client(app) as client:
        token = client.get("/api/auth/csrf").json()["csrf_token"]
        response = client.post(
            "/api/auth/login",
            json={"username": "user@example.test", "password": "x"},
            headers={CSRF_HEADER_NAME: token, **headers},
        )

        client.cookies.clear()

    assert response.status_code == 200, headers
    assert provider.calls == 1


def test_an_origin_on_a_different_port_of_the_same_host_is_accepted() -> None:
    """Only the host is compared: the public port is not knowable behind the proxy."""
    app = _app()

    with _client(app) as client:
        token = client.get("/api/auth/csrf").json()["csrf_token"]
        response = client.post(
            "/api/auth/login",
            json={"username": "user@example.test", "password": "x"},
            headers={CSRF_HEADER_NAME: token, "Origin": "https://testserver:8443"},
        )

    assert response.status_code == 200


def test_a_cross_site_logout_is_refused_and_leaves_the_session_alive() -> None:
    """The session CSRF control gains the same origin check, and still needs the token."""
    app, client, _ = _signed_in()

    response = client.post(
        "/api/auth/logout",
        headers={
            CSRF_HEADER_NAME: client.get("/api/auth/csrf").json()["csrf_token"],
            "Sec-Fetch-Site": "cross-site",
        },
    )

    assert response.status_code == 403
    assert app.state.session_store.active_count == 1


def test_session_csrf_behaviour_is_unchanged_for_a_same_origin_request() -> None:
    """The authenticated mechanism is untouched: token in the header, nothing else."""
    app, client, _ = _signed_in()

    token = client.get("/api/auth/csrf").json()["csrf_token"]
    response = client.post(
        "/api/auth/logout",
        headers={CSRF_HEADER_NAME: token, "Sec-Fetch-Site": "same-origin"},
    )

    assert response.status_code == 204
    assert app.state.session_store.active_count == 0


# --- full-origin verification against the declared public origin ------------
#
# With PENTAIA_PUBLIC_ORIGIN set, the browser's Origin must equal it exactly, scheme and
# port included. Nothing is inferred from Host and nothing is read from a forwarded
# header, so a client cannot influence the comparison.


def _attempt(client, token: str, headers: dict):
    return client.post(
        "/api/auth/login",
        json={"username": "user@example.test", "password": "x"},
        headers={CSRF_HEADER_NAME: token, **headers},
    )


@pytest.mark.parametrize(
    "origin",
    [
        "https://testserver",
        "https://testserver/",
        "https://testserver:443",
        "HTTPS://TESTSERVER",
    ],
)
def test_an_origin_matching_the_declared_public_origin_is_accepted(origin: str) -> None:
    provider = _Provider()
    app = _app(public_origin="https://testserver", provider=provider)

    with _client(app) as client:
        token = client.get("/api/auth/csrf").json()["csrf_token"]
        response = _attempt(client, token, {"Origin": origin})

    assert response.status_code == 200, origin
    assert provider.calls == 1


@pytest.mark.parametrize(
    "origin",
    [
        "http://testserver",  # wrong scheme: this is the case Host-only comparison missed
        "https://testserver:8443",  # wrong port
        "https://testserver:80",
        "https://evil.example",
        "https://testserver.evil.example",
        "null",
    ],
)
def test_an_origin_differing_from_the_declared_public_origin_is_refused(
    origin: str,
) -> None:
    provider = _Provider()
    app = _app(public_origin="https://testserver", provider=provider)

    with _client(app) as client:
        token = client.get("/api/auth/csrf").json()["csrf_token"]
        response = _attempt(client, token, {"Origin": origin})

    assert response.status_code == 403, origin
    assert provider.calls == 0


def test_a_forwarded_host_header_cannot_influence_the_comparison() -> None:
    """The declared origin is the only authority; forwarded headers are ignored."""
    provider = _Provider()
    app = _app(public_origin="https://testserver", provider=provider)

    with _client(app) as client:
        token = client.get("/api/auth/csrf").json()["csrf_token"]
        forged = _attempt(
            client,
            token,
            {"Origin": "https://evil.example", "X-Forwarded-Host": "evil.example"},
        )

    assert forged.status_code == 403
    assert provider.calls == 0


@pytest.mark.parametrize("origin", ["https://testserver", "https://testserver:443"])
def test_an_unrequested_forwarded_host_does_not_break_a_correct_origin(
    origin: str,
) -> None:
    provider = _Provider()
    app = _app(public_origin="https://testserver", provider=provider)

    with _client(app) as client:
        token = client.get("/api/auth/csrf").json()["csrf_token"]
        response = _attempt(
            client,
            token,
            {"Origin": origin, "X-Forwarded-Host": "evil.example"},
        )

    assert response.status_code == 200
    assert provider.calls == 1


def test_without_a_declared_origin_the_host_fallback_still_refuses_another_host() -> None:
    """The weaker mode is weaker, not absent: a different host is still refused."""
    provider = _Provider()
    app = _app(provider=provider)

    with _client(app) as client:
        token = client.get("/api/auth/csrf").json()["csrf_token"]
        refused = _attempt(client, token, {"Origin": "https://evil.example"})

    assert refused.status_code == 403
    assert provider.calls == 0


def test_a_declared_origin_still_requires_the_token() -> None:
    """Full-origin verification is defence in depth, never a replacement for the token."""
    provider = _Provider()
    app = _app(public_origin="https://testserver", provider=provider)

    with _client(app) as client:
        response = _attempt(client, "", {"Origin": "https://testserver"})

    assert response.status_code == 403
    assert provider.calls == 0


def test_a_cross_site_fetch_metadata_header_is_refused_in_strict_mode() -> None:
    provider = _Provider()
    app = _app(public_origin="https://testserver", provider=provider)

    with _client(app) as client:
        token = client.get("/api/auth/csrf").json()["csrf_token"]
        response = _attempt(
            client,
            token,
            {"Origin": "https://testserver", "Sec-Fetch-Site": "cross-site"},
        )

    assert response.status_code == 403
    assert provider.calls == 0
