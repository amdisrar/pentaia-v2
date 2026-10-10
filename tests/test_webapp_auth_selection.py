"""P4-07 configurable authentication provider selection.

The properties asserted here are behavioural. A provider is either built or the
application refuses to start, and a provider that fails is never quietly replaced by
another mechanism. The name-level assertions (which providers exist, which are
implemented) are the weaker half of each test and are kept next to the behaviour they
explain.

No test opens a socket or reaches a directory: the AD transport is either replaced
through ``build_ad_provider`` or left unexercised, because selecting a provider must
not itself contact anything.
"""

import pytest
from fastapi.testclient import TestClient

from pentaia.webapp import WebAppConfig, create_app
from pentaia.webapp.api import status as status_module
from pentaia.webapp.auth import selection
from pentaia.webapp.auth.ad import CA_FILE_ENV as AD_CA_FILE_ENV
from pentaia.webapp.auth.ad import HOST_ENV as AD_HOST_ENV
from pentaia.webapp.auth.ad import PORT_ENV as AD_PORT_ENV
from pentaia.webapp.auth.ad import ADConfig
from pentaia.webapp.auth.base import (
    AuthOutcome,
    AuthProvider,
    AuthResult,
    ProviderMisconfigured,
    ProviderUnavailable,
)
from pentaia.webapp.auth.csrf import CSRF_HEADER_NAME
from pentaia.webapp.config import (
    AUTH_PROVIDER_ENV,
    SUPPORTED_AUTH_PROVIDERS,
    load_webapp_config,
    validate_auth_provider,
)
from pentaia.webapp.identity import AUTH_SOURCE_AD, AuthenticatedIdentity
from pentaia.webapp.sessions import SESSION_COOKIE_NAME

#: Values distinctive enough that finding one in a response body is unambiguous.
SECRET_HOST = "ldaps-internal-secret.pentaia.test"
SECRET_CA_NAME = "pentaia-internal-ca-secret.pem"


class FakeProvider:
    """A provider that satisfies the contract without any transport."""

    def __init__(self, name: str = AUTH_SOURCE_AD) -> None:
        self.name = name
        self.attempts: list[tuple[object, object]] = []

    def authenticate(self, username: object, password: object) -> AuthResult:
        self.attempts.append((username, password))

        return AuthResult(AuthOutcome.REJECTED)


def identity(username: str = "user@example.com") -> AuthenticatedIdentity:
    return AuthenticatedIdentity.from_provider(
        auth_source=AUTH_SOURCE_AD,
        username=username,
        display_name="Example User",
    )


def sign_in(app, client: TestClient, username: str = "user@example.com") -> None:
    """Authenticate a client through the session seam, not through a login route.

    P4-08 owns the login route. Until it exists, this is the only way to reach the
    authenticated surface, and it is deliberately not reachable from the browser.
    """
    issued = app.state.session_store.create(identity(username))
    client.cookies.set(SESSION_COOKIE_NAME, issued.session_id)


def test_the_fake_provider_satisfies_the_contract() -> None:
    """Guard the guard: the stand-in must be a real ``AuthProvider``."""
    assert isinstance(FakeProvider(), AuthProvider)


# --- configuration: what a deployment is allowed to say --------------------


def test_no_provider_is_selected_by_default() -> None:
    """An unconfigured deployment selects nothing; it does not select a default."""
    assert load_webapp_config({}).auth_provider is None


@pytest.mark.parametrize("value", ["", "   ", "\t"])
def test_a_blank_provider_means_no_provider(value: str) -> None:
    """A blank setting is unset, so an empty ``.env`` entry cannot mean "anyone"."""
    assert load_webapp_config({AUTH_PROVIDER_ENV: value}).auth_provider is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [("ad", "ad"), ("AD", "ad"), ("  Ad  ", "ad"), ("radius", "radius")],
)
def test_the_selected_provider_is_normalized(value: str, expected: str) -> None:
    assert load_webapp_config({AUTH_PROVIDER_ENV: value}).auth_provider == expected


@pytest.mark.parametrize(
    "value",
    ["ldap", "radius2", "ad,radius", "none", "true", "0", "ad radius", "ad;radius"],
)
def test_an_unknown_provider_fails_configuration_validation(value: str) -> None:
    """An unrecognised name is a startup error, not something to ignore."""
    with pytest.raises(ValueError) as caught:
        load_webapp_config({AUTH_PROVIDER_ENV: value})

    assert AUTH_PROVIDER_ENV in str(caught.value)


@pytest.mark.parametrize("value", [1, 0, [], {}, True, object()])
def test_a_non_string_provider_fails_configuration_validation(value: object) -> None:
    with pytest.raises(ValueError):
        validate_auth_provider(value)


def test_radius_keeps_its_place_in_the_configuration_contract() -> None:
    """Deferring P4-06 must not remove RADIUS from the architecture's contract."""
    assert set(SUPPORTED_AUTH_PROVIDERS) == {AUTH_SOURCE_AD, "radius"}
    assert selection.IMPLEMENTED_AUTH_PROVIDERS == (AUTH_SOURCE_AD,)


# --- selection: how a name becomes a provider ------------------------------


def test_the_ad_provider_is_built_from_the_ad_configuration_loader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One configuration path: selection does not invent its own AD settings."""
    seen: list[object] = []
    provider = FakeProvider()

    def record(config: ADConfig) -> AuthProvider:
        seen.append(config)

        return provider

    monkeypatch.setattr(selection, "build_ad_provider", record)

    built = selection.build_auth_provider(
        "ad", environ={AD_HOST_ENV: "dc.pentaia.test", AD_PORT_ENV: "1636"}
    )

    assert built is provider
    assert len(seen) == 1
    assert isinstance(seen[0], ADConfig)
    assert seen[0].host == "dc.pentaia.test"
    assert seen[0].port == 1636


def test_selection_reads_the_environment_it_is_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[ADConfig] = []

    monkeypatch.setenv(AD_HOST_ENV, "ambient.invalid")
    monkeypatch.setattr(
        selection, "build_ad_provider", lambda config: seen.append(config) or FakeProvider()
    )

    selection.build_auth_provider("ad", environ={AD_HOST_ENV: "dc.pentaia.test"})

    assert [config.host for config in seen] == ["dc.pentaia.test"]


def test_radius_fails_closed_and_points_at_its_issue() -> None:
    """A supported-but-unimplemented provider stops the application, with a reason."""
    with pytest.raises(ProviderMisconfigured) as caught:
        selection.build_auth_provider("radius")

    message = str(caught.value)

    assert "radius" in message
    assert "#56" in message, "the operator must be told which issue owns RADIUS"
    assert AUTH_SOURCE_AD in message, "the message must say what is available instead"
    assert "fallback" in message, "the message must state that nothing was substituted"


@pytest.mark.parametrize("value", ["ldap", "", "   ", "none"])
def test_a_provider_that_is_not_configured_cannot_be_built(value: str) -> None:
    with pytest.raises(ValueError):
        selection.build_auth_provider(value)


def test_no_provider_cannot_be_built() -> None:
    with pytest.raises(ValueError):
        selection.build_auth_provider(None)  # type: ignore[arg-type]


def test_a_provider_that_cannot_be_built_is_never_replaced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The failure reaches the caller unchanged; nothing else is tried."""
    failure = ProviderUnavailable("the directory could not be reached")
    calls: list[object] = []

    def fail(config: ADConfig) -> AuthProvider:
        calls.append(config)

        raise failure

    monkeypatch.setattr(selection, "build_ad_provider", fail)

    with pytest.raises(ProviderUnavailable) as caught:
        selection.build_auth_provider("ad", environ={AD_HOST_ENV: "dc.pentaia.test"})

    assert caught.value is failure
    assert len(calls) == 1


def test_selection_never_authenticates(monkeypatch: pytest.MonkeyPatch) -> None:
    """Selecting a provider is not an authentication attempt."""
    provider = FakeProvider()

    monkeypatch.setattr(selection, "build_ad_provider", lambda config: provider)

    selection.build_auth_provider("ad", environ={AD_HOST_ENV: "dc.pentaia.test"})

    assert provider.attempts == []


# --- application wiring: selection happens before anything is served -------


def test_a_configured_provider_is_built_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = FakeProvider()
    calls: list[object] = []

    def build(name: str):
        calls.append(name)

        return provider

    monkeypatch.setattr("pentaia.webapp.app.build_auth_provider", build)

    app = create_app(WebAppConfig(auth_provider="ad"))

    assert calls == ["ad"]
    assert app.state.auth_provider is provider


def test_an_injected_provider_is_used_without_building_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A supplied provider is authoritative, and nothing is constructed behind it."""
    provider = FakeProvider()
    built: list[object] = []

    def build(name: str):
        built.append(name)

        raise AssertionError("no provider may be built when one is injected")

    monkeypatch.setattr("pentaia.webapp.app.build_auth_provider", build)

    app = create_app(WebAppConfig(auth_provider="ad"), auth_provider=provider)

    assert app.state.auth_provider is provider
    assert built == []


def test_no_provider_is_built_when_none_is_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built: list[object] = []

    def build(name: str):
        built.append(name)

        raise AssertionError("no provider may be built when none is configured")

    monkeypatch.setattr("pentaia.webapp.app.build_auth_provider", build)

    app = create_app(WebAppConfig())

    assert app.state.auth_provider is None
    assert built == []


def test_an_unbuildable_selection_stops_the_application() -> None:
    """A deployment that cannot honour its own configuration never starts."""
    with pytest.raises(ProviderMisconfigured) as caught:
        create_app(WebAppConfig(auth_provider="radius"))

    assert "#56" in str(caught.value)


def test_a_failing_ad_provider_stops_the_application(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real selection path is used; only the AD transport is replaced."""

    def fail(config: ADConfig) -> AuthProvider:
        raise ProviderMisconfigured("bad CA bundle")

    monkeypatch.setenv(AD_HOST_ENV, "dc.pentaia.test")
    monkeypatch.setattr(selection, "build_ad_provider", fail)

    with pytest.raises(ProviderMisconfigured):
        create_app(WebAppConfig(auth_provider="ad"))


# --- the HTTP surface: health, readiness and the protected surface ---------


def test_health_is_liveness_only_while_authentication_is_separate() -> None:
    """Health and the ability to authenticate are different questions."""
    app = create_app(WebAppConfig())

    with TestClient(app) as client:
        assert client.get("/healthz").status_code == 200
        assert client.get("/healthz").json() == {"status": "ok"}
        # Not ready to authenticate anyone, and that is visible as a refusal rather
        # than as an anonymous status page.
        assert client.get("/api/status").status_code == 401
        assert client.get("/api/me").status_code == 401


def test_an_unconfigured_deployment_reports_no_provider() -> None:
    app = create_app(WebAppConfig())

    with TestClient(app) as client:
        sign_in(app, client)

        response = client.get("/api/status")

    assert response.status_code == 200
    assert response.json()["authentication_provider"] is None
    assert response.json()["authentication_ready"] is False


def test_a_configured_deployment_reports_the_active_provider() -> None:
    provider = FakeProvider()
    app = create_app(WebAppConfig(auth_provider="ad"), auth_provider=provider)

    with TestClient(app) as client:
        sign_in(app, client)

        response = client.get("/api/status")

    assert response.status_code == 200
    assert response.json()["authentication_provider"] == AUTH_SOURCE_AD
    assert response.json()["authentication_ready"] is True


def test_the_status_payload_names_the_provider_object_that_is_active() -> None:
    provider = FakeProvider(name="radius")

    payload = status_module.build_status_payload(provider)

    assert payload.authentication_provider == "radius"
    assert payload.authentication_ready is True
    assert status_module.build_status_payload(None).authentication_ready is False


def test_no_provider_mode_cannot_reach_the_protected_surface() -> None:
    """The absence of a provider is never a way in."""
    app = create_app(WebAppConfig(docs_enabled=True))

    with TestClient(app) as client:
        # Login exists from P4-08, and in a deployment with no provider it authenticates
        # nobody: the same failure a caller would get from a provider it cannot reach,
        # and never a session.
        token = client.get("/api/auth/csrf").json()["csrf_token"]
        refused = client.post(
            "/api/auth/login",
            json={"username": "admin@example.test", "password": "whatever"},
            headers={CSRF_HEADER_NAME: token},
        )

        assert refused.status_code == 503
        assert SESSION_COOKIE_NAME not in refused.headers.get("set-cookie", "")

        # A forged session cookie is a bearer credential the store has never seen.
        client.cookies.set(SESSION_COOKIE_NAME, "sess-forged")

        for path in ("/api/status", "/api/me"):
            assert client.get(path).status_code == 401

        client.cookies.clear()

        attempts = [
            {"headers": {"Authorization": "Bearer forged"}},
            {"headers": {"X-User-ID": "ad:attacker@example.com"}},
            {"params": {"user_id": "ad:attacker@example.com", "username": "attacker"}},
        ]

        for attempt in attempts:
            for path in ("/api/status", "/api/me"):
                response = client.get(path, **attempt)

                assert response.status_code == 401, (path, attempt)
                assert set(response.json()) == {"detail"}


def test_a_configured_provider_still_refuses_unauthenticated_callers() -> None:
    """A configured provider changes nothing about the unauthenticated surface."""
    app = create_app(WebAppConfig(auth_provider="ad"), auth_provider=FakeProvider())

    with TestClient(app) as client:
        assert client.get("/api/status").status_code == 401
        assert client.get("/api/me").status_code == 401
        assert client.post("/api/auth/logout").status_code == 401


def test_provider_configuration_never_reaches_a_browser_response(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """Secrets in provider configuration stay server-side, on every surface."""
    ca_file = tmp_path / SECRET_CA_NAME
    ca_file.write_bytes(b"placeholder")
    monkeypatch.setenv(AD_HOST_ENV, SECRET_HOST)
    monkeypatch.setenv(AD_CA_FILE_ENV, str(ca_file))

    # The real AD provider is constructed here; construction opens no connection.
    app = create_app(WebAppConfig(docs_enabled=True, auth_provider="ad"))

    assert app.state.auth_provider.name == AUTH_SOURCE_AD

    with TestClient(app) as client:
        bodies = {
            "/healthz": client.get("/healthz"),
            "/api/status (unauthenticated)": client.get("/api/status"),
            "/openapi.json": client.get("/openapi.json"),
        }

        sign_in(app, client)
        bodies["/api/status (authenticated)"] = client.get("/api/status")

    for label, response in bodies.items():
        assert SECRET_HOST not in response.text, label
        assert SECRET_CA_NAME not in response.text, label

    assert bodies["/api/status (authenticated)"].json()["authentication_provider"] == (
        AUTH_SOURCE_AD
    )
