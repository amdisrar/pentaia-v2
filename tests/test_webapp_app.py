"""Phase 4 web application foundation: factory, lifecycle, and the HTTP surface.

These tests deliberately assert on behaviour through the test client rather than on
``app.routes`` internals, which differ between FastAPI versions.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pentaia.webapp.app import create_app
from pentaia.webapp.config import PORT_ENV, WebAppConfig

# Tokens that must never appear in an unauthenticated response body.
FORBIDDEN_IN_RESPONSE = (
    "kali",
    "172.16",
    "gemini",
    "google",
    "api_key",
    "apikey",
    "password",
    "secret",
    "ssh",
    "allowlist",
    "lhost",
    "lport",
)


@pytest.fixture()
def client() -> TestClient:
    app = create_app(WebAppConfig())

    with TestClient(app) as test_client:
        yield test_client


def test_create_app_returns_a_fastapi_application() -> None:
    assert isinstance(create_app(WebAppConfig()), FastAPI)


def test_application_state_carries_the_resolved_configuration() -> None:
    config = WebAppConfig(host="127.0.0.1", port=9999)

    app = create_app(config)

    assert app.state.config is config


def test_create_app_loads_configuration_when_none_is_supplied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(PORT_ENV, "8123")

    assert create_app().state.config.port == 8123


def test_create_app_without_configuration_ignores_ambient_store_and_provider() -> None:
    """The suite must never reach the resources a developer configured in their ``.env``.

    ``create_app()`` with no arguments loads the environment, so this asserts that the
    autouse isolation fixture has pinned the store to memory, blanked the data directory,
    and blanked the authentication provider. Without that fixture this fails whenever
    ``.env`` selects ``PENTAIA_STORE_MODE=sqlite`` — the application would load that
    configuration, open the database and migrate it — and it fails *hard* wherever the
    configured directory is not writable.

    The last assertion is the one that matters for the provider: ``create_app()`` builds a
    provider during construction, so if the ambient setting survived, a real AD provider
    would exist here and would reach the directory on the first authentication attempt.
    Nothing in this test reads the developer's configured values: the point is that they
    cannot be reached.
    """
    from pentaia.webapp.config import load_webapp_config

    config = load_webapp_config()

    assert config.store.mode == "memory"
    assert config.store.data_dir is None
    assert config.store.durable is False
    assert config.store.database_path is None
    assert config.auth_provider is None

    app = create_app()

    assert app.state.config.store.durable is False
    assert app.state.app_store is None, "no database handle may be opened"
    assert app.state.auth_provider is None, "no ambient provider may be constructed"


def test_a_test_may_still_choose_its_own_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fixture pins the ambient default; a test can override it deliberately.

    This is the other half of the isolation contract: the fixture must not make it
    impossible to exercise environment-driven behaviour, only to inherit it by accident.
    Construction does not contact the directory — the bind happens on the first
    authentication attempt — so this stays offline.
    """
    from pentaia.webapp.auth.ad import HOST_ENV as AD_HOST_ENV
    from pentaia.webapp.config import AUTH_PROVIDER_ENV

    monkeypatch.setenv(AUTH_PROVIDER_ENV, "ad")
    monkeypatch.setenv(AD_HOST_ENV, "dc.invalid.test")

    app = create_app()

    assert app.state.config.auth_provider == "ad"
    assert app.state.auth_provider is not None
    assert app.state.auth_provider.name == "ad"
    assert app.state.app_store is None


def test_lifespan_logs_startup_and_shutdown(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = create_app(WebAppConfig())

    with caplog.at_level("INFO", logger="pentaia.webapp.app"), TestClient(app):
        pass

    messages = [record.getMessage() for record in caplog.records]

    assert any("starting" in message for message in messages)
    assert any("stopped" in message for message in messages)
    assert any("port=8000" in message for message in messages)


def test_the_application_serves_requests_inside_the_lifespan(client: TestClient) -> None:
    assert client.get("/healthz").status_code == 200


def test_healthz_reports_liveness_only(client: TestClient) -> None:
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["content-type"].startswith("application/json")


def test_healthz_exposes_no_sensitive_information(client: TestClient) -> None:
    response = client.get("/healthz")

    assert set(response.json()) == {"status"}

    body = response.text.lower()
    assert not [token for token in FORBIDDEN_IN_RESPONSE if token in body]


def test_the_browser_api_surface_is_exactly_the_reviewed_set() -> None:
    """No execution-shaped route may appear on the browser surface.

    Reading the OpenAPI document is version-tolerant and fails loudly if a later change
    registers a route that was not reviewed. P4-02 asserted the two routes it created;
    P4-04 added the authenticated identity and logout routes and P4-08 adds login and
    CSRF token bootstrapping, so the expected set is updated rather than the assertion
    removed.
    """
    app = create_app(WebAppConfig(docs_enabled=True))

    with TestClient(app) as client:
        spec = client.get("/openapi.json").json()

    assert set(spec["paths"]) == {
        "/healthz",
        "/api/status",
        "/api/me",
        "/api/auth/logout",
        "/api/auth/login",
        "/api/auth/csrf",
    }

    for path, operations in spec["paths"].items():
        assert set(operations) <= {"get", "post"}, path

        # No route may accept a client-supplied value in its path or query string. That
        # rules out a target, an action id, tool arguments, a conversation id or an
        # approval reference arriving from the browser.
        for operation in operations.values():
            assert operation.get("parameters", []) == []

        # Exactly one route may accept a body, and the next test pins what it contains.
        for method, operation in operations.items():
            if (method, path) == ("post", "/api/auth/login"):
                continue

            assert "requestBody" not in operation, (method, path)


def test_the_only_request_body_is_the_credential_body() -> None:
    """Login accepts credentials and nothing else: no provider, role, target or flag."""
    app = create_app(WebAppConfig(docs_enabled=True))

    with TestClient(app) as client:
        spec = client.get("/openapi.json").json()

    body = spec["paths"]["/api/auth/login"]["post"]["requestBody"]
    reference = body["content"]["application/json"]["schema"]["$ref"]
    schema = spec["components"]["schemas"][reference.rsplit("/", 1)[-1]]

    assert set(schema["properties"]) == {"username", "password"}
    assert set(schema["required"]) == {"username", "password"}
    assert {field["type"] for field in schema["properties"].values()} == {"string"}

    # No other route in the document accepts a body, so nothing else can be steered.
    assert "requestBody" not in spec["paths"]["/api/auth/logout"]["post"]
    assert "requestBody" not in spec["paths"]["/api/auth/csrf"]["get"]


def test_status_is_registered_but_fails_closed(client: TestClient) -> None:
    """P4-02 ships no authentication, so the authenticated surface stays shut."""
    response = client.get("/api/status")

    assert response.status_code == 401
    assert set(response.json()) == {"detail"}


def test_the_refusal_leaks_nothing(client: TestClient) -> None:
    response = client.get("/api/status")

    body = response.text.lower()
    assert not [token for token in FORBIDDEN_IN_RESPONSE if token in body]


def test_the_safe_status_payload_is_typed_and_secret_free() -> None:
    from pentaia.webapp.api.status import build_status_payload

    payload = build_status_payload()

    assert payload.application == "pentaia"
    assert payload.authentication_provider is None
    assert payload.authentication_ready is False
    assert payload.accounting == "disabled"
    # Pinning the field set is the point: a secret-bearing field cannot be added
    # without this test failing and the addition being reviewed deliberately. P4-07
    # added the two authentication fields and P4-09 the accounting state, so the set is
    # updated rather than the assertion removed.
    assert set(payload.model_dump()) == {
        "application",
        "authentication_provider",
        "authentication_ready",
        "accounting",
    }


def test_interactive_documentation_is_disabled_by_default(client: TestClient) -> None:
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404, path


def test_interactive_documentation_can_be_enabled_explicitly() -> None:
    app = create_app(WebAppConfig(docs_enabled=True))

    with TestClient(app) as client:
        assert client.get("/openapi.json").status_code == 200
        assert client.get("/docs").status_code == 200


def test_unknown_routes_are_not_found(client: TestClient) -> None:
    # P4-02 originally asserted that "/" was 404. P4-03 deliberately serves the GUI
    # shell there, so "/" is no longer an unknown path and a genuinely unknown path is
    # used instead. The GUI route is asserted in tests/test_webapp_gui.py.
    assert client.get("/api/does-not-exist").status_code == 404
    assert client.get("/console").status_code == 404


def test_the_module_entry_point_is_importable_and_runnable() -> None:
    """``python -m pentaia.webapp`` must exist, without binding a port in tests."""
    from pentaia.webapp import __main__ as webapp_main

    assert callable(webapp_main.main)


def test_the_startup_log_records_the_origin_verification_mode(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The operator must be able to see whether full-origin checking is active."""

    def start(config: WebAppConfig) -> str:
        caplog.clear()

        with (
            caplog.at_level("INFO", logger="pentaia.webapp.app"),
            TestClient(create_app(config)),
        ):
            pass

        return "\n".join(record.getMessage() for record in caplog.records)

    assert "public_origin=unset" in start(WebAppConfig())
    assert "public_origin=https://testserver:443" in start(
        WebAppConfig(public_origin="https://testserver")
    )
