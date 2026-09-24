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
    P4-04 deliberately adds the authenticated identity and logout routes, so the
    expected set is updated rather than the assertion removed.
    """
    app = create_app(WebAppConfig(docs_enabled=True))

    with TestClient(app) as client:
        spec = client.get("/openapi.json").json()

    assert set(spec["paths"]) == {
        "/healthz",
        "/api/status",
        "/api/me",
        "/api/auth/logout",
    }

    for path, operations in spec["paths"].items():
        assert set(operations) <= {"get", "post"}, path

        for operation in operations.values():
            # No route may accept any client-supplied value at this stage. Login, which
            # will accept credentials, belongs to P4-05/P4-06.
            assert operation.get("parameters", []) == []
            assert "requestBody" not in operation


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
    # Pinning the field set is the point: a secret-bearing field cannot be added
    # without this test failing and the addition being reviewed deliberately.
    assert set(payload.model_dump()) == {"application", "authentication_provider"}


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
