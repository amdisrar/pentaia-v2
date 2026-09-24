"""P4-03 GUI shell: routing, static assets, safety of the served content.

The shell is static files served verbatim, so several of these tests compare served
bytes with on-disk bytes. That is the strongest available statement that no backend
configuration is injected into the browser: the server adds nothing to the document.
"""

import re

import pytest
from fastapi.testclient import TestClient

from pentaia.webapp import WebAppConfig, create_app
from pentaia.webapp.gui import INDEX_FILE, STATIC_DIRECTORY, static_files

# Backend identifiers and configuration names that must never reach the browser.
FORBIDDEN_IDENTIFIERS = (
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "KALI_HOST",
    "KALI_USERNAME",
    "KALI_SSH_KEY",
    "PENTAIA_",
    "allowlist",
    "denylist",
    "172.16",
    "127.0.0.1",
)

# Endpoints the browser shell is allowed to call. Later issues extend this set
# deliberately; conversation and approval endpoints arrive in P4-11 and P4-12.
ALLOWED_BROWSER_ENDPOINTS = {"/healthz", "/api/status"}

SHELL_ELEMENT_IDS = (
    # login state
    "login-view",
    "login-notice",
    "preview-shell",
    # shell chrome
    "app-view",
    "app-header",
    "app-nav",
    "session-area",
    "session-identity",
    "logout-button",
    "main",
    # conversation workspace
    "conversation-sidebar",
    "conversation-list",
    "conversation-view",
    "conversation-title",
    "message-list",
    "message-form",
    "message-input",
    "send-button",
    "turn-status",
    "durability-warning",
    # approval placeholder
    "approval-panel",
    "approval-target",
    "approval-action",
    "approval-rationale",
    "approval-expected-effect",
    "approval-parameters",
    "approval-approve",
    "approval-reject",
    # accounting and status
    "accounting-view",
    "accounting-table",
    "status-view",
    "status-healthz",
    "status-api",
    "refresh-status",
)


@pytest.fixture()
def client() -> TestClient:
    with TestClient(create_app(WebAppConfig())) as test_client:
        yield test_client


def html(client: TestClient) -> str:
    response = client.get("/")
    assert response.status_code == 200

    return response.text


# --- routing ---------------------------------------------------------------


def test_the_root_route_serves_the_gui_document(client: TestClient) -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "<!DOCTYPE html>" in response.text


def test_the_served_document_is_the_file_on_disk_unchanged(client: TestClient) -> None:
    """No templating and no injected configuration, proven by byte equality."""
    assert html(client) == INDEX_FILE.read_text(encoding="utf-8")


def test_the_shell_assets_are_served(client: TestClient) -> None:
    for path in ("/static/css/app.css", "/static/js/app.js"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert response.text.strip(), path

def test_hidden_attribute_always_hides_elements() -> None:
    """CSS must not override the native hidden attribute used by GUI state changes."""
    css = (STATIC_DIRECTORY / "css" / "app.css").read_text(encoding="utf-8")
    compact = re.sub(r"\s+", "", css)

    assert "[hidden]{display:none!important;}" in compact

@pytest.mark.parametrize("path", sorted(str(p) for p in static_files()))
def test_every_shipped_asset_is_reachable(path: str) -> None:
    relative = path.split("static/", 1)[1]

    with TestClient(create_app(WebAppConfig())) as client:
        assert client.get(f"/static/{relative}").status_code == 200


def test_the_gui_route_is_not_part_of_the_json_api_schema() -> None:
    """The document is not an API route and must not appear in the schema.

    Only the GUI concern is asserted here. The exact browser API surface is pinned in
    tests/test_webapp_app.py and tests/test_webapp_auth.py, so that adding an API route
    does not require editing this file.
    """
    with TestClient(create_app(WebAppConfig(docs_enabled=True))) as client:
        paths = client.get("/openapi.json").json()["paths"]

    assert "/" not in paths
    assert not [path for path in paths if path.startswith("/static")]
    assert all(path == "/healthz" or path.startswith("/api") for path in paths)


def test_unknown_browser_paths_are_not_found(client: TestClient) -> None:
    """There is no catch-all, so nothing can shadow /api or /healthz."""
    for path in ("/console", "/app", "/index.html", "/static/", "/static/nope.css"):
        assert client.get(path).status_code == 404, path


def test_the_static_mount_does_not_list_directories(client: TestClient) -> None:
    response = client.get("/static/")

    assert response.status_code == 404
    assert "app.css" not in response.text
    assert "app.js" not in response.text


# --- nothing sensitive or executable is exposed ----------------------------


@pytest.mark.parametrize(
    "path", ["/", "/static/css/app.css", "/static/js/app.js"]
)
def test_no_backend_identifier_reaches_the_browser(client: TestClient, path: str) -> None:
    body = client.get(path).text

    offenders = [token for token in FORBIDDEN_IDENTIFIERS if token in body]

    assert not offenders, f"{path} exposes {offenders}"


@pytest.mark.parametrize(
    "path", ["/", "/static/css/app.css", "/static/js/app.js"]
)
def test_the_shell_makes_no_external_request(client: TestClient, path: str) -> None:
    """Same-origin only: no CDN, no external font, no third-party script."""
    body = client.get(path).text

    assert "http://" not in body
    assert "https://" not in body
    assert "//cdn" not in body


def test_the_shell_contains_no_stack_trace_or_python_source(client: TestClient) -> None:
    for path in ("/", "/static/css/app.css", "/static/js/app.js"):
        body = client.get(path).text
        assert "Traceback" not in body, path
        assert "def create_app" not in body, path
        assert "import fastapi" not in body, path


def test_the_browser_only_calls_the_two_safe_status_endpoints(client: TestClient) -> None:
    script = client.get("/static/js/app.js").text

    referenced = {
        match.strip('"') for match in re.findall(r'"/[A-Za-z0-9._\-/]*"', script)
    }

    assert referenced == ALLOWED_BROWSER_ENDPOINTS


@pytest.mark.parametrize(
    "path",
    [
        "/execute",
        "/api/execute",
        "/api/run",
        "/api/tools",
        "/api/nmap",
        "/api/nuclei",
        "/api/metasploit",
        "/api/kali",
    ],
)
def test_no_direct_execution_route_exists(client: TestClient, path: str) -> None:
    """The web layer must not offer a second path to Kali."""
    assert client.get(path).status_code == 404, path
    assert client.post(path, json={}).status_code == 404, path


@pytest.mark.parametrize(
    "path",
    [
        "/pyproject.toml",
        "/README.md",
        "/.env",
        "/app.py",
        "/config.py",
        "/src/pentaia/webapp/app.py",
        "/tests/test_webapp_app.py",
        "/logs/pentaia.log",
        "/static/../app.py",
        "/static/%2e%2e/app.py",
        "/static/../../pyproject.toml",
        "/static/..%2f..%2f.env",
    ],
)
def test_repository_files_are_never_served(client: TestClient, path: str) -> None:
    response = client.get(path)

    assert response.status_code == 404, path
    assert "[project]" not in response.text
    assert "import fastapi" not in response.text
    assert "GOOGLE_API_KEY" not in response.text


# --- shell structure -------------------------------------------------------


@pytest.mark.parametrize("element_id", SHELL_ELEMENT_IDS)
def test_the_shell_contains_the_expected_structure(
    client: TestClient, element_id: str
) -> None:
    assert f'id="{element_id}"' in html(client), element_id


def test_the_shell_exposes_the_required_navigation(client: TestClient) -> None:
    body = html(client)

    for target in ("conversations", "accounting", "status"):
        assert f'data-nav="{target}"' in body, target


def test_the_login_state_offers_no_credential_entry(client: TestClient) -> None:
    """No fake authentication: there is no password field in this build."""
    body = html(client).lower()

    assert 'type="password"' not in body
    assert "<form" in body  # the message composer exists
    assert 'name="username"' not in body
    assert "autocomplete=\"current-password\"" not in body


def test_the_shell_states_that_conversations_are_not_durable(client: TestClient) -> None:
    body = html(client).lower()

    assert "not stored across a restart" in body
    assert "phase 5" in body


def test_the_approval_controls_are_disabled_in_this_build(client: TestClient) -> None:
    """P4-03 reserves the panel; it must not be able to approve anything."""
    body = html(client)

    for control in ("approval-approve", "approval-reject"):
        element = re.search(rf'<button[^>]*id="{control}"[^>]*>', body)
        assert element is not None, control
        assert "disabled" in element.group(0), control


def test_the_shell_uses_no_inline_script_or_style(client: TestClient) -> None:
    """Keeps a strict Content-Security-Policy a drop-in later."""
    body = html(client)

    assert "<style" not in body
    assert "<script>" not in body
    assert 'src="/static/js/app.js"' in body
    assert 'href="/static/css/app.css"' in body


def test_the_script_renders_text_safely_and_never_as_markup(client: TestClient) -> None:
    script = client.get("/static/js/app.js").text

    assert "textContent" in script
    # Assigning markup is what must never happen. Naming innerHTML in a comment that
    # forbids it is fine, so these check for use rather than for the word.
    assert not re.search(r"\.innerHTML\s*=", script)
    assert ".insertAdjacentHTML(" not in script
    assert "document.write(" not in script
    assert not re.search(r"\beval\s*\(", script)
    assert "new Function(" not in script


def test_the_script_defines_every_required_turn_state(client: TestClient) -> None:
    script = client.get("/static/js/app.js").text

    for turn_state in (
        "idle",
        "running",
        "waiting",
        "busy",
        "approval-required",
        "error",
    ):
        assert turn_state in script, turn_state


def test_the_script_renders_only_whitelisted_status_fields(client: TestClient) -> None:
    """A new field in /api/status must not be rendered without review."""
    script = client.get("/static/js/app.js").text

    assert 'SAFE_STATUS_FIELDS = ["application", "authentication_provider"]' in script


def test_every_element_the_script_addresses_exists_in_the_document(
    client: TestClient,
) -> None:
    """Cross-check the script against the markup.

    ``byId`` returns null for an unknown id and the render helpers then no-op, so a
    typo would fail silently in a browser. There is no browser in CI, so the ids are
    checked statically instead.
    """
    script = client.get("/static/js/app.js").text
    body = html(client)

    referenced = set(re.findall(r'byId\("([^"]+)"\)', script))

    assert referenced
    missing = sorted(name for name in referenced if f'id="{name}"' not in body)
    assert not missing, f"script addresses ids that do not exist: {missing}"


def test_every_navigation_target_has_a_matching_view_section(client: TestClient) -> None:
    body = html(client)

    targets = set(re.findall(r'data-nav="([^"]+)"', body))

    assert targets == {"conversations", "accounting", "status"}
    for target in targets:
        assert f'id="{target}-view"' in body, target


def test_the_shell_does_not_promise_streaming(client: TestClient) -> None:
    """Phase 4 uses request/response plus polling; no SSE or WebSocket here."""
    script = client.get("/static/js/app.js").text

    assert "EventSource" not in script
    assert "WebSocket" not in script
    assert "socket.io" not in script


# --- the P4-02 surface is unchanged ---------------------------------------


def test_healthz_is_unchanged(client: TestClient) -> None:
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_api_status_is_still_protected(client: TestClient) -> None:
    response = client.get("/api/status")

    assert response.status_code == 401


def test_documentation_still_follows_the_configuration_switch() -> None:
    with TestClient(create_app(WebAppConfig())) as client:
        assert client.get("/docs").status_code == 404

    with TestClient(create_app(WebAppConfig(docs_enabled=True))) as client:
        assert client.get("/docs").status_code == 200


def test_static_assets_stay_outside_the_authenticated_api_prefix(client: TestClient) -> None:
    """GUI assets are public layout; they must not sit under the protected /api."""
    for path in ("/api/css/app.css", "/api/js/app.js", "/api/static/js/app.js"):
        assert client.get(path).status_code == 404, path


def test_the_gui_directory_is_the_only_static_root() -> None:
    assert STATIC_DIRECTORY.is_dir()
    assert INDEX_FILE.is_file()
    assert (STATIC_DIRECTORY / "css" / "app.css").is_file()
    assert (STATIC_DIRECTORY / "js" / "app.js").is_file()
