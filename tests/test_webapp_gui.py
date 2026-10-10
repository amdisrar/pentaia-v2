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
#
# P4-08 adds the authentication endpoints: the shell signs in, signs out, and reads its
# own identity and CSRF token. Nothing else may be referenced, so a route cannot be
# reached from the browser without appearing here first.
ALLOWED_BROWSER_ENDPOINTS = {
    "/healthz",
    "/api/status",
    "/api/me",
    "/api/auth/csrf",
    "/api/auth/login",
    "/api/auth/logout",
}

SHELL_ELEMENT_IDS = (
    # login state
    "login-view",
    "login-subtitle",
    "login-form",
    "login-username",
    "login-password",
    "login-submit",
    "login-error",
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


def test_the_browser_calls_only_the_reviewed_endpoints(client: TestClient) -> None:
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


def test_the_login_form_posts_credentials_to_the_login_endpoint(
    client: TestClient,
) -> None:
    """The sign-in form is real, and a password can never end up in a URL.

    P4-03 shipped no credential entry at all; P4-08 replaces that placeholder, so this
    test is inverted rather than removed. ``method="post"`` with no ``action`` is the
    part that matters: if the script fails to load, the browser posts a body to this same
    origin instead of appending the credentials to the URL.
    """
    body = html(client)

    assert 'type="password"' in body
    assert 'name="username"' in body
    assert 'name="password"' in body
    assert 'autocomplete="username"' in body
    assert 'autocomplete="current-password"' in body

    form = re.search(r"<form[^>]*id=\"login-form\"[^>]*>", body)

    assert form is not None
    assert 'method="post"' in form.group(0)
    assert "action=" not in form.group(0), "a native submit target could carry a URL"

    # The form is driven by script; the endpoint it uses is the reviewed one.
    script = client.get("/static/js/app.js").text
    assert '"/api/auth/login"' in script


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


# --- P4-08 sign-in state ---------------------------------------------------


def test_the_shell_keeps_credentials_and_tokens_out_of_browser_storage(
    client: TestClient,
) -> None:
    """No persistent storage anywhere in the shell: a reload must lose the token.

    Naming a storage API in a comment that forbids it is fine, so these check for use
    rather than for the word.
    """
    script = client.get("/static/js/app.js").text

    for api in ("localStorage", "sessionStorage", "indexedDB"):
        assert not re.search(rf"\b{api}\s*[.\[]", script), api

    assert not re.search(r"document\.cookie\s*=", script)


def test_the_shell_never_puts_a_token_or_credential_in_a_url(client: TestClient) -> None:
    """Tokens travel in a header; the URL carries only the view fragment."""
    script = client.get("/static/js/app.js").text

    assert "location.search" not in script
    assert "location.href" not in script
    assert "csrf_token=" not in script
    assert "password=" not in script
    assert "username=" not in script


def test_the_shell_sends_the_reviewed_csrf_header(client: TestClient) -> None:
    script = client.get("/static/js/app.js").text

    assert 'var CSRF_HEADER = "X-PentAiA-CSRF"' in script
    assert "headers[CSRF_HEADER]" in script


def test_the_shell_never_renders_server_provided_text(client: TestClient) -> None:
    """Status codes map to fixed strings, so a response body cannot become page text."""
    script = client.get("/static/js/app.js").text

    # The FastAPI error envelope is never read, and no server string is inserted: the
    # message shown comes from this file's own fixed table, chosen by status code.
    assert "result.body.detail" not in script
    assert "body.detail" not in script
    assert "body.error" not in script
    assert "showLoginError(messageForStatus(result.response.status))" in script

    # Every response field the shell reads is named here. A new one has to be added to
    # this set deliberately, which is what stops a response body being rendered wholesale.
    read_fields = set(re.findall(r"\b(?:result\.)?body\.([A-Za-z_]+)", script))

    assert read_fields == {"username", "display_name", "csrf_token"}


def test_the_shell_handles_every_authentication_failure_state(client: TestClient) -> None:
    """Each answer the login route can give has its own honest message."""
    script = client.get("/static/js/app.js").text

    for status in ("401", "403", "429", "503"):
        assert status in script, status

    for key in ("rejected", "unverified", "throttled", "unavailable", "expired"):
        assert key in script, key


def test_the_shell_clears_the_password_field_after_a_submission(
    client: TestClient,
) -> None:
    script = client.get("/static/js/app.js").text

    assert 'byId("login-password")' in script
    assert "passwordField.value = \"\"" in script


def test_the_shell_asks_the_server_who_the_caller_is(client: TestClient) -> None:
    """The signed-in state comes from the server, never from a stored flag."""
    script = client.get("/static/js/app.js").text

    assert '"/api/me"' in script
    assert "bootstrap" in script
    assert "state.authenticated" in script
    # The preview flag P4-03 used to fake a signed-in state is gone.
    assert "preview" not in script.lower()


def test_the_shell_addresses_the_sign_in_controls_it_needs(client: TestClient) -> None:
    body = html(client)
    script = client.get("/static/js/app.js").text

    for element_id in ("login-form", "login-username", "login-password", "login-submit", "login-error", "logout-button"):
        assert f'id="{element_id}"' in body, element_id
        assert f'byId("{element_id}")' in script, element_id


# --- the sign-in screen shows nothing about the implementation -------------


def test_the_login_screen_shows_only_the_sign_in_copy(client: TestClient) -> None:
    """The sign-in card carries the application name, the form and nothing else.

    The exact visible string is pinned, so a line added here — a deployment note, a
    provider name, a security explanation — has to be reviewed deliberately instead of
    arriving as a side effect of another change. Markup comments are not visible text and
    are ignored; the error paragraph is empty until the application fills it.
    """
    section = re.search(r'<section id="login-view".*?</section>', html(client), re.DOTALL)

    assert section is not None

    visible = re.sub(r"<!--.*?-->", " ", section.group(0), flags=re.DOTALL)
    visible = re.sub(r"<[^>]+>", " ", visible)

    assert " ".join(visible.split()) == (
        "PentAiA Sign in to continue Username Password Sign in"
    )


@pytest.mark.parametrize(
    "text",
    [
        "AI-assisted penetration testing",
        "explicitly authorized lab systems",
        "Credentials are sent to this application",
        "never placed in a URL",
        "HTTPS origin",
        "identity provider",
        "LDAP",
        "RADIUS",
        "PENTAIA_",
        "CSRF",
    ],
)
def test_the_login_screen_does_not_describe_the_implementation(
    client: TestClient, text: str
) -> None:
    """No deployment, provider, protocol or security-implementation wording on screen."""
    assert text.lower() not in html(client).lower(), text


def test_the_login_screen_keeps_the_application_name_prominent(
    client: TestClient,
) -> None:
    """The product name is what the screen leads with, not a paragraph about the app."""
    heading = re.search(r'<h1[^>]*id="login-heading"[^>]*>([^<]*)</h1>', html(client))

    assert heading is not None
    assert heading.group(1).strip() == "PentAiA"

    stylesheet = client.get("/static/css/app.css").text
    assert ".login-card h1" in stylesheet, "the sign-in heading has its own treatment"
    assert "#login-subtitle" in stylesheet
