/*
 * PentAiA Phase 4 GUI shell (P4-03), with the real sign-in flow (P4-08).
 *
 * Scope: layout state and authentication state. This script signs in, signs out, reads
 * the safe status endpoints, and switches between the signed-out and signed-in views.
 * It does not call a tool, a wrapper, the Kali executor, or any agent function, and it
 * never constructs an approval or a proposal.
 *
 * Safety rules enforced here:
 *   - every dynamic value is written with textContent, never as markup;
 *   - only whitelisted fields from /api/status are rendered, by name;
 *   - server-provided error text is never rendered: status codes map to fixed strings
 *     written in this file, so a response body cannot become page content;
 *   - the CSRF token lives in a variable in this closure. It is never written to
 *     localStorage, sessionStorage, a cookie or a URL, and it is not logged;
 *   - credentials are sent in a JSON request body to the login endpoint and nowhere
 *     else;
 *   - a failed or refused request is shown as a state, never faked as data.
 */
(function () {
  "use strict";

  var HEALTH_PATH = "/healthz";
  var STATUS_PATH = "/api/status";
  var IDENTITY_PATH = "/api/me";
  var CSRF_PATH = "/api/auth/csrf";
  var LOGIN_PATH = "/api/auth/login";
  var LOGOUT_PATH = "/api/auth/logout";

  var CSRF_HEADER = "X-PentAiA-CSRF";

  // Turn states the Phase 4 architecture needs the UI to express. The backend
  // behaviour behind them arrives with conversation integration (P4-11) and the
  // per-conversation busy/conflict response.
  var TURN_STATES = {
    idle: { label: "Idle", detail: "" },
    running: { label: "Running", detail: "PentAiA is working on this conversation." },
    waiting: { label: "Waiting", detail: "Waiting for the next step." },
    busy: {
      label: "Busy",
      detail: "Another turn is already running for this conversation."
    },
    "approval-required": {
      label: "Approval required",
      detail: "A state-changing action is waiting for a human decision."
    },
    error: { label: "Error", detail: "The last turn did not complete." }
  };

  // Only these /api/status fields may be shown, by name. Anything else in the
  // payload is ignored rather than rendered.
  var SAFE_STATUS_FIELDS = ["application", "authentication_provider"];

  // Fixed client-side messages. The server's own text is never displayed, so an
  // unexpected response body cannot place words in the interface.
  var MESSAGES = {
    invalid: "Enter a username and a password.",
    rejected: "Sign-in failed. Check your username and password.",
    unverified: "Sign-in could not be verified. Reload the page and try again.",
    throttled: "Too many sign-in attempts. Wait a moment and try again.",
    unavailable: "Sign-in is temporarily unavailable.",
    failed: "Sign-in could not be completed.",
    expired: "Your session ended. Sign in again."
  };

  var VIEWS = ["conversations", "accounting", "status"];

  var state = {
    authenticated: false,
    identity: null,
    csrfToken: null,
    submitting: false,
    view: "conversations"
  };

  function byId(id) {
    return document.getElementById(id);
  }

  /** Write text safely. Never innerHTML: this is the single rendering path. */
  function setText(element, text) {
    if (element) {
      element.textContent = text === null || text === undefined ? "" : String(text);
    }
  }

  function setHidden(element, hidden) {
    if (element) {
      element.hidden = Boolean(hidden);
    }
  }

  function setDisabled(element, disabled) {
    if (element) {
      element.disabled = Boolean(disabled);
    }
  }

  function viewFromHash() {
    var hash = window.location.hash || "";
    var name = hash.replace(/^#/, "");

    return VIEWS.indexOf(name) === -1 ? null : name;
  }

  function showLoginError(message) {
    var element = byId("login-error");

    setText(element, message || "");
    setHidden(element, !message);
  }

  function identityLabel() {
    if (!state.authenticated || !state.identity) {
      return "Not signed in";
    }

    return state.identity.display_name || state.identity.username || "Signed in";
  }

  function render() {
    var requested = viewFromHash();

    if (requested) {
      state.view = requested;
    }

    setHidden(byId("login-view"), state.authenticated);
    setHidden(byId("app-view"), !state.authenticated);

    VIEWS.forEach(function (name) {
      setHidden(byId(name + "-view"), !state.authenticated || name !== state.view);
    });

    Array.prototype.forEach.call(
      document.querySelectorAll("#app-nav a[data-nav]"),
      function (link) {
        var active = link.getAttribute("data-nav") === state.view;
        link.setAttribute("aria-current", active ? "page" : "false");
        link.classList.toggle("active", active);
      }
    );

    setText(byId("session-identity"), identityLabel());
    setDisabled(byId("logout-button"), !state.authenticated);
    setDisabled(byId("login-submit"), state.submitting);

    if (state.authenticated && state.view === "status") {
      refreshStatus();
    }
  }

  function setTurnState(name) {
    var turn = TURN_STATES[name] || TURN_STATES.idle;
    var element = byId("turn-status");

    if (element) {
      element.setAttribute("data-state", TURN_STATES[name] ? name : "idle");
    }

    setText(byId("turn-status-label"), turn.label);
    setText(byId("turn-status-detail"), turn.detail);
  }

  /**
   * Render the server-owned proposal in the reserved approval panel.
   *
   * Unused until P4-12 supplies a proposal from the server. It exists now so the
   * safe rendering path for untrusted proposal text is established and tested: every
   * field goes through textContent, and nothing here can approve anything.
   */
  function renderApproval(proposal) {
    if (!proposal) {
      setHidden(byId("approval-panel"), true);

      return;
    }

    setText(byId("approval-target"), proposal.target);
    setText(byId("approval-action"), proposal.action_id);
    setText(byId("approval-rationale"), proposal.rationale);
    setText(byId("approval-expected-effect"), proposal.expected_effect);
    setText(
      byId("approval-parameters"),
      proposal.parameters ? JSON.stringify(proposal.parameters) : ""
    );

    setHidden(byId("approval-panel"), false);
  }

  function describeResponse(response) {
    return "HTTP " + response.status;
  }

  function renderStatusField(elementId, outcome, detail) {
    var element = byId(elementId);

    if (element) {
      element.setAttribute("data-state", outcome);
    }

    setText(element, detail);
  }

  function readJson(response) {
    return response
      .json()
      .catch(function () {
        return null;
      })
      .then(function (body) {
        return { response: response, body: body };
      });
  }

  function get(path) {
    return window
      .fetch(path, {
        method: "GET",
        credentials: "same-origin",
        headers: { Accept: "application/json" }
      })
      .then(readJson);
  }

  function post(path, body) {
    var headers = { Accept: "application/json", "Content-Type": "application/json" };

    if (state.csrfToken) {
      headers[CSRF_HEADER] = state.csrfToken;
    }

    return window
      .fetch(path, {
        method: "POST",
        credentials: "same-origin",
        headers: headers,
        body: JSON.stringify(body)
      })
      .then(readJson);
  }

  /** Drop to the signed-out view when the server says the session is gone. */
  function handleSessionLoss() {
    state.authenticated = false;
    state.identity = null;
    state.csrfToken = null;
    showLoginError(MESSAGES.expired);

    return loadCsrfToken().then(render);
  }

  /**
   * Fetch the CSRF token for the current state.
   *
   * Signed out this is the pre-authentication token the login form needs; signed in it
   * is the session's own token, which is also how a reloaded page recovers the value it
   * held only in memory.
   */
  function loadCsrfToken() {
    return get(CSRF_PATH).then(function (result) {
      if (result.response.ok && result.body && result.body.csrf_token) {
        state.csrfToken = result.body.csrf_token;
      }
      // A missing token is not fatal here: the next state-changing request is refused
      // by the server and reported honestly rather than being sent unverified.
    });
  }

  function applyIdentity(body) {
    state.authenticated = true;
    state.identity = {
      username: body && body.username ? body.username : "",
      display_name: body && body.display_name ? body.display_name : ""
    };
  }

  function bootstrap() {
    return get(IDENTITY_PATH).then(function (result) {
      if (result.response.status === 401) {
        state.authenticated = false;
        state.identity = null;

        return loadCsrfToken().then(render);
      }

      if (!result.response.ok || !result.body) {
        // Reported as a state rather than guessed at: the sign-in form stays usable so
        // the operator is not locked out by a transient failure.
        showLoginError(MESSAGES.failed);

        return loadCsrfToken().then(render);
      }

      applyIdentity(result.body);

      return loadCsrfToken().then(render);
    });
  }

  function submitLogin(event) {
    if (event) {
      event.preventDefault();
    }

    if (state.submitting) {
      return;
    }

    var usernameField = byId("login-username");
    var passwordField = byId("login-password");
    var username = usernameField ? usernameField.value : "";
    var password = passwordField ? passwordField.value : "";

    if (!username || !password) {
      showLoginError(MESSAGES.invalid);

      return;
    }

    state.submitting = true;
    showLoginError("");
    render();

    post(LOGIN_PATH, { username: username, password: password })
      .then(function (result) {
        state.submitting = false;

        // The password is cleared as soon as it has been sent, whatever the outcome.
        if (passwordField) {
          passwordField.value = "";
        }

        if (result.response.ok && result.body) {
          applyIdentity(result.body);

          return loadCsrfToken().then(function () {
            showLoginError("");
            render();
          });
        }

        showLoginError(messageForStatus(result.response.status));
        render();
      })
      .catch(function () {
        state.submitting = false;

        if (passwordField) {
          passwordField.value = "";
        }

        showLoginError(MESSAGES.failed);
        render();
      });
  }

  function messageForStatus(status) {
    if (status === 401) {
      return MESSAGES.rejected;
    }

    if (status === 403) {
      return MESSAGES.unverified;
    }

    if (status === 429) {
      return MESSAGES.throttled;
    }

    if (status === 503) {
      return MESSAGES.unavailable;
    }

    return MESSAGES.failed;
  }

  function logout() {
    if (!state.authenticated) {
      return;
    }

    post(LOGOUT_PATH, {})
      .then(function (result) {
        if (result.response.status === 401) {
          return handleSessionLoss();
        }

        if (!result.response.ok) {
          showLoginError(MESSAGES.failed);

          return;
        }

        state.authenticated = false;
        state.identity = null;
        state.csrfToken = null;
        showLoginError("");

        return loadCsrfToken().then(render);
      })
      .catch(function () {
        showLoginError(MESSAGES.failed);
      });
  }

  function refreshStatus() {
    renderStatusField("status-healthz", "unknown", "checking\u2026");
    renderStatusField("status-api", "unknown", "checking\u2026");
    setText(byId("status-note"), "");

    get(HEALTH_PATH)
      .then(function (result) {
        renderStatusField(
          "status-healthz",
          result.response.ok ? "ok" : "error",
          result.response.ok ? "healthy (" + describeResponse(result.response) + ")" : describeResponse(result.response)
        );
      })
      .catch(function () {
        renderStatusField("status-healthz", "error", "unreachable");
      });

    get(STATUS_PATH)
      .then(function (result) {
        if (result.response.status === 401) {
          // The session ended while the page was open. Reported honestly rather than
          // hidden or replaced with placeholder data.
          renderStatusField(
            "status-api",
            "warning",
            "authentication required (" + describeResponse(result.response) + ")"
          );
          setText(
            byId("status-note"),
            "The authenticated status endpoint refuses unauthenticated requests by design."
          );

          return;
        }

        if (!result.response.ok || !result.body) {
          renderStatusField("status-api", "error", describeResponse(result.response));

          return;
        }

        var parts = SAFE_STATUS_FIELDS.filter(function (field) {
          return Object.prototype.hasOwnProperty.call(result.body, field);
        }).map(function (field) {
          return field + ": " + String(result.body[field]);
        });

        renderStatusField("status-api", "ok", parts.join(", ") || "available");
      })
      .catch(function () {
        renderStatusField("status-api", "error", "unreachable");
      });
  }

  function bind() {
    var form = byId("login-form");
    var logoutButton = byId("logout-button");
    var refresh = byId("refresh-status");

    if (form) {
      form.addEventListener("submit", submitLogin);
    }

    if (logoutButton) {
      logoutButton.addEventListener("click", logout);
    }

    if (refresh) {
      refresh.addEventListener("click", refreshStatus);
    }

    window.addEventListener("hashchange", render);
  }

  // Exposed for tests and for the later integration points. Nothing here executes an
  // action: the disabled controls stay disabled in this build. The CSRF token is
  // deliberately not exposed.
  window.PentAiAShell = {
    TURN_STATES: TURN_STATES,
    SAFE_STATUS_FIELDS: SAFE_STATUS_FIELDS,
    MESSAGES: MESSAGES,
    setTurnState: setTurnState,
    renderApproval: renderApproval,
    refreshStatus: refreshStatus,
    bootstrap: bootstrap,
    submitLogin: submitLogin,
    logout: logout,
    getState: function () {
      return {
        authenticated: state.authenticated,
        hasIdentity: Boolean(state.identity),
        hasCsrfToken: Boolean(state.csrfToken),
        view: state.view
      };
    }
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      bind();
      setTurnState("idle");
      bootstrap();
    });
  } else {
    bind();
    setTurnState("idle");
    bootstrap();
  }
})();
