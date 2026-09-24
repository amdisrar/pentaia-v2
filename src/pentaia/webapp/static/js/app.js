/*
 * PentAiA Phase 4 GUI shell (P4-03).
 *
 * Scope: layout state only. This script switches between the login state and the
 * application shell, tracks a turn/busy state, and reads the two existing safe
 * status endpoints. It does not call a tool, a wrapper, the Kali executor, or any
 * agent function, and it never constructs an approval or a proposal.
 *
 * Safety rules enforced here:
 *   - every dynamic value is written with textContent, never as markup, so future
 *     conversation and approval text cannot inject HTML;
 *   - only whitelisted fields from /api/status are rendered, by name;
 *   - a failed or refused request is shown as a state, never faked as data.
 */
(function () {
  "use strict";

  var LOGIN_HASH = "#login";

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

  var VIEWS = ["conversations", "accounting", "status"];

  var state = {
    preview: false,
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

  function viewFromHash() {
    var hash = window.location.hash || "";
    var name = hash.replace(/^#/, "");

    return VIEWS.indexOf(name) === -1 ? null : name;
  }

  function render() {
    var requested = viewFromHash();

    if (requested) {
      state.view = requested;
    }

    if (window.location.hash === LOGIN_HASH) {
      state.preview = false;
    }

    setHidden(byId("login-view"), state.preview);
    setHidden(byId("app-view"), !state.preview);

    VIEWS.forEach(function (name) {
      setHidden(byId(name + "-view"), !state.preview || name !== state.view);
    });

    Array.prototype.forEach.call(
      document.querySelectorAll("#app-nav a[data-nav]"),
      function (link) {
        var active = link.getAttribute("data-nav") === state.view;
        link.setAttribute("aria-current", active ? "page" : "false");
        link.classList.toggle("active", active);
      }
    );

    setHidden(byId("preview-badge"), !state.preview);
    setHidden(byId("exit-preview"), !state.preview);
    setText(
      byId("session-identity"),
      state.preview ? "Preview \u2014 not authenticated" : "Not signed in"
    );

    if (state.preview && state.view === "status") {
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

  function fetchJson(path) {
    return window
      .fetch(path, {
        method: "GET",
        credentials: "same-origin",
        headers: { Accept: "application/json" }
      })
      .then(function (response) {
        return response
          .json()
          .catch(function () {
            return null;
          })
          .then(function (body) {
            return { response: response, body: body };
          });
      });
  }

  function refreshStatus() {
    renderStatusField("status-healthz", "unknown", "checking\u2026");
    renderStatusField("status-api", "unknown", "checking\u2026");
    setText(byId("status-note"), "");

    fetchJson("/healthz")
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

    fetchJson("/api/status")
      .then(function (result) {
        if (result.response.status === 401) {
          // Expected until authentication exists (P4-04). Reported honestly rather
          // than hidden or replaced with placeholder data.
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

  function startPreview() {
    state.preview = true;

    if (!viewFromHash()) {
      window.location.hash = "#conversations";

      return;
    }

    render();
  }

  function exitPreview() {
    state.preview = false;
    window.location.hash = LOGIN_HASH;
    render();
  }

  function bind() {
    var preview = byId("preview-shell");
    var exit = byId("exit-preview");
    var refresh = byId("refresh-status");

    if (preview) {
      preview.addEventListener("click", startPreview);
    }

    if (exit) {
      exit.addEventListener("click", exitPreview);
    }

    if (refresh) {
      refresh.addEventListener("click", refreshStatus);
    }

    window.addEventListener("hashchange", render);
  }

  // Exposed for tests and for the later integration points. Nothing here executes an
  // action: the disabled controls stay disabled in this build.
  window.PentAiAShell = {
    TURN_STATES: TURN_STATES,
    SAFE_STATUS_FIELDS: SAFE_STATUS_FIELDS,
    setTurnState: setTurnState,
    renderApproval: renderApproval,
    refreshStatus: refreshStatus,
    getState: function () {
      return { preview: state.preview, view: state.view };
    }
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      bind();
      setTurnState("idle");
      render();
    });
  } else {
    bind();
    setTurnState("idle");
    render();
  }
})();
