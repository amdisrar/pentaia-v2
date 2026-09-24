# PentAiA v2 — Phase 4 Architecture

## Document Control

| Field | Value |
|---|---|
| Document Title | PentAiA v2 — Phase 4 Architecture |
| Document ID | PENTAIA-ARCH-P4-DSH-01 |
| Version | 0.1 |
| Status | Draft — reviewed with the owner; awaiting acceptance |
| **Written by** | **DSH** |
| Produced with | DSH (DeepSeek Harness) coding agent, in session with the owner |
| Owner | Israr |
| Project | PentAiA v2 |
| Repository | `amdisrar/pentaia-v2` |
| Related GitHub Issue | #51 — P4-01 Define Phase 4 web, identity, accounting, and CLI security architecture |
| Prepared Date | 24 September 2026 |
| Classification | Project Internal / Educational Research |
| Relationship to other documents | An independent second architecture draft for the same issue. `docs/phase4-architecture.md` (PENTAIA-ARCH-P4-01) is the separately authored document; this one is not a modification of it and was written without editing it. |

### Document History

| Version | Date | Written by | Change Summary | Status |
|---|---|---|---|---|
| 0.1 | 24 September 2026 | DSH | Initial Phase 4 architecture: component and deployment topology, identity and provider model, secure web sessions, browser-reachable API surface, web approval workflow, accounting/audit, break-glass CLI split, Phase 4/5 boundary, testing strategy, issue coverage, and implementation sequencing | Draft |

---

**Status of the content:** sections marked **[F]** are fixed by issue P4-01 and the
project invariants; **[D]** marks decisions agreed with the owner during review of
this document (recorded in §0).

Scope of this document: issue **#51 (P4-01)** — the Phase 4 production architecture
for the web GUI, FastAPI backend, enterprise authentication, secure sessions,
application accounting/audit, and the retained local break-glass CLI.

This document defines **no new exploitation capability**. Phase 3's approval,
target-authorization and controlled-tool boundaries are unchanged by design, and
that is an explicit acceptance criterion of #51.

---

## 0. Decisions agreed in review

| # | Decision | Outcome |
|---|---|---|
| Q1 | Deployment host | **[D]** Same workstation/WSL host that runs the CLI today. The Kali SSH trust boundary does not move; Phase 4 adds no new network path to the lab. |
| Q2 | Application store | **[D]** SQLite behind a repository layer, under `PENTAIA_DATA_DIR` (file mode 0600). |
| Q3 | Identity key | **[D]** Normalised UPN (`auth_source:username`), no directory read rights required. |
| Q4 | Sessions per user | **[D]** Multiple concurrent sessions, bounded by idle and absolute timeouts, each accounted separately. |
| Q5 | Break-glass split | **[D]** Disable only the LLM agent REPL by default; move `pentaia session …` under `pentaia-admin`, where it stays usable during an identity outage. |
| Q6 | Audit tamper-evidence | **[D]** Hash-chained append-only records, verifiable by `pentaia-admin accounting verify`. |
| Q7 | Live progress streaming | **[D]** No. Request/response plus short polling in Phase 4; add SSE only if the UX demands it. |
| Q8 | Identity infrastructure | **[D]** Active Directory over LDAPS is available and **will be validated end to end (#66)**. RADIUS is not available; #56 is still implemented per its issue, verified with mocked tests only, and **#67 must be recorded as a labelled gap, not closed as verified**. |
| Q9 | Requester vs approver | **[D]** Single-operator approval is acceptable in Phase 4, but requester and approver are stored as separate identities so a Phase 5 two-person rule needs no schema change. |
| Q10 | TLS termination | **[D]** Reverse proxy on the same host; the app trusts `X-Forwarded-Proto` only from a configured proxy. |


## 1. Goals and non-goals

### Goals
- A browser GUI becomes the normal operational interface for PentAiA.
- Enterprise authentication (Active Directory over LDAPS, RADIUS) replaces nothing
  about how actions are approved — it identifies *who* is operating.
- Every authentication, conversation, approval and administration event is
  accounted for, durably and queryably.
- The existing CLI is retained as a local break-glass path that does not depend on
  enterprise identity being available.
- Existing Phase 1–3 behaviour stays reachable and regression-testable.

### Non-goals (deferred to Phase 5 or later)
- RBAC / authorization policy beyond "authenticated identity exists".
- Full settings/admin portal (Phase 4 has only minimal operational status/config).
- Persistent agent memory across restarts (#50).
- Multi-tenancy, horizontal scaling, HA.
- Any new target interaction, tool, or exploit path.

### Explicit non-goal: the browser is not a privileged client
The single most important architectural statement in this document:

> The browser is a **presentation and intent** client. It never receives tool
> schemas, never constructs a proposal, never supplies approval state, never sends
> a target, and never reaches a wrapper. Every state-changing decision is resolved
> server-side from graph state and re-validated by the existing Phase 3 code.

This is invariant 18 made concrete. Section 7 defines the only browser-reachable
surface, and it is deliberately tiny.

---

## 2. Deployment topology

**[D] Single-host deployment, one application process.** Runs on the same
workstation/WSL host that runs the CLI today (Q1), so the SSH trust boundary to
Kali does not move.

```text
                    ┌─────────────────────────────────────────┐
  Operator browser  │  PentAiA host (workstation or server)    │
        │           │                                          │
        │  HTTPS    │  ┌────────────────────────────────────┐  │
        └──────────►│  │ uvicorn: FastAPI app               │  │
                    │  │  static GUI assets + JSON API      │  │
                    │  │  auth · sessions · accounting      │  │
                    │  │  conversation service              │  │
                    │  │  ─────────────────────────────     │  │
                    │  │  pentaia core (Phases 1–3)         │  │
                    │  │  graph · wrappers · kali_executor  │  │
                    │  └───────────────┬────────────────────┘  │
                    │                  │ SSH (existing path)   │
                    └──────────────────┼──────────────────────┘
                                       ▼
                                  Kali 172.16.0.x
                                       │
                                       ▼
                            authorized lab target
```

Rationale:
- The Phase 3 trust boundary is the SSH connection from the PentAiA host to Kali.
  Keeping the web app on the same host as today's CLI means **that boundary does
  not move**, so Phase 4 introduces no new network path to the lab.
- One process avoids inventing a service mesh for a lab tool, and keeps the
  existing in-process LangGraph session semantics honest (see §6).
- Runs as an unprivileged service user owning its own config and data directory.
- TLS: **[D]** terminate at a reverse proxy (Caddy/nginx) on the same host; the app
  sets `Secure` cookies and trusts `X-Forwarded-Proto` only from a configured
  proxy. App-level TLS is the alternative if no proxy is wanted.

---

## 3. Component architecture

**[F]** Boundaries fixed by #52 and invariant 18; internal structure is **[D]**.

```text
Browser (GUI)
   │  HTTPS, opaque session cookie, CSRF token
   ▼
FastAPI application
   ├── api/            versioned JSON routes — the ONLY browser surface
   ├── auth/           provider abstraction: ad | radius
   ├── identity/       authenticated user + server-side web sessions
   ├── conversations/  conversation ↔ LangGraph thread mapping, per-thread lock
   ├── approval/       read-only projection + decision resolution (no state injection)
   ├── accounting/     append-only event store + emitter
   └── core/           EXISTING pentaia package, imported unchanged
         graph.py · approval.py · authorization.py · phase3_tools.py
         metasploit_wrapper.py · phase3_session.py · kali_executor.py
```

Rules that make the boundary real:
1. `api/` may import `core/`. `core/` must never import `api/`, `auth/`,
   `identity/`, `conversations/`, or `accounting/`. Enforce with an import test.
2. No route handler builds a native command. Only existing wrappers do that.
3. No route accepts a proposal, approval, signature, tool argument, or target as a
   client-controlled value. Section 7 enumerates the surface.

Proposed package addition (no existing module is rewritten):

```text
src/pentaia/
  webapp/
    api/          routes, dependencies, error mapping
    auth/         base provider, ad_ldaps.py, radius.py, selection
    identity/     user model, session store, cookie policy
    conversations/ registry, locking, thread mapping
    approval/     projection, decision endpoint logic
    accounting/   event schema, emitter, repository, redaction
    static/       GUI assets
  admin_cli.py    pentaia-admin entry point
```

---

## 4. Authentication and identity

### 4.1 Provider abstraction

**[F]** One configurable provider per deployment (#57: "choose the supported
backend without changing application code"). **[D]** Do not support simultaneous
providers in Phase 4 — it halves the test matrix and Phase 5 RBAC is where
multi-source policy belongs.

```python
class AuthOutcome(enum.Enum):
    SUCCESS = "success"
    REJECTED = "rejected"        # credentials wrong
    UNAVAILABLE = "unavailable"  # server down / timeout
    MISCONFIGURED = "misconfigured"

@dataclass(frozen=True)
class AuthResult:
    outcome: AuthOutcome
    identity: AuthenticatedIdentity | None
    detail: str = ""             # safe, never contains credentials

class AuthProvider(Protocol):
    name: str
    def authenticate(self, username: str, password: str) -> AuthResult: ...
    def health(self) -> AuthOutcome: ...
```

**[F] Fail closed.** `UNAVAILABLE` and `MISCONFIGURED` deny login. There is no
fallback to a local password and no "remember last known good" cache. A
deployment that cannot reach its identity provider is a deployment nobody can log
into — that is the correct trade, and it is why §8 exists.

### 4.2 AD over LDAPS (#55)

- Configuration: host(s), port (636), base DN, bind mode, and either a service
  account (`bind_dn` + `bind_password`) or direct user bind.
- **[D] Direct user bind as the default**: bind as the user to prove the password,
  then optionally search for display attributes. A service account is only needed
  if group/attribute lookups are required. Fewer stored secrets, and no privileged
  credential on disk.
- **Must not**: write to the directory, perform unauthenticated searches, or
  disable certificate verification. `LDAPS` with a required server certificate is
  the only supported transport; **[D]** support an explicit
  `PENTAIA_AD_CA_BUNDLE` for a private CA rather than an "ignore TLS" switch.
- Timeout on every operation (default 5s) so a hung directory cannot hang logins.

### 4.3 RADIUS (#56)

- Configuration: server, port (1812), shared secret, NAS identifier, timeout,
  retries.
- Implementation: Access-Request → Access-Accept / Access-Reject / no response.
  **[D]** Use a maintained client library rather than hand-rolling the packet
  format; hand-rolled RADIUS authenticators are a common source of subtle bugs
  (Message-Authenticator, response authenticator validation).
- **Must not** implement role/authorization mapping from RADIUS attributes in
  Phase 4 (#56 explicitly defers this).
- Timeout/retry exhaustion maps to `UNAVAILABLE` → fail closed.

### 4.4 Normalised identity

**[F]** Passwords and shared secrets never enter LangGraph state, conversation
history, logs, or the browser (#54, invariant 16).

```python
@dataclass(frozen=True)
class AuthenticatedIdentity:
    user_id: str        # stable, provider-scoped identifier used in accounting
    username: str       # as presented, normalised
    display_name: str   # for the GUI; may fall back to username
    auth_source: str    # "ad" | "radius"
    authenticated_at: datetime
```

- The password is used for the bind and **discarded in the same function scope**.
  It is never stored on the session, never passed to the conversation service, and
  never logged.
- **[D]** `user_id = f"{auth_source}:{username.lower()}"`. This needs no directory
  read rights and is stable as long as the UPN is. If a rename-stable identifier is
  wanted, AD `objectGUID` would require an extra service-account search — see
  **§0 Q3**.
- Phase 5 RBAC will hang off `user_id`; Phase 4 assigns no roles.

---

## 5. Web session model (#54, #58)

**[F]** Identity is application-owned after authentication; the cookie is never a
bearer of authority beyond a session lookup.

| Control | Decision |
|---|---|
| Session storage | Server-side record keyed by a 256-bit random session ID |
| Cookie | `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, no `Domain` |
| CSRF | `SameSite=Lax` **plus** a per-session token required on every state-changing request |
| Fixation | New session ID issued on every successful login; old record destroyed |
| Idle timeout | Configurable, default 30 min, refreshed on activity |
| Absolute lifetime | Configurable, default 12 h, never extended |
| Logout | Destroys the server-side record immediately |
| Forced invalidation | Admin/break-glass can invalidate a user's sessions; rotating the app secret invalidates all |
| Login throttling | Token bucket per username **and** per client IP, with an accounting event on throttle |
| Error messages | Always "invalid credentials"; provider failures are *not* distinguishable to the client |
| Session ID in logs | Never. Accounting records a session *label*, not the cookie value |

- **[D] What the session does not store:** no password, no token, no directory
  attributes beyond the identity fields in §4.4, no tool or proposal data.
- **[D]** Session records are the authority; the cookie is an opaque pointer. A
  stolen cookie is contained by idle timeout + invalidation, and every use is
  accounted with the session label.
- **§0 Q4** Concurrent sessions per user: allow (default) or single-session-only?
  Single-session is a stronger control but surprises operators with multiple
  browsers/tabs on the same profile.

---

## 6. Conversation and LangGraph integration (#61, #63)

```text
Conversation (application concept)
  conversation_id  ·  user_id  ·  thread_id  ·  created_at  ·  last_active  ·  title
        │
        │  1:1
        ▼
LangGraph thread state (existing AgentState: messages, pending_approval,
validation_context)
```

**[F] Preserve current in-process session memory.** #61 says so explicitly, and
Phase 5 (#50) is where durability arrives. The consequence is documented, not
hidden:

> A conversation is **lost on application restart** in Phase 4. The GUI must say so
> rather than implying history is permanent.

Rules:
1. Every conversation request resolves ownership from the session:
   `conversation.user_id == identity.user_id`, else **404** (not 403 — do not
   confirm the existence of another user's conversation).
2. **One active turn per conversation.** The graph carries `pending_approval` in
   state, so concurrent turns would interleave approval state. A per-conversation
   lock serialises turns; a second request while a turn is running gets a clear
   "busy" response rather than corrupting state.
3. The conversation service is the only component that touches graph state. Routes
   never pass raw messages into the graph without going through it.
4. Phase 3 tool routing, `candidate_lookup`, `approval_gate` and the tool node run
   exactly as they do in the CLI — the web layer does not fork the graph.
5. **[D] Progress delivery:** request/response with short polling for Phase 4
   (simplest, no new failure modes). Server-Sent Events only if the UX needs live
   streaming — see **§0 Q7**.

---

## 7. The browser-reachable surface (approval included)

This section is the security core. The GUI can do exactly this and nothing more.

### 7.1 Enumerated routes (Phase 4)

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/healthz` | liveness, no identity |
| `GET` | `/api/status` | safe provider name + health; no secrets |
| `POST` | `/api/auth/login` | username + password → session cookie |
| `POST` | `/api/auth/logout` | destroy session |
| `GET` | `/api/me` | current identity projection |
| `POST` | `/api/conversations` | start a conversation |
| `GET` | `/api/conversations` | list **own** conversations |
| `GET` | `/api/conversations/{id}` | own conversation + messages |
| `POST` | `/api/conversations/{id}/messages` | send a message; returns the turn result |
| `GET` | `/api/conversations/{id}/approval` | **read-only** pending-approval projection |
| `POST` | `/api/conversations/{id}/approval` | `{"decision": "approve"｜"reject"}` |
| `GET` | `/api/accounting` | own events (admin view is break-glass only) |

**There is no route that accepts**: a target, an `action_id`, tool arguments,
`parameters`, a `proposal`, an approval object, a signature, or a correlation ID
chosen by the client. Approval is not an object the client holds; it is server
state the client may only *decide about*.

### 7.2 The approval flow

```text
turn runs → graph sets pending_approval in state
    │
GET /approval  →  server projection (never the raw state):
    action_id · target · rationale · expected_effect · parameters · signature
    · requested_by (user_id) · proposal_age
    │
GUI renders the exact proposal, then Approve / Reject controls
    │
POST /approval {"decision": "approve"}
    │
server:
  1. resolve the session's identity            (who is deciding)
  2. load pending_approval from graph state    (the client never supplies it)
  3. require it to still be pending and to match the stored signature
  4. if stale/absent → 409, and the human must approve the fresh proposal
  5. decision is exactly the string "approve" or "reject"; anything else → reject
  6. bind the decision to identity.user_id as approver; record requester separately
  7. resume the graph the same way cli_approval.resolve_cli_approval does today
```

Controls preserved, point by point:
- **Exact signature matching** — done by the existing `approval.py`; the web layer
  only calls it.
- **Stale blocking** — existing `stale_approval_node` semantics; the web path adds
  no bypass and reports it as a conflict the human can act on.
- **No client-supplied approval** — `InjectedState("pending_approval")` remains the
  only source of the approval value passed into the tool.
- **Reject is the default** — blank, missing, misspelled, or repeated decisions
  reject. Approval requires an exact positive match, mirroring the CLI's `y`/`yes`.
- **Target authorization unchanged** — `authorization.py` is called from the same
  place; the browser cannot influence the target, which originates from the
  agent's proposal and is re-validated at execution time.
- **Requester vs approver** — recorded as separate identities now, even though in a
  single-operator lab they will usually be the same person (see **§0 Q9**).

### 7.3 Abuse cases considered

| Abuse | Mitigation |
|---|---|
| Client forges an approval | No route accepts approval state; server resolves it from graph state |
| Client reuses another user's conversation | Ownership check on every route → 404 |
| Client changes the target | Target never accepted from the client; `authorization.py` unchanged |
| Stolen cookie | HttpOnly + Secure, idle/absolute timeout, server-side invalidation, use is accounted |
| CSRF | SameSite=Lax + per-session CSRF token on state changes |
| Session fixation | ID regenerated on login |
| Credential stuffing | Per-user and per-IP throttling, generic errors, accounted failures |
| Provider outage | Fail closed; no local fallback |
| Secrets in the DOM | Server-side sessions only; the API never returns a secret |
| XSS | Output escaping + strict CSP; no inline script in the GUI shell |

---

## 8. Break-glass CLI and administration (#51, #64)

**[F] Three interfaces, deliberately distinct:**

| Interface | Audience | Identity | Default |
|---|---|---|---|
| Web GUI | Normal operations | AD / RADIUS | enabled |
| `pentaia` (agent REPL) | Local break-glass | server OS access | **disabled** |
| `pentaia-admin` | Local maintenance | server OS access / sudo | disabled unless invoked locally |

- **[D]** The agent REPL is what gets disabled by default
  (`PENTAIA_CLI_ENABLED=false`). When disabled it prints a clear explanation and
  exits non-zero rather than silently degrading.
- **[D]** `pentaia session list|show|attach|close` belongs to **operational
  maintenance, not the LLM**, so it lives under `pentaia-admin` and remains
  available without enterprise identity. This keeps the existing held-console
  workflow usable during an identity outage, and keeps the dangerous surface (an
  LLM with tools) behind the explicit opt-in. See **§0 Q5**.
- `pentaia-admin` performs no LLM work and no target interaction. Candidate
  commands: `status`, `config validate`, `provider test`, `session
  list|show|close`, `accounting tail|export`, `sessions invalidate`, `recover`.
- **No network listener.** `pentaia-admin` is a local process, not a service. There
  is no remote admin API, so there is nothing to authenticate over the network and
  nothing to expose by misconfiguration.
- Rationale for the whole model: when AD is down, the person standing at the
  console must still be able to close a held Metasploit console and read the audit
  log — that is exactly what OS-level access already grants, so the CLI adds no new
  trust.

---

## 9. Accounting and audit (#59, #60)

### 9.1 Two concerns, one stream

- **Accounting** — who used the system, for what, with what outcome.
- **Audit** — the security-relevant subset: authentication, approval, refused and
  blocked actions, administration.

**[D] One append-only event stream serves both**, with `event_type` distinguishing
them, so there is a single source of truth and no divergence between two logs.

### 9.2 Event schema

```python
@dataclass(frozen=True)
class AccountingEvent:
    event_id: str            # uuid4
    timestamp: datetime      # UTC, ISO-8601 in storage
    event_type: str          # see below
    outcome: str             # success | failure | rejected | blocked | error | stale
    user_id: str | None      # accounting identity (§4.4)
    auth_source: str | None  # "ad" | "radius" | "local"
    session_label: str | None# opaque label, NEVER the cookie value
    conversation_id: str | None
    request_id: str | None   # server-generated correlation id
    duration_ms: int | None
    target: str | None       # where applicable
    action_id: str | None    # where applicable
    proposal_signature: str | None
    error_type: str | None   # exception class name only
    detail: str              # short, whitelisted, human-readable
```

`event_type` values: `login_success`, `login_failure`, `login_throttled`, `logout`,
`session_expired`, `session_invalidated`, `conversation_created`,
`conversation_message`, `approval_requested`, `approval_approved`,
`approval_rejected`, `approval_stale`, `action_blocked`, `action_executed`,
`action_result`, `admin_change`, `system_start`, `system_stop`.

### 9.3 Redaction is a whitelist, not a blacklist

**[F]** No credentials, shared secrets, API keys, SSH key material, session cookie
values, raw configuration dumps, or raw tool output enter the store. This is
enforced structurally: the emitter accepts a typed event object, and `detail` is
composed only from named fields. A blacklist ("strip anything that looks like a
password") is not acceptable, because it fails open the first time a new secret
name appears.

A test must assert that no serialised event matches a set of forbidden patterns
(`password`, `secret`, `api_key`, `BEGIN ... PRIVATE KEY`, the session cookie
value) when fed adversarial inputs.

### 9.4 Durability and tamper-evidence

- Storage: append-only table in the application store (§10). No `UPDATE`, no
  `DELETE`, no route or admin command that removes an event.
- **[D] Hash chain.** `record_hash = sha256(prev_record_hash || canonical_json(event))`
  stored per record, so silent edits or deletions are detectable by a
  `pentaia-admin accounting verify` command. Cheap to implement, and meaningful for
  a tool whose output may be used as evidence. See **§0 Q6**.
- The existing Phase 3 audit logger keeps working. **[D]** Accounting records are
  the source of truth; the Phase 3 audit line is additionally emitted at INFO with
  the same `event_id`, so current operational habits and log greps still work while
  the viewer reads the store.

### 9.5 Viewer (#60)

- `GET /api/accounting` returns the **caller's own** events.
- An administrative view (all users) is available only through `pentaia-admin`
  in Phase 4, because Phase 5 is where roles exist to justify a web admin viewer.
- The viewer is read-only and never renders raw target output.

---

## 10. Data and configuration ownership

**[D] Application store: SQLite on the PentAiA host** (`PENTAIA_DATA_DIR`, file mode
0600), accessed through a thin repository layer.

- Why not in-memory: sessions dying on restart is tolerable, but **accounting must
  survive a restart or it is not accounting**, and conversations already have a
  documented Phase 4 limitation without adding another.
- Why not Postgres in Phase 4: it adds a service to operate for a single-host lab
  tool. The repository layer keeps a later move cheap, and Phase 5 persistence
  (#50) may want a different durable store anyway. See **§0 Q2**.
- The LangGraph checkpointer/thread state is **not** moved into this store in
  Phase 4 (#61 preserves in-process behaviour).

Configuration:
- One loader, validated at startup, failing fast with actionable messages.
- Provider secrets (`PENTAIA_RADIUS_SECRET`, AD bind credentials) are server-side
  only and never reach the API.
- `GET /api/status` exposes only: provider name, provider health, app version.
- Session-signing material lives in a 0600 file under the data dir; rotating it
  invalidates all sessions (documented behaviour, not an accident).
- `.env.example` is updated with every new key; `.env` stays uncommitted.

---

## 11. Phase 4 vs Phase 5 boundary

| Concern | Phase 4 | Phase 5 |
|---|---|---|
| Authentication | ✅ AD (LDAPS), RADIUS, provider selection | — |
| Identity + web sessions | ✅ | — |
| Accounting/audit + retention | ✅ append-only, own-events viewer | richer policy/reporting |
| Web approval workflow | ✅ exact proposal, signature-bound | — |
| Conversation plumbing | ✅ in-process, documented as non-durable | ✅ persistent memory (#50) |
| Authorization / RBAC | ❌ authenticated ≠ authorized | ✅ roles, per-target policy, tool scoping |
| Full settings/admin portal | ❌ minimal status/config only | ✅ |
| Admin viewer of all users | ❌ break-glass CLI only | ✅ role-gated |

**[F]** Phase 4 grants every authenticated user the same capability they have in
today's CLI. Phase 4 is not a permissions system, and the doc must not imply it is.

---

## 12. Testing strategy

- **Unit:** provider clients with mocked LDAP/RADIUS responses (success, reject,
  timeout, malformed); session store lifecycle; cookie attributes; CSRF; throttle
  behaviour; redaction whitelist; hash chain verify.
- **API:** route tests with an ASGI test client asserting — approval routes reject
  missing/blank/extra decision values; ownership failures return 404; **no route
  accepts** `approval`/`signature`/`parameters`/`target`/`action_id`; unauthenticated
  requests to every `/api/*` route are refused.
- **Import boundary test:** `core/` contains no import of any web package.
- **Integration:** conversation → proposal → approve/reject against a fake tool, with
  an explicit assertion that **reject performs no execution** and that a stale
  approval cannot resume a turn.
- **Regression:** the existing 387 tests must stay green; Phase 3 behaviour is not
  allowed to change to accommodate the web layer.
- **No test may contact real AD or RADIUS.**

### Validation reality

Issues **#66** (AD) and **#67** (RADIUS) are *end-to-end validations against real
infrastructure*, and mocked tests cannot close them. They are not equivalent:

- **#66 — AD over LDAPS: will be validated for real.** A domain controller is
  available. Prerequisites to confirm before that test runs: a reachable DC on
  636/tcp, a bind DN (user or service account), and a certificate the PentAiA host
  trusts or an explicit `PENTAIA_AD_CA_BUNDLE`. Until those are confirmed, #66 stays
  open.
- **#67 — RADIUS: will NOT be verified.** No RADIUS server is available. #56 is
  still implemented per its own issue, with mocked coverage for accept, reject,
  timeout and malformed responses. **Do not close #67 as verified.** Record it as a
  labelled, deliberately unverified gap, and repeat that in the Phase 4 validation
  report (#68) so the distinction survives into the project's own history.

---

## 13. Issue coverage

| Issue | Covered by |
|---|---|
| #51 P4-01 architecture | this document |
| #52 P4-02 FastAPI layer | §2, §3, §7.1 |
| #53 P4-03 GUI shell | §2, §7 (surface), §3 (static assets) |
| #54 P4-04 identity + sessions | §4.4, §5 |
| #55 P4-05 AD LDAPS | §4.2 |
| #56 P4-06 RADIUS | §4.3 |
| #57 P4-07 provider selection | §4.1, §10 |
| #58 P4-08 session hardening | §5, §7.3 |
| #59 P4-09 accounting subsystem | §9 |
| #60 P4-10 accounting viewer | §9.5 |
| #61 P4-11 web ↔ LangGraph | §6 |
| #62 P4-12 GUI approval | §7.2 |
| #63 P4-13 conversation history | §6, §10 (durability caveat) |
| #64 P4-14 break-glass CLI | §8 |
| #65 P4-15 admin/status page | §9.5, §10 |
| #66 P4-16 AD validation | §12 gap, **§0 Q8** |
| #67 P4-17 RADIUS validation | §12 gap, **§0 Q8** |
| #68 P4-18 full validation | §12 |
| #69 P4-19 deployment docs | §2, §10, §11 |

---

## 14. Open questions — all resolved

Every question raised during review is answered in **§0**, including the two that
changed the plan: the app runs on this workstation (Q1), and RADIUS infrastructure
does not exist so #67 will be a labelled gap while AD (#66) is validated for real
(Q8).

Nothing is outstanding for implementation. New questions should be appended to §0 as
they arise, so that section stays the single record of agreed decisions.

---

## 15. Definition of Done — mapping to #51

- [x] Phase 4 component architecture documented — §2, §3
- [x] Authentication trust boundaries documented — §4, §5, §7.3
- [x] Accounting event model documented — §9
- [x] CLI break-glass model documented — §8
- [x] Phase 4 vs Phase 5 responsibility boundary documented — §11
- [x] Existing Phase 3 approval/authorization controls remain unchanged by design —
      §1, §7.2, §12 (regression)

All six DoD items for #51 are satisfied by this document, and the review decisions
that were blocking implementation are recorded in §0.

---

## 16. Implementation sequencing

Order is chosen so that each step is independently testable and nothing depends on
a layer that does not exist yet. Each step keeps the existing 387 tests green.

| Step | Issue | Why here |
|---|---|---|
| 0 | #64 (partial) | The interface split comes first, because it decides where `pentaia session` lives. Add `pentaia-admin` and gate the agent REPL behind `PENTAIA_CLI_ENABLED=false`. Small, and it must not break the current workflow. |
| 1 | #59 | The accounting event model and store exist before anything that emits events. SQLite repository + hash chain + redaction whitelist, tested standalone. |
| 2 | #52 | FastAPI skeleton, health/status, config loading, app lifecycle, and the import-boundary test that keeps `core/` free of web imports. |
| 3 | #54 | Identity model + secure server-side sessions on top of #59's store, with #58's controls folded in (cookie flags, CSRF, fixation, timeouts, throttling) since they are the same surface. |
| 4 | #55 + #57 | The AD LDAPS provider plus configuration-driven selection, validated at startup and failing closed. |
| 5 | #53 | GUI shell: login, conversation view, and the approval panel. Served as static assets by the app. |
| 6 | #61 | Conversation service: conversation ↔ thread mapping, ownership checks, per-conversation locking, accounting correlation. |
| 7 | #62 | The approval workflow wired into the GUI, reusing `approval.py` unchanged. The highest-risk step, so it lands after the plumbing it needs and gets its own adversarial tests. |
| 8 | #63 | Conversation history view, with the restart-durability limitation stated in the UI. |
| 9 | #65 | Minimal admin/status page: provider health, version, safe operational settings. |
| 10 | #56 | RADIUS provider, implemented per its issue and verified with mocked tests only (§12 gap). |
| 11 | #60 | Accounting viewer for the caller's own events; the all-users view stays break-glass. |
| 12 | #66 | AD end-to-end validation against the real domain controller (prerequisites in §12). |
| 13 | #68 | Full Phase 4 GUI, identity, accounting and approval validation, including the RADIUS gap statement. |
| 14 | #67 | **Not verifiable** — record the labelled gap rather than closing it. |
| 15 | #69 | Deployment, authentication, accounting and recovery documentation. |

Two sequencing notes: #58 is folded into step 3 rather than run separately, because
session hardening applied after the fact is how hardening gaps survive. And #67 is
listed last deliberately — it is the one issue in the set whose purpose is to be
*recorded as unverified*, not completed.

Working protocol for each step stays as before: one issue at a time, code plus
tests, handed over for the operator to test before moving on.
