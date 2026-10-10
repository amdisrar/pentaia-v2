# PentAiA v2

PentAiA v2 is an AI-assisted penetration-testing research and learning project built
with LangChain, LangGraph, Google Gemini, and a remote Kali Linux execution
environment. An LLM plans and interprets; a code-owned wrapper layer decides what is
actually allowed to run.

**Phases 1–3 are complete and verified end to end in an isolated private lab.**
Phase 4 is now in progress. The FastAPI web foundation (P4-02) and initial web GUI shell (P4-03) are complete; identity/session work continues in P4-04.

## Architecture

```text
User
  → CLI (approval pause / resume)
  → LangGraph
  → Gemini via LangChain
  → code-owned security tool wrapper
  → Kali SSH executor
  → authorized lab target
```

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | End-to-end Nmap demonstration | complete |
| 2 | Nuclei vulnerability discovery, conservative normalized findings | complete |
| 3 | Human-approved, controlled Metasploit validation with a held session | complete |
| 4 | Web GUI, identity, authentication, accounting, and recovery | in progress |

## Control and safety model

The model gets a typed, semantic tool interface. It never gets a shell.

1. Gemini has no unrestricted shell and no arbitrary Metasploit console.
2. Native command lines are constructed by Python wrappers, never by model text.
3. Model-visible parameters are typed and semantic. Runtime-owned parameters
   (callback address, listener port) and code-owned constants are not
   model-overridable, and an unexpected or missing tool argument is refused.
4. State-changing Phase 3 actions require explicit human approval, bound to a
   SHA-256 signature over the exact proposal. Approval is injected into the tool
   from graph state, never supplied by the model.
5. Any material change to target, action or parameters makes the approval stale.
6. Target authorization is checked before execution and re-checked at execution
   time. Protected and denied targets override the allowlist. Callback
   configuration that changed after approval makes the approval stale.
7. Tool results are normalized conservatively. Exit code 0 is never treated as
   proof of success, and blocked / inconclusive / error / failed outcomes stay
   distinct.
8. PentAiA never deletes anything on the target. The proof marker written by an
   approved action is evidence, and removing it is the operator's decision.
9. Credentials and secrets never enter graph state, browser output, audit records
   or logs.

## Verified Phase 3 flow

The full chain has been exercised live against Metasploitable in the lab:

```text
Nmap discovery (21/tcp vsftpd 2.3.4)
  → normalized finding maps to one supported candidate
  → exact proposal shown, signature dd423f92…  (parameters: lhost 172.16.0.13, lport 5000, rport 21)
  → human approves that exact signature
  → authorization re-checked, listener port re-validated
  → Metasploit exploit/unix/ftp/vsftpd_234_backdoor runs on Kali
  → reverse command shell caught and held in a detached tmux console
  → code-owned proof marker written on the target and read back to verify
  → operator takes the session over with tmux attach
```

Observed evidence: `[*] Command shell session 1 opened (172.16.0.13:5000 -> 172.16.0.64)`,
a root-owned verification marker on the target at
`/tmp/pentaia-poc-66d6db4c2ad8.txt` containing `PENTAIA: POC SUCCESSFUL`, and a
`phase3 event=result … outcome=success` audit record tied to the approved proposal
signature. The marker is deliberately left in place when the console closes.

## Layout

```text
src/pentaia/
  graph.py               LangGraph agent: state, approval gate, candidate lookup
  tools.py               read-only Nmap / Nuclei tool definitions
  discovery_profiles.py  typed scan profiles and parameter ownership
  nmap_wrapper.py        code-owned Nmap command construction
  nuclei_wrapper.py      code-owned Nuclei command construction
  findings.py            normalized finding model
  validation_mapping.py  supported finding → validation-action mapping
  approval.py            proposal, signature, approval state machine
  cli_approval.py        CLI approval pause / approve / reject
  authorization.py       target allowlist, denylist and protected-target policy
  runtime_config.py      runtime-owned callback address and port
  phase3_ports.py        listener-port reservation pool
  metasploit_wrapper.py  predefined operations, resource scripts, bounded execution
  phase3_session.py      held console lifecycle, metadata, handoff, close
  phase3_artifact.py     proof marker path, content and verified write
  phase3_audit.py        structured Phase 3 audit events
  phase3_results.py      conservative result normalization
  kali_executor.py       the single SSH execution path
  session_cli.py         `pentaia session list|show|attach|close`
```

Design documents live in `docs/`:

| Document | Document ID | Purpose |
| --- | --- | --- |
| `phase4-architecture.md` | PENTAIA-ARCH-P4-01 | Approved Phase 4 architecture for the web GUI, identity, sessions, accounting, approvals, and break-glass recovery |

The Phase 4 architecture is the current design contract for issues #52–#69. The independent DSH comparison draft used during architecture review was intentionally removed after its accepted decisions were merged into the master document.

## Phase 1 Setup and Reproduction

Phase 1 demonstrates the complete read-only path from an operator prompt to an Nmap scan executed on the dedicated Kali host.

### Prerequisites

- Linux/WSL development host with Python and `uv`
- reachable Kali Linux host with Nmap installed
- SSH key-based access from the PentAiA host to Kali
- Google Gemini API key
- an explicitly authorized lab target

### Kali SSH preparation

PentAiA uses the shared SSH executor for remote tool execution. Configure the Kali connection with placeholders in `.env`:

```text
KALI_HOST=<kali-ip-or-hostname>
KALI_PORT=22
KALI_USERNAME=<kali-user>
KALI_SSH_KEY=<path-to-private-key>
```

Before launching PentAiA, verify the same key works manually from the PentAiA host:

```bash
ssh -i <path-to-private-key> <kali-user>@<kali-ip-or-hostname>
```

The project does not require password-based SSH credentials to be stored in agent state or prompts.

### Phase 1 workflow

```text
User
  → CLI
  → LangGraph
  → Gemini via LangChain
  → Nmap tool definition
  → Nmap wrapper
  → Kali executor
  → SSH
  → Kali Linux
  → authorized lab target
```

The model selects a typed Nmap action; Python code constructs the native command and the shared Kali executor runs it remotely. The model never receives unrestricted shell access.

### Launch and reproduce

```bash
uv sync
uv run pentaia
```

Then request a read-only Nmap scan of an authorized lab target. For example:

```text
Run an Nmap service and version scan against the authorized lab target <target-ip>.
```

Expected Phase 1 behavior:

1. the CLI sends the request into the existing LangGraph workflow;
2. the Nmap semantic tool is selected;
3. the code-owned wrapper validates and constructs the command;
4. the Kali executor runs Nmap over SSH;
5. stdout/stderr/exit status return to PentAiA for interpretation.

### Phase 1 limitations

Phase 1 intentionally does not provide:

- arbitrary shell execution
- unrestricted user-supplied Nmap command lines
- Nuclei vulnerability discovery
- state-changing validation actions
- human approval workflow
- web GUI/authentication
- persistent cross-restart memory

Those capabilities and controls are introduced only in later phases and are documented separately.


## Configuration

Copy the keys you need into `.env` (loaded automatically):

| Variable | Purpose |
| --- | --- |
| `GOOGLE_API_KEY` | Gemini API access |
| `GEMINI_MODEL` | model name, defaults to `gemini-3.5-flash-lite` |
| `KALI_HOST`, `KALI_PORT`, `KALI_USERNAME`, `KALI_SSH_KEY` | Kali SSH execution host |
| `PENTAIA_LHOST`, `PENTAIA_LPORT` | runtime-owned callback address and port |
| `PENTAIA_LPORT_MIN`, `PENTAIA_LPORT_MAX` | approved listener-port pool |
| `PENTAIA_PHASE3_ALLOWLIST` | targets Phase 3 may touch |
| `PENTAIA_PHASE3_DENYLIST` | targets Phase 3 must never touch |
| `PENTAIA_NUCLEI_DENYLIST` | Nuclei template denylist |
| `PENTAIA_WEB_HOST`, `PENTAIA_WEB_PORT` | web application bind address (default `127.0.0.1:8000`) |
| `PENTAIA_WEB_DOCS` | enable `/docs` (default false) |
| `PENTAIA_AUTH_PROVIDER` | identity provider for the web application: `ad` or `radius`, blank for none |
| `PENTAIA_SESSION_IDLE_TIMEOUT` | idle session timeout in seconds, default `1800` |
| `PENTAIA_SESSION_ABSOLUTE_LIFETIME` | absolute session lifetime in seconds, default `43200` (never extended) |
| `PENTAIA_PUBLIC_ORIGIN` | origin this deployment is reachable at, e.g. `https://pentaia.example.test` |
| `PENTAIA_TRUSTED_PROXIES` | peers whose `X-Forwarded-For` is believed, default `127.0.0.1` |
| `PENTAIA_LOGIN_MAX_ATTEMPTS` | failed logins per username/address pair, default `5` |
| `PENTAIA_LOGIN_WINDOW_SECONDS` | throttling window in seconds, default `900` |
| `PENTAIA_LOGIN_MAX_KEYS` | upper bound on throttling state, default `10000` |
| `PENTAIA_AD_HOST` | Active Directory domain controller, bare host (required for AD) |
| `PENTAIA_AD_PORT` | LDAPS port, default `636` |
| `PENTAIA_AD_CA_FILE` | optional private CA bundle for LDAPS |
| `PENTAIA_AD_CONNECT_TIMEOUT` | LDAPS connect timeout in seconds, default `5` |
| `PENTAIA_AD_RECEIVE_TIMEOUT` | LDAPS read timeout in seconds, default `5` |

### Authentication provider selection

`PENTAIA_AUTH_PROVIDER` chooses the one identity provider a deployment authenticates
against. Phase 4 defines two:

| Value | State |
| --- | --- |
| `ad` | Active Directory over LDAPS, implemented and described below |
| `radius` | part of the Phase 4 contract, not implemented yet (issue #56) |

Leaving the setting unset, or blank, is valid and means **no provider**. The
application starts and `/healthz` answers, but nothing can authenticate: every `/api`
route refuses. That is not anonymous access, and it never becomes one.

Selection is validated and the provider is built **before the server binds**, so a
deployment cannot come up in a state it cannot honour:

- an unrecognised value (`ldap`, `ad,radius`, …) fails startup and names the variable;
- `radius` fails startup, naming issue #56 and the provider that is available instead;
- invalid provider settings (missing `PENTAIA_AD_HOST`, unusable CA bundle, …) fail
  startup as they already did.

There is **no fallback**. A configured provider is either built or the application
refuses to start, and a provider that fails is never replaced by another mechanism.

The active provider is visible to an authenticated operator on `/api/status` as
`authentication_provider` (`"ad"`, or `null` when none is selected) alongside
`authentication_ready`. Readiness is a construction fact, not a reachability check: the
directory is contacted when a credential is verified, not while the application starts.

`GET /healthz` stays a liveness probe and never reports on authentication. The login
route that turns a successful bind into a session is described under *Web sessions and
login* below.

### Web sessions and login

`POST /api/auth/login` accepts a JSON body containing only `username` and `password`,
authenticates them with the selected provider, and on success starts a server-side
session. There is no provider parameter, no role and no target in the request: a
browser cannot influence which backend authenticates it or what it is allowed to do.

Every other answer is deliberately uniform:

| Situation | Answer |
| --- | --- |
| Wrong password, unknown username | `401` with one fixed message |
| Provider unreachable, misconfigured, or none configured | `503` with one fixed message |
| Too many failures | `429` with `Retry-After` |

The two failure classes exist so an operator can tell a rejection from an outage; within
a class the response is byte-identical, so it can never be used to discover whether an
account exists, and no directory error, credential or username is ever echoed.

**Sessions.** After a successful login the browser holds a 256-bit opaque identifier in
an `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/` cookie with no `Domain` attribute. The
authoritative record is server-side, keyed by a SHA-256 digest of that identifier, so
the raw value is never stored. Records expire after 30 idle minutes (configurable) or 12
hours absolute (configurable, **never extended by activity**). Logout, expiry and
administrative invalidation (`invalidate_user`, used by `pentaia-admin` in P4-14) all
destroy the record, so a captured identifier stops working immediately.

**Fixation.** Login never adopts a client-supplied identifier. Whatever session the
presented cookie points to is destroyed on success and a new identifier — with a new
CSRF token — is issued. An identifier an attacker planted before authentication is dead
the moment the real user signs in. A *failed* login touches no session at all, so a
wrong password cannot disturb an existing one.

**CSRF.** Two mechanisms, one per state:

- Before authentication the token is **server-bound**: `GET /api/auth/csrf` issues a
  random 256-bit value and the server keeps a digest of it. `POST /api/auth/login`
  requires it in the `X-PentAiA-CSRF` header. A page on another origin can neither read
  the response that carries the token nor set that header, so it cannot force a victim's
  browser to sign in as somebody else.
- After authentication the authoritative token is the one inside the session record, and
  it is required on every state-changing request — including logout. The check is
  mounted on the routers and driven by the request method, so a future state-changing
  route cannot be added without it.

Tokens are compared in constant time, and missing, malformed and oversized values are
refused before any comparison. The browser keeps its token in memory only: never in
`localStorage`, `sessionStorage`, a cookie or a URL. A page reload loses it and recovers
it from `GET /api/auth/csrf`, which returns the session's own token.

The pre-authentication token is also bound to the client address it was issued to, so a
token that leaks by any other route is useless from anywhere else.

**Origin verification.** `PENTAIA_PUBLIC_ORIGIN` declares the origin this deployment is
reachable at. When it is set, a state-changing request carrying an `Origin` header must
match it exactly, scheme and port included, and `Sec-Fetch-Site: cross-site` is refused
outright. Nothing is inferred from `Host` and nothing is read from a forwarded header, so
a client cannot influence the comparison. With the setting unset only the host is
compared against the `Host` the request was addressed to — weaker, and visibly logged as
`public_origin=unset` at startup. In both modes the CSRF token remains the control that
actually authorises the request; origin checking is defence in depth.

**Login request size.** The one unauthenticated route that accepts a body is bounded by
the application at 64 KiB. A declared `Content-Length` over the limit is refused before a
byte is read, and the body is *also* counted as it streams, so omitting the header and
using chunked encoding does not bypass the bound. Both paths answer with the same generic
`413`. A proxy-level body limit remains worth configuring as defence in depth.

**Throttling.** Failures are counted per `(username, address)` pair — five in fifteen
minutes by default — with an aggregate allowance of four times that per address and per
username. A blocked pair never reaches the directory. Usernames are stored and logged
only as digests; a malformed or unknown username is counted exactly like a real one, so
the throttle is not an existence oracle. The state is bounded, and eviction may only
remove entries that are not currently blocking, so generating new keys cannot flush a
live lockout away.

**Client address behind the proxy.** The application disables uvicorn's own header
rewriting and resolves the client address itself. `X-Forwarded-For` is consulted **only**
when the TCP peer is listed in `PENTAIA_TRUSTED_PROXIES`, and then walked from the right,
so the address our own proxy appended is the one used and client-supplied entries to its
left are ignored. Header length and hop count are bounded, and only well-formed IP
addresses become throttle identities.

> **Deployment requirement.** The reverse proxy must **append** the address it observed
> (`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`) or **replace** the
> header with `$remote_addr`. A proxy that passes a client-supplied `X-Forwarded-For`
> through unchanged hands the client control of its own throttle bucket. Session cookies
> stay `Secure` in every configuration; there is no insecure-cookie development switch.

### Active Directory (LDAPS) authentication

Implemented in `src/pentaia/webapp/auth/`. Phase 4 uses a **direct-user bind**: the
supplied username and password are bound straight to Active Directory. No service
account, no directory search and no base DN are needed, so there is no filter to inject
into and no stored directory credential.

The username must be a **UPN**, `user@example.com`. PentAiA builds the canonical
identity from the username it was given, so accepting both the UPN and the down-level
`DOMAIN\user` form would give one AD principal two different identities
(`ad:user@example.com` and `ad:example\user`). The down-level form is therefore refused
rather than converted, because converting would mean guessing a UPN suffix — and
resolving it properly would require exactly the directory search this provider avoids.
A single-label suffix such as `user@example` is accepted; no dot is required.

Transport rules are deliberate and not configurable:

- **LDAPS only.** There is no plaintext `ldap://` path for password authentication.
- **Certificate validation is mandatory.** The chain *and* the server name are verified.
  There is no "ignore verification" mode, and setting an environment variable that
  implies one (`PENTAIA_AD_VERIFY_TLS`, `PENTAIA_AD_INSECURE`, …) is **refused** rather
  than ignored, so a deployment cannot believe a downgrade took effect.
- **System trust store by default.** `PENTAIA_AD_CA_FILE` points at a private CA bundle
  when the enterprise CA is not in the system store; the file must exist and be readable.
- **Bounded timeouts.** Every connect and read is bounded and validated at startup.
- **No directory read on connect**, and referrals are never followed.
- **No AD group or role mapping.** Phase 4 does not implement RBAC.

Authentication outcomes are normalized to `SUCCESS`, `REJECTED`, `UNAVAILABLE` or
`MISCONFIGURED`, and everything that is not an explicit success fails closed. A rejected
credential and an unknown user are indistinguishable to a caller. Passwords are used for
one bind and never stored, logged, returned or placed in session state.

Provider selection (`PENTAIA_AUTH_PROVIDER`) and the login flow are separate concerns,
described above and below: this provider knows nothing about which backend a deployment
chose, and nothing about sessions. It is exercised through its own interface, through
the login route, and through `scripts/ad_ldaps_check.py`.

#### Optional real-Active-Directory validation

The normal test suite is offline and needs no domain controller. Against a real Windows
Server with AD DS and LDAPS on 636:

```bash
# 1. valid UPN + valid password, and 2. wrong password, and 3. unknown user
PENTAIA_AD_HOST=dc01.example.test \
PENTAIA_AD_CA_FILE=/etc/ssl/certs/enterprise-ca.pem \
uv run python scripts/ad_ldaps_check.py --attempts 3
# expect outcome=success with canonical identity ad:user@example.test,
# then outcome=rejected for the wrong password and for the unknown user

# 4. unreachable DC -> outcome=unavailable (exit code 2)
PENTAIA_AD_HOST=192.0.2.1 PENTAIA_AD_CONNECT_TIMEOUT=2 \
uv run python scripts/ad_ldaps_check.py --username user@example.test

# 5. untrusted CA -> outcome=misconfigured (exit code 3): omit PENTAIA_AD_CA_FILE
PENTAIA_AD_HOST=dc01.example.test uv run python scripts/ad_ldaps_check.py

# 6. trusted private CA -> outcome=success: set PENTAIA_AD_CA_FILE as in step 1
# 7. hostname/certificate mismatch -> outcome=misconfigured: point PENTAIA_AD_HOST at
#    an address whose certificate does not carry that name
# 8. timeout behaviour: set PENTAIA_AD_CONNECT_TIMEOUT=1 against a blackholed address

# 9. confirm the canonical identity is ad:user@example.test
```

The script reads the password from the terminal without echo, never from the command
line. Use placeholder values only: no real domain, username, password or CA material
belongs in the repository or in `.env.example`.

## Running

Current local interfaces:

```bash
uv run pentaia                    # interactive agent CLI
uv run pentaia session list       # held Phase 3 consoles
uv run python -m pentaia.webapp   # Phase 4 FastAPI web application
```

The Phase 4 GUI currently provides the shell only; enterprise authentication, real web sessions, conversations, accounting, and approval integration are delivered by later Phase 4 issues.

A typical Phase 3 prompt:

```text
Run the full Phase 3 validation test against the authorized lab target 172.16.0.64.
First run an Nmap service and version scan of that target, then use those results to
run the supported Phase 3 validation action for the vsftpd 2.3.4 backdoor.
```

PentAiA pauses on the exact proposal and prompts `Approve this exact action? [y/N]`;
only `y` or `yes` approves. Type or paste only at the prompt — the CLI redraws a
progress spinner while the agent works, and keystrokes typed during that window are
buffered into the next prompt.

Consoles are held in tmux on the Kali host and managed with:

```bash
uv run pentaia session list
uv run pentaia session show <name>
uv run pentaia session attach <name>   # prints the tmux attach command
uv run pentaia session close <name>    # stops the console, leaves the marker
```

## Testing

```bash
uv run pytest tests -q
uv run ruff check src tests
```

Do **not** run a bare `uv run pytest` from the repository root: `src/pentaia/test_*.py`
are exploratory scripts whose module-level code performs live Gemini calls and SSH to
Kali. Always scope to `tests/`.

After `git pull`, restart the agent. `uv run pentaia` is a long-running REPL that
loads the package once, so a pull does not change the code a running agent executes,
while `pentaia session …` is a new process each time.

## Documentation Roadmap

This README is the operational entry point for the repository and records enough architecture, setup, usage, and current limitations for a new developer to reproduce the completed phases.

As the project matures, a consolidated **Solution Definition / Solution Design Document** should capture the full end-to-end product view in one place, including business/technical objectives, requirements, assumptions, architecture, trust boundaries, interfaces, deployment, data flows, security controls, operational model, validation, and known limitations.

The phase-specific architecture documents remain the detailed design records for their respective implementation stages.


## Authorized use only

PentAiA is built for an isolated lab against explicitly allowlisted targets. It
performs no exploitation outside a supported, code-owned action that a human
approved by signature, and it refuses to touch protected or denied infrastructure.
