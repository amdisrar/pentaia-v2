# PentAiA v2 — Phase 4 Web, Identity, Accounting, and CLI Security Architecture

## Document Control

| Field | Value |
|---|---|
| Document Title | PentAiA v2 — Phase 4 Web, Identity, Accounting, and CLI Security Architecture |
| Document ID | PENTAIA-ARCH-P4-01 |
| Version | 0.1 |
| Status | Draft |
| Project | PentAiA v2 |
| Repository | `amdisrar/pentaia-v2` |
| Related GitHub Issue | #51 — P4-01 Define Phase 4 web, identity, accounting, and CLI security architecture |
| Owner | Israr |
| Prepared Date | 24 September 2026 |
| Classification | Project Internal / Educational Research |
| Review Requirement | Owner review required before P4-01 is closed |

## Document History

| Version | Date | Author | Change Summary | Status |
|---|---|---|---|---|
| 0.1 | 24 September 2026 | PentAiA project / AI-assisted draft | Initial Phase 4 architecture covering web, identity, sessions, accounting, approvals, secrets, break-glass, Phase 3 compatibility, and implementation mapping | Draft |

## Table of Contents

1. [Purpose](#1-purpose)
2. [Project Context and Safety Boundary](#2-project-context-and-safety-boundary)
3. [Scope](#3-scope)
4. [Non-Goals](#4-non-goals)
5. [Existing Phase 1–3 Baseline](#5-existing-phase-13-baseline)
6. [Phase 4 Architecture Principles](#6-phase-4-architecture-principles)
7. [Target Component Architecture](#7-target-component-architecture)
8. [Component Responsibilities](#8-component-responsibilities)
9. [Trust Boundaries](#9-trust-boundaries)
10. [Authentication Architecture](#10-authentication-architecture)
11. [Authenticated Identity Model](#11-authenticated-identity-model)
12. [Web Session Model](#12-web-session-model)
13. [Conversation and LangGraph Session Model](#13-conversation-and-langgraph-session-model)
14. [Human Approval Workflow in the Web GUI](#14-human-approval-workflow-in-the-web-gui)
15. [Target Authorization and Existing Phase 3 Controls](#15-target-authorization-and-existing-phase-3-controls)
16. [Accounting and Audit Architecture](#16-accounting-and-audit-architecture)
17. [Secret and Configuration Ownership](#17-secret-and-configuration-ownership)
18. [Local Break-Glass and Recovery CLI](#18-local-break-glass-and-recovery-cli)
19. [Administrative and Operational Status Functions](#19-administrative-and-operational-status-functions)
20. [Failure and Recovery Scenarios](#20-failure-and-recovery-scenarios)
21. [Phase 4 vs Later-Phase Responsibility Boundary](#21-phase-4-vs-later-phase-responsibility-boundary)
22. [Deployment and Network Security Assumptions](#22-deployment-and-network-security-assumptions)
23. [Implementation Mapping to Phase 4 Issues](#23-implementation-mapping-to-phase-4-issues)
24. [Acceptance Criteria for P4-01](#24-acceptance-criteria-for-p4-01)
25. [Open Design Questions](#25-open-design-questions)
26. [Summary](#26-summary)

---

## 1. Purpose

This document defines the Phase 4 architecture for PentAiA v2.

Phase 4 introduces a normal browser-based operational interface, a FastAPI application layer, enterprise authentication, secure web sessions, authenticated conversation ownership, application accounting and audit visibility, and a local recovery path.

The primary architectural goal is to add these capabilities **without changing or weakening the execution-control model proven in Phases 1–3**.

Phase 4 must therefore be treated as an application and identity layer around the existing PentAiA engine rather than as a replacement for it.

The design established in this document will act as the implementation contract for Phase 4 issues P4-02 through P4-19.

---

## 2. Project Context and Safety Boundary

PentAiA v2 is an educational and research project for learning AI-agent engineering, security validation workflow design, security tooling integration, identity architecture, and controlled human-in-the-loop operation.

All active security testing is performed only in a controlled personal lab against deliberately vulnerable systems owned by, or explicitly authorized for use by, the project owner.

The project is not designed for unauthorized testing of third-party infrastructure.

The intended external cybersecurity impact is zero. The project retains explicit target authorization, code-owned execution, human approval, deterministic validation mappings, constrained tool access, and truthful audit records specifically to prevent uncontrolled or unintended actions.

Representative lab components include:

- PentAiA development/orchestration environment
- Kali Linux execution host
- Metasploitable2
- Mutillidae
- explicitly authorized lab targets only

Phase 4 does not change this safety boundary.

---

## 3. Scope

P4-01 defines the architecture for the following Phase 4 capabilities:

- Browser-based PentAiA GUI
- FastAPI backend
- enterprise authentication
- Active Directory authentication over LDAPS
- RADIUS authentication
- configurable authentication provider selection
- authenticated web sessions
- authenticated user identity
- authenticated conversation ownership
- integration of web conversations with LangGraph thread/session state
- web presentation of pending Phase 3 approval
- approval and rejection through authenticated server-side actions
- application accounting
- application audit visibility
- local recovery and break-glass administration
- minimal operational configuration/status functions
- secret/configuration ownership
- preservation of existing Phase 3 authorization and execution controls

---

## 4. Non-Goals

The following are explicitly outside the scope of P4-01 and should not be accidentally implemented as part of the architecture issue:

- implementing FastAPI code
- implementing the frontend
- implementing LDAPS or RADIUS code
- implementing full application RBAC
- implementing a complete settings portal
- implementing persistent agent memory
- changing Phase 3 target authorization behavior
- changing the Phase 3 approval signature model
- adding arbitrary shell access
- adding unrestricted Metasploit execution
- exposing Kali directly to the browser
- allowing the browser or model to construct native security commands
- allowing browser requests to bypass LangGraph or the existing controlled wrappers
- adding remote network access to the break-glass CLI
- storing user passwords or enterprise credentials
- placing secrets in graph state or model context

---

## 5. Existing Phase 1–3 Baseline

Phase 4 must build on the existing verified architecture.

Current baseline:

```text
User
  |
  v
CLI
  |
  v
LangGraph
  |
  v
Gemini via LangChain
  |
  v
Typed semantic tools
  |
  v
Code-owned Python wrappers
  |
  v
Single Kali SSH executor
  |
  v
Authorized lab target
```

The current implementation already includes:

- Nmap discovery
- Nuclei vulnerability discovery
- normalized findings
- deterministic supported-candidate mapping
- code-owned Metasploit operations
- target allowlist/denylist/protected-target controls
- runtime-owned callback/listener configuration
- exact Phase 3 action proposals
- SHA-256 proposal signatures
- human approval and rejection
- stale-approval detection
- execution-time authorization re-checks
- conservative result normalization
- structured Phase 3 audit events
- held validation sessions
- proof/evidence artifact verification
- explicit operator session handoff

### 5.1 Existing Trusted Execution Components

The following modules are part of the existing security-control layer and should remain authoritative in Phase 4:

```text
authorization.py
approval.py
graph.py
metasploit_wrapper.py
nmap_wrapper.py
nuclei_wrapper.py
phase3_audit.py
phase3_artifact.py
phase3_ports.py
phase3_results.py
phase3_session.py
runtime_config.py
kali_executor.py
```

### 5.2 Core Existing Invariants

Phase 4 must preserve all of these:

1. Gemini does not receive unrestricted shell access.
2. Python constructs native commands.
3. Runtime-owned and code-owned parameters cannot be overridden by the model.
4. State-changing Phase 3 actions require explicit human approval.
5. Approval is bound to the exact proposal signature.
6. Any material proposal change makes prior approval stale.
7. Target authorization is checked before execution and rechecked at execution time.
8. Deny/protected rules override allow rules.
9. Exit code alone is never treated as proof of validation success.
10. Secrets do not enter model conversation state, normal logs, audit records, or browser output.
11. Human session handoff is explicit.
12. Once handed off, operator activity must not be misrepresented as PentAiA activity.

---

## 6. Phase 4 Architecture Principles

### 6.1 Add an Interface, Do Not Add an Execution Path

FastAPI and the web GUI are presentation/application layers.

They must not create a second direct route to Kali.

Correct:

```text
Browser
   |
   v
FastAPI
   |
   v
PentAiA application/service boundary
   |
   v
LangGraph
   |
   v
Existing controlled wrappers
   |
   v
kali_executor.py
```

Incorrect:

```text
Browser
   |
   v
FastAPI
   |
   +------> direct SSH to Kali
   |
   +------> direct subprocess security commands
```

### 6.2 Server Owns Security State

The browser may display state, but must not be trusted to define it.

Server-owned items include:

- authenticated identity
- session state
- conversation ownership
- LangGraph thread identifiers
- pending approval state
- exact proposal data
- proposal signature
- target authorization decision
- runtime configuration
- audit/accounting records

### 6.3 Browser Input Is Untrusted

All browser input must be validated by FastAPI/application logic before it reaches PentAiA.

The browser must never be trusted to send:

- an authoritative username
- an authoritative role
- an approval object
- an approval signature to be accepted without server comparison
- an arbitrary command
- a module path
- a callback/listener address
- privileged runtime settings

### 6.4 Authentication Is Separate from Security-Target Authorization

User authentication answers:

```text
Who is using PentAiA?
```

Existing target authorization answers:

```text
Is PentAiA allowed to interact with this target?
```

These controls serve different purposes and must remain separate.

---

## 7. Target Component Architecture

### 7.1 High-Level Architecture

```text
                         +-----------------------+
                         |        Browser        |
                         |       Web GUI         |
                         +-----------+-----------+
                                     |
                                   HTTPS
                                     |
                                     v
                         +-----------------------+
                         |       FastAPI         |
                         |  Application Layer    |
                         +-----------+-----------+
                                     |
              +----------------------+----------------------+
              |                      |                      |
              v                      v                      v
     +----------------+     +----------------+     +----------------+
     | Authentication |     | Web Session /  |     | Accounting /   |
     |     Layer      |     | Conversation   |     | Audit Layer    |
     +-------+--------+     +--------+-------+     +----------------+
             |                       |
       +-----+-----+                 |
       |           |                 |
       v           v                 v
  +---------+ +---------+   +---------------------+
  | AD/LDAPS| | RADIUS  |   | Existing LangGraph |
  +---------+ +---------+   |   PentAiA Engine   |
                             +----------+----------+
                                        |
                                 Existing Phase 1-3
                                        |
                    +-------------------+-------------------+
                    |                   |                   |
                    v                   v                   v
                  Nmap                Nuclei          Phase 3 tools
                                                            |
                                                            v
                                                     Metasploit wrapper
                                                            |
                                                            v
                                                   kali_executor.py
                                                            |
                                                            v
                                                        Kali Linux
                                                            |
                                                            v
                                                Authorized lab targets
```

### 7.2 Administrative Recovery Path

```text
Administrator
      |
      v
Local console / SSH to PentAiA server
      |
      v
Operating-system authenticated access
      |
      v
pentaia-admin
      |
      v
Local recovery/status operations
```

The recovery path must not depend on AD or RADIUS availability.

It must not become a network-facing PentAiA login service.

---

## 8. Component Responsibilities

## 8.1 Browser / Web GUI

Responsibilities:

- render login interface
- render conversations
- send user prompts
- render tool status and normalized results
- display exact pending approvals
- submit approve/reject intent
- display conversation history
- display permitted audit/accounting data
- display session visibility/status
- maintain normal browser-side UX state

The browser does not own authoritative security state.

## 8.2 FastAPI Application Layer

Responsibilities:

- HTTP API
- authentication orchestration
- web session handling
- CSRF protection
- server-side identity
- conversation ownership enforcement
- request validation
- integration with LangGraph
- pending approval retrieval
- authenticated approval/rejection actions
- accounting event generation
- safe response shaping
- operational status endpoints

FastAPI must not construct arbitrary native tool commands.

## 8.3 Authentication Provider Layer

Responsibilities:

- expose a common application authentication interface
- isolate provider-specific behavior
- normalize successful identity output
- normalize authentication failure
- prevent raw credentials from escaping authentication scope

Proposed conceptual interface:

```python
class AuthenticationProvider:
    def authenticate(self, username: str, password: str) -> AuthenticatedUser:
        ...
```

The exact Python interface will be defined during implementation.

## 8.4 LangGraph / PentAiA Engine

Responsibilities remain largely unchanged:

- agent workflow
- model interaction
- typed tool selection
- deterministic candidate context
- pending Phase 3 approval state
- stale approval checks
- routing
- controlled tool execution

Phase 4 may add server-managed metadata around conversations, but should avoid inserting secrets or unnecessary identity data into model-visible message state.

## 8.5 Existing Wrapper and Executor Layer

Remains authoritative for:

- native command construction
- target validation
- predefined Metasploit operations
- runtime parameter ownership
- Kali execution

## 8.6 Accounting/Audit Layer

Responsibilities:

- immutable or append-oriented application event records
- authenticated actor association
- event timestamps
- conversation/session correlation
- proposal/approval correlation
- security-relevant failure records
- operator-visible audit views where appropriate

---

## 9. Trust Boundaries

### 9.1 Trust Boundary A — Browser to FastAPI

The browser is untrusted.

Controls should include:

- HTTPS
- secure session cookies
- server-side identity
- CSRF protection for state-changing browser requests
- request validation
- origin/host controls as appropriate
- no trust in browser-supplied authorization metadata

### 9.2 Trust Boundary B — FastAPI to Authentication Provider

Credentials exist only long enough to authenticate.

Requirements:

- LDAPS for Active Directory
- protected RADIUS shared secret
- no credential logging
- no password persistence
- no password insertion into audit records
- no credential insertion into LangGraph state
- normalized identity returned to the application after successful authentication

### 9.3 Trust Boundary C — FastAPI to PentAiA/LangGraph

FastAPI may submit authenticated user prompts and resume server-owned workflow state.

Requirements:

- conversation belongs to authenticated user
- thread ID is server-owned
- pending approval belongs to the same server-side conversation
- approval decision is associated with the authenticated actor
- browser cannot replace the proposal

### 9.4 Trust Boundary D — PentAiA to Kali

Existing Phase 1–3 boundary remains.

Requirements:

- existing SSH executor
- code-owned commands
- configured key/credentials
- no direct browser-to-Kali access
- no direct model-to-Kali shell

### 9.5 Trust Boundary E — Kali to Authorized Target

Existing target authorization remains authoritative.

The introduction of web users must not imply that an authenticated user can target arbitrary addresses.

---

## 10. Authentication Architecture

Phase 4 supports two enterprise authentication backends:

- Active Directory over LDAPS
- RADIUS

A provider abstraction should prevent the rest of the application from depending on provider-specific behavior.

### 10.1 Provider Selection

Conceptual configuration:

```text
PENTAIA_AUTH_PROVIDER=ldap
```

or:

```text
PENTAIA_AUTH_PROVIDER=radius
```

Only configured providers should be initialized.

Unsupported values must fail closed at application startup.

### 10.2 Active Directory / LDAPS

Expected flow:

```text
Browser
   |
   | username + password over HTTPS
   v
FastAPI
   |
   v
LDAP authentication provider
   |
   | LDAPS
   v
Active Directory
   |
   v
success / failure + normalized identity
```

Requirements:

- LDAPS only for password authentication
- certificate validation
- configurable server/base DN/search behavior
- safe failure messages
- passwords never stored
- credentials never logged
- group/role retrieval may be collected only if required by later authorization design; Phase 4 must not accidentally implement an undocumented RBAC policy

### 10.3 RADIUS

Expected flow:

```text
Browser
   |
   | username + password over HTTPS
   v
FastAPI
   |
   v
RADIUS authentication provider
   |
   v
RADIUS server
   |
   v
Access-Accept / Access-Reject
```

Requirements:

- RADIUS shared secret is application secret configuration
- shared secret never exposed to the model/browser
- password is transient
- provider response normalized to the PentAiA identity model

### 10.4 Authentication Failure

Authentication failures must:

- create a safe accounting event
- avoid recording passwords
- avoid leaking whether sensitive directory attributes exist
- not create an authenticated web session
- not create a LangGraph conversation

---

## 11. Authenticated Identity Model

Phase 4 requires a stable internal application identity independent of the authentication backend.

Proposed logical model:

```text
AuthenticatedUser
  user_id
  username
  display_name
  provider
  provider_subject
  authenticated_at
```

### 11.1 Internal User ID

PentAiA should use a server-owned internal identifier for database/session ownership.

The provider username should not be the only database key.

### 11.2 Provider Identity

Examples:

```text
provider = "ldap"
provider_subject = directory identity reference

provider = "radius"
provider_subject = normalized authenticated username/reference
```

### 11.3 Identity and the Model

The model generally does not need authentication credentials.

If user identity is needed for natural-language context, only the minimum safe display identity should be provided.

Secrets and authentication tokens must never enter model context.

---

## 12. Web Session Model

After successful authentication, the application creates an authenticated web session.

Logical relationship:

```text
Authenticated User
       |
       +---- Web Session
       |        |
       |        +---- Browser
       |
       +---- Conversation A
       +---- Conversation B
       +---- Conversation C
```

Recommended server-owned fields:

```text
web_session_id
user_id
created_at
last_activity_at
expires_at
authentication_provider
authentication_time
```

### 12.1 Cookie Requirements

The implementation should use secure cookie behavior suitable for the deployment model, including:

- HttpOnly
- Secure when HTTPS is used
- appropriate SameSite policy
- opaque session identifier
- no credentials in cookies
- no raw provider password/token in cookies

### 12.2 Session Expiration

Phase 4 implementation should support:

- inactivity timeout
- absolute lifetime where appropriate
- explicit logout
- server-side invalidation
- regeneration after login to prevent fixation

Exact timeout values belong in implementation/configuration issues, not P4-01.

### 12.3 Session Revocation

A revoked or expired session must no longer be allowed to:

- send prompts
- view conversations
- approve pending actions
- inspect protected audit information

---

## 13. Conversation and LangGraph Session Model

The current CLI uses a LangGraph thread identifier owned by the CLI process.

Phase 4 needs explicit ownership metadata.

Proposed model:

```text
user_id
   |
   +---- web_session_id
   |
   +---- conversation_id
             |
             +---- langgraph_thread_id
```

### 13.1 Server-Owned IDs

The following must be server generated/owned:

- conversation ID
- LangGraph thread ID
- pending approval ID/reference
- web session ID

The model must not control these identifiers.

### 13.2 Conversation Ownership

Every read/write operation must verify:

```text
conversation.user_id == authenticated_user.user_id
```

unless a future explicitly designed administrative authorization model permits otherwise.

### 13.3 Phase 4 Persistence

P4-13 includes authenticated conversation history/session visibility.

This requires Phase 4 application persistence for conversation metadata and history visibility.

This is distinct from **agent long-term memory**.

Long-term semantic memory across unrelated sessions is not introduced by P4-01.

---

## 14. Human Approval Workflow in the Web GUI

Phase 4 must reuse the existing Phase 3 approval model.

Existing authoritative components include:

- `Phase3ActionProposal`
- `Phase3ApprovalState`
- proposal SHA-256 signature
- `approve_phase3_action()`
- `reject_phase3_action()`
- stale approval detection

### 14.1 Approval Presentation Flow

```text
LangGraph
    |
    v
pending Phase3ApprovalState
    |
    v
FastAPI reads server-side pending approval
    |
    v
Web GUI renders exact proposal
    |
    +---------- Reject
    |
    +---------- Approve
```

The GUI should display the material proposal fields already produced by the server, including:

- action ID
- target
- rationale
- expected effect
- resolved material parameters
- proposal signature
- relevant evidence/artifact note

### 14.2 Approval Submission Flow

Conceptual flow:

```text
Authenticated browser
       |
       | POST approve
       v
FastAPI
       |
       +--> verify authenticated session
       |
       +--> load server-side conversation
       |
       +--> load server-side pending approval
       |
       +--> confirm request refers to current pending proposal
       |
       +--> call existing approval logic
       |
       +--> write accounting/audit event with actor
       |
       +--> resume LangGraph
```

### 14.3 Approval Security Rules

The browser must not be able to:

- create a new proposal
- modify target
- modify action ID
- modify runtime parameters
- replace the server proposal signature
- approve a proposal belonging to another user/conversation
- reuse an approval after the proposal changes

### 14.4 Concurrent/Stale Approval

If a proposal has changed or already been resolved, the server must reject the browser approval attempt as stale/conflicting.

Phase 3 stale-signature behavior remains authoritative.

---

## 15. Target Authorization and Existing Phase 3 Controls

Phase 4 authentication does not replace target authorization.

Example:

```text
User successfully authenticates
        |
        v
User asks PentAiA to assess target X
        |
        v
Existing target authorization
        |
        +---- allowed --> normal controlled flow
        |
        +---- denied --> blocked
```

An authenticated user does not automatically obtain permission to operate against arbitrary infrastructure.

Existing configuration remains authoritative:

- Phase 3 allowlist
- Phase 3 denylist
- protected targets
- runtime callback configuration
- Nuclei template restrictions

Any future per-user target authorization policy must be explicitly designed rather than inferred from authentication.

---

## 16. Accounting and Audit Architecture

Phase 4 adds application-level accounting tied to authenticated identity.

This complements, rather than replaces, current Phase 3 audit events.

### 16.1 Goals

Accounting should answer:

- who logged in
- when authentication succeeded or failed
- which user created a conversation
- which authenticated user submitted a prompt
- which tool/action lifecycle events occurred
- who approved or rejected a state-changing action
- which proposal signature was involved
- which target was involved
- when a session was handed off
- when application sessions ended or expired

### 16.2 Proposed Event Categories

Authentication:

```text
LOGIN_SUCCESS
LOGIN_FAILURE
LOGOUT
WEB_SESSION_CREATED
WEB_SESSION_EXPIRED
WEB_SESSION_REVOKED
```

Conversation:

```text
CONVERSATION_CREATED
CONVERSATION_OPENED
PROMPT_SUBMITTED
CONVERSATION_CLOSED
```

Security workflow:

```text
TOOL_REQUESTED
TOOL_COMPLETED
PROPOSAL_CREATED
APPROVAL_APPROVED
APPROVAL_REJECTED
APPROVAL_STALE
VALIDATION_STARTED
VALIDATION_COMPLETED
SESSION_HELD
SESSION_HANDOFF
SESSION_CLOSED
```

Administration:

```text
AUTH_PROVIDER_STATUS_CHECK
BREAK_GLASS_USED
RECOVERY_ACTION
OPERATIONAL_SETTING_CHANGED
```

The final event set should be implemented incrementally and kept purposeful.

### 16.3 Proposed Event Model

Logical fields:

```text
event_id
timestamp
event_type
user_id
username/display reference
authentication_provider
web_session_id
conversation_id
langgraph_thread_id
action_id
target
proposal_signature
outcome/status
correlation_id
safe_details
```

Not every event needs every field.

### 16.4 Prohibited Audit Content

Never record:

- passwords
- LDAP bind passwords
- RADIUS shared secrets
- API keys
- SSH private keys
- raw session cookies
- authentication tokens
- arbitrary sensitive environment variables

Existing Phase 3 behavior of storing a stable reference rather than raw evidence text should continue where appropriate.

### 16.5 Audit Truthfulness

Audit records must distinguish:

- model recommendation
- PentAiA proposal
- human approval
- PentAiA execution
- observed evidence
- human session handoff
- human-controlled activity after handoff

PentAiA must not claim ownership of operator actions after explicit handoff.

---

## 17. Secret and Configuration Ownership

Phase 4 should continue the project's parameter-ownership philosophy.

### 17.1 Application-Owned Configuration

Examples:

```text
AUTH_PROVIDER
DATABASE_URL
SESSION_SECRET / session signing or encryption material
cookie/security configuration
audit destination
application host/port configuration
```

### 17.2 Authentication Infrastructure Secrets

Examples:

```text
LDAP server configuration
LDAP bind identity
LDAP bind password
RADIUS server
RADIUS shared secret
CA/certificate trust configuration
```

### 17.3 Existing PentAiA Runtime Configuration

Examples:

```text
GOOGLE_API_KEY
GEMINI_MODEL
KALI_HOST
KALI_PORT
KALI_USERNAME
KALI_SSH_KEY
PENTAIA_LHOST
PENTAIA_LPORT
PENTAIA_LPORT_MIN
PENTAIA_LPORT_MAX
PENTAIA_PHASE3_ALLOWLIST
PENTAIA_PHASE3_DENYLIST
PENTAIA_NUCLEI_DENYLIST
```

### 17.4 Secret Flow Rule

Secrets may be consumed only by the component that requires them.

They must not be copied into:

- user prompts
- AI messages
- LangGraph model-visible messages
- normal browser responses
- audit records
- Git commits

### 17.5 Configuration Validation

Invalid security-sensitive configuration should fail closed at application startup where practical.

Examples:

- unknown authentication provider
- insecure LDAP configuration when LDAPS is required
- missing required RADIUS secret
- missing session secret
- invalid target authorization configuration

---

## 18. Local Break-Glass and Recovery CLI

Phase 4 retains a local administrative path for recovery when the normal web or enterprise authentication path is unavailable.

### 18.1 Intended Use

Examples:

- AD unavailable
- RADIUS unavailable
- authentication misconfiguration
- web session subsystem failure
- need to inspect service status
- emergency recovery/configuration correction

### 18.2 Trust Model

Break-glass access is based on access to the PentAiA host itself.

```text
Administrator
      |
      v
OS-authenticated local/SSH access
      |
      v
pentaia-admin
```

Therefore:

- it is not exposed as a public HTTP login mechanism
- it does not depend on AD/RADIUS
- it does not implement another remote password database
- host access controls protect it

### 18.3 Disabled by Default for Normal Operation

Normal users should use the GUI.

Break-glass functions should require explicit local administrative invocation.

### 18.4 Audit

Break-glass use should generate an accounting/audit event where the application/audit subsystem is available.

The event should state that local recovery was used.

### 18.5 Scope Limitation

The break-glass utility is for recovery/administration.

It must not become a shortcut that bypasses existing Phase 3 target authorization or approval controls for normal security validation.

---

## 19. Administrative and Operational Status Functions

Phase 4 requires only minimal status/configuration functions needed for safe operation.

Possible read-only status items:

- current authentication provider
- authentication backend reachability
- database status
- LangGraph/application status
- Kali execution-host reachability
- audit subsystem status
- configured model name
- listener pool status
- held session count

Sensitive values must not be displayed.

Examples of values that should never be rendered:

- LDAP password
- RADIUS secret
- API keys
- SSH private key contents
- raw session secret

A full settings/admin portal is not part of P4-01.

---

## 20. Failure and Recovery Scenarios

### 20.1 Active Directory Unavailable

Expected behavior:

- LDAP login fails safely
- no authenticated web session is created
- safe accounting event generated
- existing authenticated sessions follow configured session policy
- local break-glass remains available to host administrators

### 20.2 RADIUS Unavailable

Expected behavior mirrors AD failure:

- login fails safely
- credentials are not logged
- no fallback to an insecure local web password
- break-glass remains local to the host

### 20.3 Authentication Succeeds but PentAiA Engine Is Unavailable

Expected behavior:

- user remains authenticated
- GUI reports application engine unavailable
- no direct fallback to Kali
- accounting records operational failure

### 20.4 Kali Unavailable

Expected behavior:

- existing executor returns unavailable/failure status
- FastAPI does not bypass the executor
- GUI shows safe normalized error
- no secret/SSH details exposed

### 20.5 Browser Submits Approval After Proposal Changed

Expected behavior:

- approval refused as stale
- nothing executes
- user sees that the approval is no longer current
- audit/accounting records stale attempt as appropriate

### 20.6 Browser Session Expires While Approval Is Pending

Expected behavior:

- approval cannot be completed without an authenticated session
- pending action remains unexecuted
- reauthentication does not silently approve it
- server decides whether the pending proposal remains viewable/current after reauthentication

### 20.7 Database or Accounting Store Unavailable

The implementation must define fail behavior before Phase 4 production use.

For security-significant operations such as approval, the project should prefer fail-closed behavior if required audit/accounting guarantees cannot be met.

This decision should be finalized during P4-09/P4-12 implementation design.

### 20.8 Web Application Compromise Assumption

FastAPI is a trusted application component; therefore it must be treated as a critical security boundary.

Even so, defense in depth remains:

- Phase 3 target authorization remains in the execution layer
- code-owned wrapper constraints remain
- runtime-owned values remain protected
- approval signature checking remains in shared application logic

---

## 21. Phase 4 vs Later-Phase Responsibility Boundary

The current issue states that Phase 4 implements authentication and accounting while full application RBAC/authorization is deferred.

The project backlog also currently uses Phase 5 for persistent memory.

This creates a naming/roadmap ambiguity that should be cleaned up before later implementation, but it does not block P4-01.

### 21.1 Phase 4 Responsibilities

Phase 4:

- GUI
- FastAPI
- enterprise authentication
- authenticated identity
- secure web sessions
- conversation ownership
- application accounting/audit
- web approval integration
- session visibility
- local recovery utility
- minimal operational status/configuration

### 21.2 Not Phase 4

Deferred unless explicitly re-planned:

- full application RBAC
- complex multi-role policy
- per-user target entitlement policy
- full settings/admin portal
- long-term semantic/persistent AI memory
- advanced multi-tenant isolation
- arbitrary provider/plugin marketplace

### 21.3 Existing Target Authorization Remains

Even before application RBAC exists, Phase 3 target authorization remains mandatory and unchanged.

---

## 22. Deployment and Network Security Assumptions

P4-01 does not finalize deployment packaging, but Phase 4 architecture assumes:

- the browser reaches PentAiA over HTTPS
- the FastAPI service is not used as a direct Kali proxy
- Kali remains on a controlled network path
- enterprise authentication traffic follows controlled network paths
- LDAPS certificate validation is enforced
- RADIUS shared secrets are protected
- application secrets are stored outside source control
- production debug output is disabled
- session cookies are protected
- host access to the break-glass utility is restricted
- database/audit storage access is restricted to required components

Detailed deployment instructions are planned for P4-19.

---

## 23. Implementation Mapping to Phase 4 Issues

The P4-01 architecture maps to the current backlog as follows.

| Issue | Implementation Area | Architecture Dependency |
|---|---|---|
| P4-01 / #51 | Architecture | This document |
| P4-02 / #52 | FastAPI backend | Sections 6–9 |
| P4-03 / #53 | Web GUI shell | Sections 7–8 |
| P4-04 / #54 | Identity/session model | Sections 11–12 |
| P4-05 / #55 | AD over LDAPS | Section 10.2 |
| P4-06 / #56 | RADIUS | Section 10.3 |
| P4-07 / #57 | Provider selection | Sections 10.1 and 17 |
| P4-08 / #58 | Web session hardening | Sections 9 and 12 |
| P4-09 / #59 | Accounting/audit subsystem | Section 16 |
| P4-10 / #60 | Audit viewer | Sections 16 and 19 |
| P4-11 / #61 | Web conversation + LangGraph | Section 13 |
| P4-12 / #62 | Web human approval | Section 14 |
| P4-13 / #63 | Conversation history/session visibility | Sections 12–13 |
| P4-14 / #64 | Local admin recovery/break-glass | Section 18 |
| P4-15 / #65 | Minimal admin/status page | Section 19 |
| P4-16 / #66 | AD end-to-end validation | Sections 10.2, 12 |
| P4-17 / #67 | RADIUS end-to-end validation | Sections 10.3, 12 |
| P4-18 / #68 | Complete Phase 4 validation | Entire architecture |
| P4-19 / #69 | Deployment/auth/accounting/recovery docs | Sections 17, 18, 22 |

### 23.1 Recommended Implementation Order

The issue numbering already provides a reasonable order, but dependencies should be respected:

```text
P4-01 Architecture
      |
      v
P4-02 FastAPI foundation
      |
      +----> P4-03 GUI shell
      |
      +----> P4-04 identity/session model
                  |
                  +----> P4-05 LDAPS
                  +----> P4-06 RADIUS
                  +----> P4-07 provider selection
                  +----> P4-08 session hardening
      |
      +----> P4-09 accounting
                  |
                  +----> P4-10 audit viewer
      |
      +----> P4-11 LangGraph conversations
                  |
                  +----> P4-12 web approval
                  +----> P4-13 history/session visibility
      |
      +----> P4-14 break-glass
      +----> P4-15 status/admin
      |
      +----> P4-16 AD validation
      +----> P4-17 RADIUS validation
      +----> P4-18 complete validation
      +----> P4-19 final documentation
```

---

## 24. Acceptance Criteria for P4-01

P4-01 is ready for owner review when all of the following are documented:

- [x] Phase 4 component architecture
- [x] browser → GUI → FastAPI → LangGraph boundary
- [x] FastAPI is not a second direct Kali execution path
- [x] AD/LDAPS trust flow
- [x] RADIUS trust flow
- [x] authentication provider abstraction
- [x] authenticated identity model
- [x] secure web session model
- [x] conversation/LangGraph ownership model
- [x] web approval model
- [x] existing Phase 3 approval signature preserved
- [x] existing target authorization preserved
- [x] application accounting event model
- [x] secret/configuration ownership
- [x] local break-glass model
- [x] Phase 4 vs later-phase boundary
- [x] failure/recovery scenarios
- [x] implementation mapping to P4-02 through P4-19
- [ ] owner review and acceptance

No Phase 4 code is required for P4-01 itself.

---

## 25. Open Design Questions

The following decisions can be finalized during owner review or the corresponding implementation issue.

### 25.1 Frontend Technology

The architecture requires a browser GUI but does not yet require a specific frontend framework.

Options can be evaluated in P4-03.

### 25.2 Application Database

Phase 4 requires persistence for identities, sessions/conversation metadata, and accounting.

The database technology should be selected before or during P4-02/P4-04/P4-09.

### 25.3 Session Storage Strategy

Decide whether web sessions are:

- database-backed
- dedicated session-store backed
- another server-side design

The browser should still hold only an opaque session reference.

### 25.4 Accounting Fail-Closed Policy

Define which operations must be blocked if durable accounting cannot be written.

State-changing approval/execution should receive special consideration.

### 25.5 Authentication Provider Failover

Phase 4 currently describes configured provider selection, not automatic fallback.

Automatic fallback between AD and RADIUS should not be introduced without explicit design because it changes the authentication trust model.

### 25.6 Application RBAC Roadmap

The GitHub issue states full RBAC is deferred to Phase 5, while the existing Phase 5 backlog also contains persistent memory.

The roadmap should be normalized before those future items begin.

### 25.7 CSRF Implementation

The architecture requires CSRF protection for browser state-changing actions. The concrete mechanism should be chosen alongside the frontend/session implementation.

---

## 26. Summary

Phase 4 transforms PentAiA from a CLI-only research agent into an authenticated web application while preserving the security boundaries already proven in Phases 1–3.

The primary architecture is:

```text
Browser / GUI
      |
      v
FastAPI
      |
      +---- Authentication (LDAPS or RADIUS)
      |
      +---- Secure Web Session
      |
      +---- Accounting / Audit
      |
      v
Existing PentAiA / LangGraph engine
      |
      v
Existing code-owned wrappers
      |
      v
Existing Kali SSH executor
      |
      v
Authorized lab target
```

The most important architectural rule is that Phase 4 adds identity, usability, accountability, and recovery around the existing PentAiA engine; it does not create a new execution path.

The existing Phase 3 controls remain mandatory:

- deterministic supported actions
- target authorization
- code-owned native commands
- runtime-owned protected parameters
- exact proposal signatures
- explicit human approval
- stale-approval rejection
- evidence-based result normalization
- truthful audit records
- explicit human session handoff

This document should be reviewed and accepted before P4-02 FastAPI implementation begins.
