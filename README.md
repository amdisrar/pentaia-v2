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
