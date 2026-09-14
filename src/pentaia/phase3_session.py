"""Code-owned persistence of an approved Phase 3 reverse session.

Testing against the authorized lab established two things: Metasploit's own
handler is what catches the reverse shell, and that session lives only as long as
the msfconsole process does. The bounded one-shot run therefore proves the
exploit but deliberately tears the session down again.

This module keeps one alive for the human. msfconsole runs inside a detached tmux
session on the Kali host, so the handler and the caught shell outlive the SSH
command that started them. The operator takes over with ``tmux attach`` and
``sessions -i <id>``.

Every token in the commands below is a code-owned constant or a value PentAiA has
already validated (an IPv4 address, a TCP port, a sanitised session name).
Nothing here is exposed to Gemini as a tool.
"""

import hashlib
import logging
import re
import shlex
import time
from dataclasses import asdict, dataclass
from typing import Any

from pentaia.approval import (
    Phase3ActionProposal,
    Phase3ApprovalState,
    require_current_phase3_approval,
)
from pentaia.authorization import authorize_phase3_target
from pentaia.kali_executor import run_command
from pentaia.metasploit_wrapper import (
    PREDEFINED_METASPLOIT_OPERATIONS,
    MetasploitOperation,
    build_live_console_script,
)
from pentaia.phase3_ports import (
    activate_listener_port,
    listener_reservation,
    release_listener_port,
)
from pentaia.runtime_config import (
    get_phase3_callback_address,
    validate_callback_ipv4,
    validate_listener_port,
)

logger = logging.getLogger(__name__)

SESSION_PREFIX = "pentaia-phase3"
TMUX_BINARY = "tmux"
CONSOLE_BINARY = "msfconsole"
TMUX_TIMEOUT = 20
CAPTURE_LINES = 400

# The console needs time to trigger the backdoor and catch the callback. Poll
# rather than sleeping for a fixed worst case, so a fast catch returns fast.
POLL_ATTEMPTS = 15
POLL_DELAY_SECONDS = 2.0

# tmux session names may not contain '.' or ':', so anything outside this set is
# replaced before the name is ever placed in a command.
_SAFE_SESSION_CHARS = re.compile(r"[^A-Za-z0-9_-]")

# Markers that appear in PentAiA's console once a session has actually been
# caught. Proof of a session comes from this evidence, never from a process exit
# status.
SESSION_EVIDENCE_MARKERS: tuple[str, ...] = (
    "command shell session",
    "meterpreter session",
)


@dataclass(frozen=True)
class LiveSession:
    """A reverse session held open on the Kali host for human takeover."""

    action_id: str
    target: str
    session_name: str
    lhost: str
    lport: int
    console_command: str
    evidence: str
    established: bool
    attach: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _is_text(value: object) -> bool:
    """True only for genuine text, so evidence is never coerced silently."""
    return isinstance(value, str)


def validate_session_name(value: object) -> str:
    """Validate a tmux session name before it can reach a command."""
    if not _is_text(value) or not value.strip():
        raise ValueError("Session name must be a non-empty string.")

    name = value.strip()

    if _SAFE_SESSION_CHARS.search(name):
        raise ValueError("Session name contains unsafe characters.")

    return name


def session_name(*, action_id: str, target: str) -> str:
    """Build a deterministic, shell-safe tmux session name for one action."""
    digest = hashlib.sha256(f"{action_id}:{target}".encode()).hexdigest()[:12]
    label = _SAFE_SESSION_CHARS.sub("-", action_id)[:32].strip("-") or "action"

    return f"{SESSION_PREFIX}-{label}-{digest}"


def attach_command(session_name_value: str) -> str:
    """Human-facing command for taking over a held session."""
    return f"{TMUX_BINARY} attach -t {validate_session_name(session_name_value)}"


def build_console_command(
    operation: MetasploitOperation,
    target: str,
    parameters: dict[str, Any],
) -> str:
    """Build the console command that runs the action and stays alive."""
    script = build_live_console_script(operation, target, parameters)

    return f"{CONSOLE_BINARY} -q -x {shlex.quote(script)}"


def session_established(evidence: object) -> bool:
    """Return True only when console evidence shows a session was caught."""
    if not _is_text(evidence):
        raise ValueError("evidence must be a string.")

    normalized = evidence.lower()

    return any(marker in normalized for marker in SESSION_EVIDENCE_MARKERS)


def live_session_running(session_name_value: object) -> bool:
    """Return True when the named tmux session exists on the Kali host."""
    name = validate_session_name(session_name_value)

    _, _, exit_code = run_command(
        f"{TMUX_BINARY} has-session -t {name}",
        timeout=TMUX_TIMEOUT,
    )

    return exit_code == 0


def capture_session_evidence(session_name_value: object) -> str:
    """Return the visible output of a held session's console."""
    name = validate_session_name(session_name_value)

    stdout, _, exit_code = run_command(
        f"{TMUX_BINARY} capture-pane -p -t {name} -S -{CAPTURE_LINES}",
        timeout=TMUX_TIMEOUT,
    )

    if exit_code != 0:
        raise RuntimeError("Unable to read the PentAiA session.")

    return stdout


def wait_for_session(
    session_name_value: object,
    *,
    attempts: int = POLL_ATTEMPTS,
    delay: float = POLL_DELAY_SECONDS,
    sleeper: Any = time.sleep,
) -> str:
    """Poll a held session's console until it shows a caught session."""
    name = validate_session_name(session_name_value)

    if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts <= 0:
        raise ValueError("attempts must be a positive integer.")

    if isinstance(delay, bool) or not isinstance(delay, (int, float)) or delay < 0:
        raise ValueError("delay must be a non-negative number.")

    evidence = ""

    for attempt in range(attempts):
        evidence = capture_session_evidence(name)

        if session_established(evidence):
            return evidence

        if attempt < attempts - 1:
            sleeper(delay)

    return evidence


def stop_live_session(session_name_value: object) -> bool:
    """Close a held session. Returns True when it is gone afterwards."""
    name = validate_session_name(session_name_value)

    _, _, exit_code = run_command(
        f"{TMUX_BINARY} kill-session -t {name}",
        timeout=TMUX_TIMEOUT,
    )

    stopped = exit_code == 0

    logger.info("Phase 3 held session stopped session=%s stopped=%s", name, stopped)

    return stopped


def start_live_session(
    proposal: Phase3ActionProposal,
    approval: Phase3ApprovalState | None,
) -> LiveSession:
    """Run one approved action inside a detached console and hold the session.

    Approval, authorization and freshness of the runtime-owned values are all
    rechecked here, immediately before the session is created, because holding a
    session is itself state-changing.
    """
    operation = PREDEFINED_METASPLOIT_OPERATIONS.get(proposal.action_id)

    if operation is None:
        raise ValueError(
            f"Unsupported Phase 3 Metasploit action: {proposal.action_id}"
        )

    if not operation.establishes_reverse_session:
        raise ValueError(
            f"Action does not establish a reverse session: {proposal.action_id}"
        )

    require_current_phase3_approval(approval, proposal)
    target = authorize_phase3_target(proposal.target)

    lhost = validate_callback_ipv4(proposal.parameters.get("lhost"))
    lport = validate_listener_port(proposal.parameters.get("lport"))

    if lhost != get_phase3_callback_address():
        raise ValueError(
            "Runtime callback configuration changed after approval; approval is stale."
        )

    # The listener port is authoritative through its reservation: a released or
    # expired reservation means the approved port is no longer held for us.
    reservation = listener_reservation(
        action_id=proposal.action_id,
        target=target,
        rport=proposal.parameters["rport"],
    )

    if reservation is None or reservation.lport != lport:
        raise ValueError(
            "The approved listener port reservation is no longer valid; approval is stale."
        )

    name = session_name(action_id=proposal.action_id, target=target)

    # A leftover session would still hold the listener port, so refuse rather
    # than silently tear down a console the operator may be using.
    if live_session_running(name):
        raise RuntimeError(
            f"A PentAiA session named {name} is already running on the Kali host."
        )

    console_command = build_console_command(
        operation,
        target,
        proposal.parameters,
    )

    _, _, exit_code = run_command(
        f"{TMUX_BINARY} new-session -d -s {name} {shlex.quote(console_command)}",
        timeout=TMUX_TIMEOUT,
    )

    if exit_code != 0 or not live_session_running(name):
        release_listener_port(
            action_id=proposal.action_id,
            target=target,
            rport=proposal.parameters["rport"],
        )
        raise RuntimeError("Unable to start the PentAiA session on the Kali host.")

    activate_listener_port(
        action_id=proposal.action_id,
        target=target,
        rport=proposal.parameters["rport"],
        proposal_signature=proposal.signature(),
    )

    logger.info(
        "Phase 3 held session started session=%s target=%s lport=%s",
        name,
        target,
        lport,
    )

    evidence = wait_for_session(name)
    established = session_established(evidence)

    if not established:
        # Never leave a console holding the listener port on a failed attempt.
        stop_live_session(name)
        release_listener_port(
            action_id=proposal.action_id,
            target=target,
            rport=proposal.parameters["rport"],
        )

    return LiveSession(
        action_id=proposal.action_id,
        target=target,
        session_name=name,
        lhost=lhost,
        lport=lport,
        console_command=console_command,
        evidence=evidence if established else "",
        established=established,
        attach=attach_command(name),
    )
