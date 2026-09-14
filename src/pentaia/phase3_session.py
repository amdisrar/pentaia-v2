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
from datetime import UTC, datetime
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
from pentaia.phase3_artifact import (
    VerificationArtifact,
    artifact_content,
    artifact_path,
    artifact_path_for_digest,
    artifact_verified,
    build_cleanup_command,
    build_write_command,
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

# Writing the marker goes out through the caught session, so allow it a moment to
# come back before concluding that it failed.
ARTIFACT_POLL_ATTEMPTS = 6
ARTIFACT_POLL_DELAY_SECONDS = 1.0

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
    artifact: VerificationArtifact | None = None

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

    # Metadata lives on the tmux session itself, so a later CLI process can list,
    # show and close it without PentAiA keeping a second store that could drift.
    set_session_metadata(
        name,
        {
            "target": target,
            "action_id": proposal.action_id,
            "lport": lport,
            "rport": proposal.parameters["rport"],
            "artifact_path": "",
            "artifact_verified": 0,
            "handed_off": 0,
        },
    )
    audit_session_event("started", session=name, target=target, lport=lport)

    evidence = wait_for_session(name)
    established = session_established(evidence)

    artifact: VerificationArtifact | None = None

    if not established:
        # Never leave a console holding the listener port on a failed attempt.
        stop_live_session(name)
        release_listener_port(
            action_id=proposal.action_id,
            target=target,
            rport=proposal.parameters["rport"],
        )
    else:
        # The approved action leaves a harmless code-owned marker on the target so
        # a successful validation has evidence on the box, not only in the pane.
        artifact = write_verification_artifact(
            console_session=name,
            action_id=proposal.action_id,
            target=target,
        )

        set_session_metadata(
            name,
            {
                "artifact_path": artifact.path if artifact is not None else "",
                "artifact_verified": (
                    1 if artifact is not None and artifact.verified else 0
                ),
            },
        )
        audit_session_event(
            "artifact_written",
            session=name,
            artifact_path=artifact.path if artifact is not None else "",
            verified=artifact is not None and artifact.verified,
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
        artifact=artifact,
    )


def send_console_line(console_session: str, line: str) -> None:
    """Type one code-owned line into a held console and press Enter."""
    name = validate_session_name(console_session)

    if not isinstance(line, str) or not line.strip():
        raise ValueError("Console line must be a non-empty string.")

    run_command(
        f"{TMUX_BINARY} send-keys -t {name} {shlex.quote(line.strip())} Enter",
        timeout=TMUX_TIMEOUT,
    )


def write_verification_artifact(
    *,
    console_session: str,
    action_id: str,
    target: str,
    attempts: int = ARTIFACT_POLL_ATTEMPTS,
    delay: float = ARTIFACT_POLL_DELAY_SECONDS,
    sleeper: Any = time.sleep,
    now: Any = None,
) -> VerificationArtifact:
    """Write the proof-of-success marker through the held session and read it back.

    A failure here is reported plainly: ``created``/``verified`` stay false and the
    caller must not present it as proof.
    """
    path = artifact_path(action_id=action_id, target=target)
    timestamp = (now or _utc_now)()
    content = artifact_content(
        action_id=action_id,
        target=target,
        timestamp=timestamp,
    )

    send_console_line(
        console_session,
        build_write_command(path=path, content=content),
    )

    pane = ""

    for attempt in range(attempts):
        pane = capture_session_evidence(console_session)

        if artifact_verified(pane_text=pane, content=content):
            logger.info(
                "Phase 3 verification artifact written path=%s verified=%s",
                path,
                True,
            )
            return VerificationArtifact(
                path=path,
                content=content,
                created=True,
                verified=True,
                evidence=f"Verified on target: {path}",
            )

        if attempt < attempts - 1:
            sleeper(delay)

    logger.warning(
        "Phase 3 verification artifact could not be confirmed path=%s",
        path,
    )

    return VerificationArtifact(
        path=path,
        content=content,
        created=False,
        verified=False,
        evidence="The proof-of-success marker could not be confirmed on the target.",
    )


def remove_verification_artifact(
    *,
    console_session: str,
    action_id: str,
    target: str,
) -> bool:
    """Remove the marker from the target through the held session."""
    path = artifact_path(action_id=action_id, target=target)

    send_console_line(
        console_session,
        build_cleanup_command(path=path),
    )

    logger.info("Phase 3 verification artifact removal requested path=%s", path)

    return True


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Session manager: lifecycle metadata, listing, and controlled close
# ---------------------------------------------------------------------------
#
# Metadata lives on the tmux session itself as tmux user options, so it survives
# between CLI processes without PentAiA keeping a second store that could drift
# from reality. tmux is the source of truth for which sessions exist.

SESSION_AUDIT_LOGGER_NAME = "pentaia.phase3.session"

SESSION_METADATA_KEYS: dict[str, str] = {
    "target": "@pentaia_target",
    "action_id": "@pentaia_action",
    "lport": "@pentaia_lport",
    "rport": "@pentaia_rport",
    "artifact_path": "@pentaia_artifact",
    "artifact_verified": "@pentaia_artifact_verified",
    "handed_off": "@pentaia_handed_off",
}

_session_audit = logging.getLogger(SESSION_AUDIT_LOGGER_NAME)


def audit_session_event(event: str, **fields: object) -> None:
    """Record one session lifecycle event.

    Only code-owned identifiers and counts are recorded: the console pane may hold
    raw target output, and dedicated lifecycle events must not duplicate it.
    """
    rendered = " ".join(f"{key}={value}" for key, value in sorted(fields.items()))

    _session_audit.info("phase3 session event=%s %s", event, rendered)


@dataclass(frozen=True)
class HeldSession:
    """One held console and the lifecycle state PentAiA can prove for it."""

    name: str
    target: str
    action_id: str
    lport: str
    rport: str
    artifact_path: str
    artifact_verified: bool
    handed_off: bool

    @property
    def lifecycle(self) -> str:
        """The furthest state the recorded facts support, never a guess ahead."""
        if self.handed_off:
            return "handed_off"
        if self.artifact_verified:
            return "verified"
        return "active"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["lifecycle"] = self.lifecycle

        return payload


def set_session_metadata(
    console_session: str,
    values: dict[str, object],
) -> None:
    """Record lifecycle metadata on the tmux session itself."""
    name = validate_session_name(console_session)

    unknown = set(values) - set(SESSION_METADATA_KEYS)
    if unknown:
        raise ValueError(f"Unknown session metadata: {sorted(unknown)}")

    parts = [
        f"set-option -t {name} {SESSION_METADATA_KEYS[key]} {shlex.quote(str(value))}"
        for key, value in values.items()
    ]

    if not parts:
        return

    run_command(f"{TMUX_BINARY} " + " \\; ".join(parts), timeout=TMUX_TIMEOUT)


def _metadata_format() -> str:
    return "|".join(["#{session_name}", *SESSION_METADATA_KEYS.values()])


def list_held_sessions() -> list[HeldSession]:
    """Every PentAiA console currently running on the Kali host."""
    stdout, _, exit_code = run_command(
        f"{TMUX_BINARY} list-sessions -F {shlex.quote(_metadata_format())}",
        timeout=TMUX_TIMEOUT,
    )

    if exit_code != 0:
        # No tmux server, or no sessions: both mean nothing is held.
        return []

    sessions: list[HeldSession] = []

    for line in stdout.splitlines():
        fields = line.split("|")

        if not fields or not fields[0].startswith(f"{SESSION_PREFIX}-"):
            continue

        padded = fields + [""] * (len(SESSION_METADATA_KEYS) + 1 - len(fields))

        sessions.append(
            HeldSession(
                name=padded[0].strip(),
                target=padded[1].strip(),
                action_id=padded[2].strip(),
                lport=padded[3].strip(),
                rport=padded[4].strip(),
                artifact_path=padded[5].strip(),
                artifact_verified=padded[6].strip() == "1",
                handed_off=padded[7].strip() == "1",
            )
        )

    return sessions


def find_held_session(console_session: str) -> HeldSession | None:
    """One held session by exact name, or None when it is not running."""
    wanted = validate_session_name(console_session)

    for session in list_held_sessions():
        if session.name == wanted:
            return session

    return None


def mark_session_handed_off(console_session: str) -> bool:
    """Record that the operator has taken the session over."""
    name = validate_session_name(console_session)

    if find_held_session(name) is None:
        raise RuntimeError(f"No PentAiA session named {name} is running on the Kali host.")

    set_session_metadata(name, {"handed_off": 1})
    audit_session_event("handed_off", session=name)

    return True


@dataclass(frozen=True)
class SessionClose:
    """The outcome of closing one held session."""

    name: str
    closed: bool
    artifact_path: str
    artifact_removed: bool
    artifact_message: str
    port_released: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def close_live_session(
    console_session: str,
    *,
    remove_artifact: bool = True,
) -> SessionClose:
    """Close one held session, optionally removing its marker.

    Cleanup is a code-owned operation and its result is audited. When the marker is
    deliberately kept, or its removal cannot be confirmed, PentAiA says so plainly
    and reports the exact path rather than implying the target was left clean.
    """
    name = validate_session_name(console_session)
    held = find_held_session(name)

    artifact_path = held.artifact_path if held is not None else ""
    if not artifact_path:
        digest = session_digest_from_name(name)
        if digest:
            artifact_path = artifact_path_for_digest(digest)

    artifact_removed = False
    artifact_message = ""

    if remove_artifact and held is not None and artifact_path:
        remove_verification_artifact(
            console_session=name,
            action_id=held.action_id,
            target=held.target,
        )
        artifact_removed = True
        artifact_message = f"Removal of {artifact_path} was requested on the target."
        audit_session_event(
            "artifact_removed",
            session=name,
            artifact_path=artifact_path,
        )
    elif artifact_path:
        artifact_message = (
            f"The proof marker remains on the target at {artifact_path}."
        )
        audit_session_event(
            "artifact_retained",
            session=name,
            artifact_path=artifact_path,
        )

    stopped = stop_live_session(name)

    port_released = False
    if held is not None and held.action_id and held.target and held.rport:
        port_released = release_listener_port(
            action_id=held.action_id,
            target=held.target,
            rport=int(held.rport),
        )

    audit_session_event(
        "closed",
        session=name,
        stopped=stopped,
        artifact_removed=artifact_removed,
    )

    return SessionClose(
        name=name,
        closed=stopped,
        artifact_path=artifact_path,
        artifact_removed=artifact_removed,
        artifact_message=artifact_message,
        port_released=port_released,
    )


def session_digest_from_name(console_session: str) -> str | None:
    """Recover the session digest from a PentAiA console name."""
    name = validate_session_name(console_session)

    if not name.startswith(f"{SESSION_PREFIX}-"):
        return None

    _, _, digest = name.rpartition("-")

    return digest if digest else None
