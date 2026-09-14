"""Operator-facing ``pentaia session`` subcommands.

A held console lives on the Kali host, so these commands inspect and manage it over
the existing SSH executor. ``attach`` prints the exact command to run on Kali rather
than pretending PentAiA can forward a terminal it does not own.
"""

import logging
from collections.abc import Callable

from pentaia.phase3_session import (
    HeldSession,
    attach_command,
    capture_session_evidence,
    close_live_session,
    find_held_session,
    list_held_sessions,
    mark_session_handed_off,
)

logger = logging.getLogger(__name__)

SHOW_CONSOLE_LINES = 20

USAGE = (
    "Usage: pentaia session <list|show|attach|close> [session-name]\n"
    "\n"
    "  list                      List PentAiA consoles held on the Kali host\n"
    "  show <name>               Show lifecycle details and recent console output\n"
    "  attach <name>             Print the command that takes the session over on Kali\n"
    "  close <name>              Close a session and report where its marker was left\n"
    "\n"
    "PentAiA never removes the proof marker from the target; closing a session\n"
    "stops the Metasploit handler and leaves the marker in place.\n"
)


def _describe(session: HeldSession, output: Callable[[str], None]) -> None:
    output(f"{session.name}")
    output(f"  lifecycle: {session.lifecycle}")
    output(f"  action:    {session.action_id or 'unknown'}")
    output(f"  target:    {session.target or 'unknown'}:{session.rport or '?'}")

    if session.lport:
        output(f"  listener:  lport {session.lport}")

    if session.artifact_path:
        state = "verified" if session.artifact_verified else "unconfirmed"
        output(f"  artifact:  {session.artifact_path} ({state})")
    else:
        output("  artifact:  none recorded")


def _list(output: Callable[[str], None]) -> int:
    sessions = list_held_sessions()

    if not sessions:
        output("No PentAiA sessions are held on the Kali host.")
        return 0

    for index, session in enumerate(sessions):
        if index:
            output("")
        _describe(session, output)

    return 0


def _show(argv: list[str], output: Callable[[str], None]) -> int:
    if not argv:
        output(USAGE)
        return 2

    session = find_held_session(argv[0])

    if session is None:
        output(f"No PentAiA session named {argv[0]} is running on the Kali host.")
        return 1

    _describe(session, output)
    output(f"  attach:    {attach_command(session.name)}")
    output("")
    output(f"Recent console output (last {SHOW_CONSOLE_LINES} lines):")

    pane = capture_session_evidence(session.name)
    for line in pane.splitlines()[-SHOW_CONSOLE_LINES:]:
        output(f"  {line}")

    return 0


def _attach(argv: list[str], output: Callable[[str], None]) -> int:
    if not argv:
        output(USAGE)
        return 2

    name = argv[0]
    session = find_held_session(name)

    if session is None:
        output(f"No PentAiA session named {name} is running on the Kali host.")
        return 1

    mark_session_handed_off(name)

    output("Run this on the Kali host to take the session over:")
    output(f"  {attach_command(name)}")
    output("")
    output("Then select the caught session there, for example 'sessions -i 1'.")
    output("PentAiA will issue no further commands through that session.")

    return 0


def _close(argv: list[str], output: Callable[[str], None]) -> int:
    if not argv:
        output(USAGE)
        return 2

    name = argv[0]

    session = find_held_session(name)

    if session is None:
        output(f"No PentAiA session named {name} is running on the Kali host.")
        return 1

    result = close_live_session(name)

    output(f"Closed: {result.name}" if result.closed else f"Could not close {result.name}.")

    if result.artifact_message:
        output(result.artifact_message)

    if result.port_released:
        output("The reserved listener port was released.")
    elif session.target and session.rport:
        # The reservation registry lives in the agent process, so a separate CLI
        # process has nothing to release. Killing the console is what frees the
        # port; say that plainly instead of leaving it looking like a failure.
        output(
            "The listener port was freed when the console stopped; this process "
            "held no reservation for it."
        )

    return 0 if result.closed else 1


def run_session_command(
    argv: list[str],
    *,
    output: Callable[[str], None] = print,
) -> int:
    """Dispatch one ``pentaia session`` invocation. Returns a process exit code."""
    if not argv:
        output(USAGE)
        return 2

    command, rest = argv[0], argv[1:]

    if command in {"-h", "--help", "help"}:
        output(USAGE)
        return 0

    handlers: dict[str, Callable[[], int]] = {
        "list": lambda: _list(output),
        "show": lambda: _show(rest, output),
        "attach": lambda: _attach(rest, output),
        "close": lambda: _close(rest, output),
    }

    handler = handlers.get(command)

    if handler is None:
        output(f"Unknown session command: {command}")
        output("")
        output(USAGE)
        return 2

    # Operator commands talk to the Kali host, which can fail for ordinary reasons.
    # Report that plainly instead of dumping a traceback at the operator.
    try:
        return handler()
    except Exception as exc:
        logger.exception("Session command failed command=%s", command)
        output(f"Session command failed: {type(exc).__name__}: {exc}")

        return 1
