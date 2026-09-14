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
    "  close <name> [--keep-artifact]\n"
    "                            Close a session, removing its proof marker by default\n"
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
    remove_artifact = "--keep-artifact" not in argv[1:]

    session = find_held_session(name)

    if session is None:
        output(f"No PentAiA session named {name} is running on the Kali host.")
        return 1

    result = close_live_session(name, remove_artifact=remove_artifact)

    output(f"Closed: {result.name}" if result.closed else f"Could not close {result.name}.")

    if result.artifact_message:
        output(result.artifact_message)

    if not remove_artifact and result.artifact_path:
        output(
            "The marker was kept deliberately; remove it yourself if that is not "
            "what you intended."
        )

    if result.port_released:
        output("The reserved listener port was released.")

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
    if command == "list":
        return _list(output)
    if command == "show":
        return _show(rest, output)
    if command == "attach":
        return _attach(rest, output)
    if command == "close":
        return _close(rest, output)

    output(f"Unknown session command: {command}")
    output("")
    output(USAGE)

    return 2
