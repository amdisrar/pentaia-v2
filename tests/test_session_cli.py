import pytest

from pentaia import phase3_session, session_cli
from pentaia.phase3_session import (
    HeldSession,
    audit_session_event,
    close_live_session,
    find_held_session,
    list_held_sessions,
    session_digest_from_name,
)
from pentaia.session_cli import run_session_command

NAME = "pentaia-phase3-validate_vsftpd_234_backdoor-66d6db4c2ad8"
DIGEST = "66d6db4c2ad8"


def _row(
    *,
    name: str = NAME,
    target: str = "172.16.0.64",
    action: str = "validate_vsftpd_234_backdoor",
    lport: str = "5000",
    rport: str = "21",
    artifact: str = f"/tmp/pentaia-poc-{DIGEST}.txt",
    verified: str = "1",
    handed_off: str = "0",
) -> str:
    return f"{name}|{target}|{action}|{lport}|{rport}|{artifact}|{verified}|{handed_off}"


def _install_fake_run_command(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sessions: list[str] | None = None,
    list_ok: bool = True,
    pane: str = "",
) -> list[str]:
    issued: list[str] = []

    def fake_run_command(command: str, timeout: int):
        issued.append(command)

        if command.startswith("tmux list-sessions"):
            if not list_ok:
                return "", "no server", 1
            return "\n".join(sessions or []), "", 0

        if command.startswith("tmux capture-pane"):
            return pane, "", 0

        return "", "", 0

    monkeypatch.setattr(phase3_session, "run_command", fake_run_command)

    return issued


# --- listing ---------------------------------------------------------------


def test_listing_parses_session_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_run_command(monkeypatch, sessions=[_row()])

    sessions = list_held_sessions()

    assert len(sessions) == 1
    session = sessions[0]
    assert session.name == NAME
    assert session.target == "172.16.0.64"
    assert session.action_id == "validate_vsftpd_234_backdoor"
    assert session.lport == "5000"
    assert session.rport == "21"
    assert session.artifact_path == f"/tmp/pentaia-poc-{DIGEST}.txt"
    assert session.artifact_verified is True
    assert session.handed_off is False


def test_listing_ignores_unrelated_tmux_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_run_command(
        monkeypatch,
        sessions=[_row(name="my-own-shell"), _row()],
    )

    names = [session.name for session in list_held_sessions()]

    assert names == [NAME]


def test_listing_is_empty_when_no_tmux_server_is_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_run_command(monkeypatch, list_ok=False)

    assert list_held_sessions() == []


def test_missing_metadata_fields_do_not_break_listing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_run_command(monkeypatch, sessions=[f"{NAME}|172.16.0.64"])

    session = list_held_sessions()[0]

    assert session.target == "172.16.0.64"
    assert session.artifact_path == ""
    assert session.artifact_verified is False


def test_listing_asks_tmux_to_expand_every_user_option(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bare option name makes tmux echo the name instead of the value."""
    issued = _install_fake_run_command(monkeypatch, sessions=[_row()])

    list_held_sessions()

    command = next(item for item in issued if item.startswith("tmux list-sessions"))

    for option in phase3_session.SESSION_METADATA_KEYS.values():
        assert f"#{{{option}}}" in command
        assert f"|{option}|" not in command
        assert command.endswith(f"|{option}'") is False


def test_metadata_that_reads_back_as_an_option_name_is_not_a_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Guard the exact live failure: tmux returned "@pentaia_target" as a value."""
    _install_fake_run_command(
        monkeypatch,
        sessions=[
            _row(
                target="@pentaia_target",
                action="@pentaia_action",
                rport="@pentaia_rport",
            )
        ],
    )
    released: list[dict] = []
    monkeypatch.setattr(
        phase3_session,
        "release_listener_port",
        lambda **kwargs: released.append(kwargs) or True,
    )

    session = list_held_sessions()[0]

    assert session.target == "@pentaia_target"

    # Closing must report the odd metadata rather than releasing an unrelated port.
    result = close_live_session(NAME)

    assert result.port_released is False
    assert released == []


@pytest.mark.parametrize(
    ("verified", "handed_off", "expected"),
    [
        ("0", "0", "active"),
        ("1", "0", "verified"),
        ("1", "1", "handed_off"),
        ("0", "1", "handed_off"),
    ],
)
def test_lifecycle_reports_only_what_is_proven(
    verified: str,
    handed_off: str,
    expected: str,
) -> None:
    session = HeldSession(
        name=NAME,
        target="172.16.0.64",
        action_id="validate_vsftpd_234_backdoor",
        lport="5000",
        rport="21",
        artifact_path="/tmp/x.txt",
        artifact_verified=verified == "1",
        handed_off=handed_off == "1",
    )

    assert session.lifecycle == expected


def test_find_returns_none_for_an_unknown_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_run_command(monkeypatch, sessions=[_row()])

    assert find_held_session("pentaia-phase3-nope-000000000000") is None
    assert find_held_session(NAME) is not None


def test_digest_is_recovered_from_the_session_name() -> None:
    assert session_digest_from_name(NAME) == DIGEST
    assert session_digest_from_name("my-own-shell") is None


# --- close -----------------------------------------------------------------


def test_close_never_types_a_deletion_into_the_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PentAiA keeps the proof marker: closing a console must not touch the target.

    The marker is the evidence that the approved action ran, so it outlives the
    session and removing it stays the operator's decision on the target itself.
    """
    issued = _install_fake_run_command(monkeypatch, sessions=[_row()])
    monkeypatch.setattr(phase3_session, "release_listener_port", lambda **k: True)

    result = close_live_session(NAME)

    assert result.artifact_path == f"/tmp/pentaia-poc-{DIGEST}.txt"
    assert "left in place" in result.artifact_message

    # Nothing is typed into the console and nothing is deleted.
    assert not any(command.startswith("tmux send-keys") for command in issued)
    assert not any("rm " in command for command in issued)
    assert not any("rm -f" in command for command in issued)

    # The only thing close does to the host is stop the console.
    assert [command for command in issued if "kill-session" in command] != []
    assert any(command.startswith("tmux kill-session") for command in issued)


def test_close_releases_the_port_recorded_in_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_run_command(monkeypatch, sessions=[_row()])
    released: list[dict] = []

    monkeypatch.setattr(
        phase3_session,
        "release_listener_port",
        lambda **kwargs: released.append(kwargs) or True,
    )

    result = close_live_session(NAME)

    assert result.closed is True
    assert result.port_released is True
    assert released == [
        {
            "action_id": "validate_vsftpd_234_backdoor",
            "target": "172.16.0.64",
            "rport": 21,
        }
    ]


def test_close_reports_the_marker_path_even_when_the_session_is_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The digest in the name still locates the marker for the report."""
    _install_fake_run_command(monkeypatch, sessions=[])
    monkeypatch.setattr(phase3_session, "release_listener_port", lambda **k: False)

    result = close_live_session(NAME)

    assert result.artifact_path == f"/tmp/pentaia-poc-{DIGEST}.txt"
    assert "left in place" in result.artifact_message


@pytest.mark.parametrize("rport", ["", "not-a-port", "21; rm -rf /"])
def test_close_tolerates_unreadable_port_metadata(
    monkeypatch: pytest.MonkeyPatch,
    rport: str,
) -> None:
    """Metadata comes back from tmux, so a bad port must not abort the close."""
    _install_fake_run_command(monkeypatch, sessions=[_row(rport=rport)])
    released: list[dict] = []
    monkeypatch.setattr(
        phase3_session,
        "release_listener_port",
        lambda **kwargs: released.append(kwargs) or True,
    )

    result = close_live_session(NAME)

    assert result.port_released is False
    assert released == []
    assert result.closed is True


def test_close_names_the_marker_from_the_session_without_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty metadata must not produce a marker path derived from empty inputs.

    Re-deriving the path from a missing target once produced a marker path hashed
    from two empty strings, which is a file that never existed.
    """
    _install_fake_run_command(
        monkeypatch,
        sessions=[
            _row(
                target="",
                action="",
                lport="",
                rport="",
                artifact="",
                verified="",
                handed_off="",
            )
        ],
    )
    monkeypatch.setattr(phase3_session, "release_listener_port", lambda **k: True)

    result = close_live_session(NAME)

    assert result.artifact_path == f"/tmp/pentaia-poc-{DIGEST}.txt"
    assert "e7ac0786668e" not in result.artifact_message


# --- metadata durability ---------------------------------------------------


def test_metadata_that_reads_back_is_not_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issued = _install_fake_run_command(monkeypatch, sessions=[_row(handed_off="0")])

    phase3_session.set_session_metadata(NAME, {"handed_off": 0})

    writes = [command for command in issued if "set-option" in command]
    assert len(writes) == 1


def test_metadata_that_does_not_read_back_is_retried_per_option(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    issued = _install_fake_run_command(monkeypatch, sessions=[_row(handed_off="0")])

    with caplog.at_level("WARNING", logger="pentaia.phase3_session"):
        phase3_session.set_session_metadata(NAME, {"handed_off": 1})

    writes = [command for command in issued if "set-option" in command]
    assert len(writes) == 2
    assert writes[1] == f"tmux set-option -t {NAME} @pentaia_handed_off 1"
    assert any("retrying per option" in record.getMessage() for record in caplog.records)


def test_metadata_that_never_applies_is_reported(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Silent metadata loss is what made the CLI report a live session as unknown."""
    _install_fake_run_command(monkeypatch, sessions=[_row(handed_off="0")])

    with caplog.at_level("ERROR", logger="pentaia.phase3_session"):
        phase3_session.set_session_metadata(NAME, {"handed_off": 1})

    assert any("could not be recorded" in record.getMessage() for record in caplog.records)


def test_close_reports_when_missing_metadata_skips_the_port_release(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A skipped release must be visible, not identical to one that found nothing."""
    _install_fake_run_command(
        monkeypatch,
        sessions=[_row(target="", action="", lport="", rport="")],
    )
    released: list[dict] = []
    monkeypatch.setattr(
        phase3_session,
        "release_listener_port",
        lambda **kwargs: released.append(kwargs) or True,
    )

    with caplog.at_level("WARNING", logger="pentaia.phase3_session"):
        result = close_live_session(NAME)

    assert released == []
    assert result.port_released is False
    assert any(
        "reason=missing_metadata" in record.getMessage() for record in caplog.records
    )


# --- lifecycle audit -------------------------------------------------------


def test_lifecycle_events_are_structured_and_avoid_raw_output(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level("INFO", logger="pentaia.phase3.session"):
        audit_session_event("closed", session=NAME, stopped=True, artifact_path="/tmp/x.txt")

    line = caplog.records[0].getMessage()

    assert "phase3 session event=closed" in line
    assert f"session={NAME}" in line
    assert "artifact_path=/tmp/x.txt" in line


# --- cli -------------------------------------------------------------------


def test_cli_without_a_subcommand_prints_usage() -> None:
    captured: list[str] = []

    assert run_session_command([], output=captured.append) == 2
    assert any("Usage: pentaia session" in line for line in captured)


def test_cli_rejects_an_unknown_subcommand() -> None:
    captured: list[str] = []

    assert run_session_command(["wibble"], output=captured.append) == 2
    assert "Unknown session command" in captured[0]


def test_cli_list_reports_nothing_held(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(session_cli, "list_held_sessions", list)
    captured: list[str] = []

    assert run_session_command(["list"], output=captured.append) == 0
    assert "No PentAiA sessions" in captured[0]


def test_cli_list_shows_lifecycle_and_artifact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        session_cli,
        "list_held_sessions",
        lambda: [
            HeldSession(
                name=NAME,
                target="172.16.0.64",
                action_id="validate_vsftpd_234_backdoor",
                lport="5000",
                rport="21",
                artifact_path="/tmp/pentaia-poc-x.txt",
                artifact_verified=True,
                handed_off=False,
            )
        ],
    )
    captured: list[str] = []

    assert run_session_command(["list"], output=captured.append) == 0

    rendered = "\n".join(captured)
    assert "lifecycle: verified" in rendered
    assert "172.16.0.64:21" in rendered
    assert "/tmp/pentaia-poc-x.txt (verified)" in rendered


def test_cli_show_includes_recent_console_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = HeldSession(
        name=NAME,
        target="172.16.0.64",
        action_id="validate_vsftpd_234_backdoor",
        lport="5000",
        rport="21",
        artifact_path="/tmp/x.txt",
        artifact_verified=True,
        handed_off=False,
    )
    monkeypatch.setattr(session_cli, "find_held_session", lambda _name: session)
    monkeypatch.setattr(
        session_cli,
        "capture_session_evidence",
        lambda _name: "[*] Command shell session 1 opened",
    )
    captured: list[str] = []

    assert run_session_command(["show", NAME], output=captured.append) == 0

    rendered = "\n".join(captured)
    assert "lifecycle: verified" in rendered
    assert "Command shell session 1 opened" in rendered


def test_cli_show_reports_an_unknown_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(session_cli, "find_held_session", lambda _name: None)
    captured: list[str] = []

    assert run_session_command(["show", "missing"], output=captured.append) == 1
    assert "No PentAiA session named missing" in captured[0]


def test_cli_attach_marks_the_session_handed_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = HeldSession(
        name=NAME,
        target="172.16.0.64",
        action_id="validate_vsftpd_234_backdoor",
        lport="5000",
        rport="21",
        artifact_path="/tmp/x.txt",
        artifact_verified=True,
        handed_off=False,
    )
    marked: list[str] = []

    monkeypatch.setattr(session_cli, "find_held_session", lambda _name: session)
    monkeypatch.setattr(
        session_cli,
        "mark_session_handed_off",
        lambda name: marked.append(name) or True,
    )
    captured: list[str] = []

    assert run_session_command(["attach", NAME], output=captured.append) == 0

    assert marked == [NAME]
    assert f"tmux attach -t {NAME}" in "\n".join(captured)
    assert "no further commands" in "\n".join(captured)


def test_cli_close_reports_where_the_marker_was_left(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = HeldSession(
        name=NAME,
        target="172.16.0.64",
        action_id="validate_vsftpd_234_backdoor",
        lport="5000",
        rport="21",
        artifact_path="/tmp/x.txt",
        artifact_verified=True,
        handed_off=False,
    )
    monkeypatch.setattr(session_cli, "find_held_session", lambda _name: session)
    monkeypatch.setattr(
        session_cli,
        "close_live_session",
        lambda name: phase3_session.SessionClose(
            name=name,
            closed=True,
            artifact_path="/tmp/x.txt",
            artifact_message="The proof marker was left in place on the target at /tmp/x.txt.",
            port_released=True,
        ),
    )
    captured: list[str] = []

    assert run_session_command(["close", NAME], output=captured.append) == 0

    rendered = "\n".join(captured)
    assert "Closed:" in rendered
    assert "left in place" in rendered
    assert "port was released" in rendered


def test_cli_close_cannot_be_asked_to_delete_the_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The old cleanup flag is gone; passing it must not delete anything."""
    session = HeldSession(
        name=NAME,
        target="172.16.0.64",
        action_id="validate_vsftpd_234_backdoor",
        lport="5000",
        rport="21",
        artifact_path="/tmp/x.txt",
        artifact_verified=True,
        handed_off=False,
    )
    seen: dict = {}

    monkeypatch.setattr(session_cli, "find_held_session", lambda _name: session)

    def fake_close(name):
        seen["called"] = name
        return phase3_session.SessionClose(
            name=name,
            closed=True,
            artifact_path="/tmp/x.txt",
            artifact_message="The proof marker was left in place on the target at /tmp/x.txt.",
            port_released=False,
        )

    monkeypatch.setattr(session_cli, "close_live_session", fake_close)
    captured: list[str] = []

    assert (
        run_session_command(["close", NAME, "--keep-artifact"], output=captured.append) == 0
    )
    assert seen["called"] == NAME
    assert "left in place" in "\n".join(captured)
    assert "--keep-artifact" not in session_cli.USAGE


def test_cli_reports_a_failure_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An operator command that cannot reach the host should say so, not crash."""

    def explode(_output):
        raise RuntimeError("Kali host unreachable")

    monkeypatch.setattr(session_cli, "_list", explode)
    captured: list[str] = []

    assert run_session_command(["list"], output=captured.append) == 1

    rendered = "\n".join(captured)
    assert "Session command failed" in rendered
    assert "Kali host unreachable" in rendered
    assert "Traceback" not in rendered
