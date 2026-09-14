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
    send_keys_ok: bool = True,
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

        if command.startswith("tmux send-keys"):
            return "", "" if send_keys_ok else "no such session", 0 if send_keys_ok else 1

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


# --- close and cleanup -----------------------------------------------------


def test_close_removes_the_marker_and_releases_the_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issued = _install_fake_run_command(monkeypatch, sessions=[_row()])
    released: list[dict] = []

    monkeypatch.setattr(
        phase3_session,
        "release_listener_port",
        lambda **kwargs: released.append(kwargs) or True,
    )

    result = close_live_session(NAME)

    assert result.closed is True
    assert result.artifact_removed is True
    assert result.port_released is True
    assert any("rm -f" in command for command in issued)
    assert any(command.startswith("tmux kill-session") for command in issued)
    assert released == [
        {
            "action_id": "validate_vsftpd_234_backdoor",
            "target": "172.16.0.64",
            "rport": 21,
        }
    ]


def test_close_can_keep_the_marker_and_says_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issued = _install_fake_run_command(monkeypatch, sessions=[_row()])
    monkeypatch.setattr(phase3_session, "release_listener_port", lambda **k: True)

    result = close_live_session(NAME, remove_artifact=False)

    assert result.artifact_removed is False
    assert result.artifact_path == f"/tmp/pentaia-poc-{DIGEST}.txt"
    assert "remains on the target" in result.artifact_message
    # Cleanup must be a code-owned operation, and skipping it must not send one.
    assert not any("rm -f" in command for command in issued)


def test_close_reports_the_marker_path_even_when_the_session_is_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The digest in the name still locates the marker for cleanup."""
    _install_fake_run_command(monkeypatch, sessions=[])
    monkeypatch.setattr(phase3_session, "release_listener_port", lambda **k: False)

    result = close_live_session(NAME)

    assert result.artifact_path == f"/tmp/pentaia-poc-{DIGEST}.txt"


@pytest.mark.parametrize("rport", ["", "not-a-port", "21; rm -rf /"])
def test_close_tolerates_unreadable_port_metadata(
    monkeypatch: pytest.MonkeyPatch,
    rport: str,
) -> None:
    """Metadata comes back from tmux, so a bad port must not abort the cleanup."""
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
    assert result.artifact_removed is True


def test_close_removes_the_marker_named_by_the_session_without_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The live failure: empty metadata made cleanup delete a different file.

    Deriving the marker path from metadata turned a missing target into
    ``rm -f /tmp/pentaia-poc-e7ac0786668e.txt`` -- a file that never existed --
    while the real marker stayed on the target and the CLI reported success.
    """
    issued = _install_fake_run_command(
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

    cleanup = [command for command in issued if "rm -f" in command]
    assert len(cleanup) == 1
    assert f"/tmp/pentaia-poc-{DIGEST}.txt" in cleanup[0]
    # The digest of two empty strings must never be what cleanup targets.
    assert "e7ac0786668e" not in cleanup[0]


def test_removal_refuses_a_path_outside_the_marker_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_run_command(monkeypatch, sessions=[_row()])

    for path in ("/etc/passwd", "/tmp", "", "rm -rf /"):
        with pytest.raises(ValueError):
            phase3_session.remove_verification_artifact(
                console_session=NAME,
                path=path,
            )


def test_close_does_not_claim_removal_when_the_console_rejects_the_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An ignored send-keys exit code is how a cleanup gets claimed but never sent."""
    _install_fake_run_command(monkeypatch, sessions=[_row()], send_keys_ok=False)
    monkeypatch.setattr(phase3_session, "release_listener_port", lambda **k: True)

    result = close_live_session(NAME)

    assert result.artifact_removed is False
    assert "may still be on the target" in result.artifact_message


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


# --- lifecycle audit -------------------------------------------------------


def test_lifecycle_events_are_structured_and_avoid_raw_output(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level("INFO", logger="pentaia.phase3.session"):
        audit_session_event("closed", session=NAME, stopped=True, artifact_removed=True)

    line = caplog.records[0].getMessage()

    assert "phase3 session event=closed" in line
    assert f"session={NAME}" in line
    assert "artifact_removed=True" in line


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


def test_cli_close_reports_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
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
        lambda name, remove_artifact=True: phase3_session.SessionClose(
            name=name,
            closed=True,
            artifact_path="/tmp/x.txt",
            artifact_removed=remove_artifact,
            artifact_message="Removal of /tmp/x.txt was requested on the target.",
            port_released=True,
        ),
    )
    captured: list[str] = []

    assert run_session_command(["close", NAME], output=captured.append) == 0

    rendered = "\n".join(captured)
    assert "Closed:" in rendered
    assert "port was released" in rendered


def test_cli_close_keep_artifact_flag(monkeypatch: pytest.MonkeyPatch) -> None:
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

    def fake_close(name, *, remove_artifact=True):
        seen["remove_artifact"] = remove_artifact
        return phase3_session.SessionClose(
            name=name,
            closed=True,
            artifact_path="/tmp/x.txt",
            artifact_removed=False,
            artifact_message="The proof marker remains on the target at /tmp/x.txt.",
            port_released=False,
        )

    monkeypatch.setattr(session_cli, "close_live_session", fake_close)
    captured: list[str] = []

    assert run_session_command(["close", NAME, "--keep-artifact"], output=captured.append) == 0
    assert seen["remove_artifact"] is False
    assert "remains on the target" in "\n".join(captured)


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
