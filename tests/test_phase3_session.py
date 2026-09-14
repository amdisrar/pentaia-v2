import pytest

from pentaia import phase3_session
from pentaia.approval import (
    Phase3ActionProposal,
    approve_phase3_action,
    create_pending_approval,
)
from pentaia.metasploit_wrapper import (
    PREDEFINED_METASPLOIT_OPERATIONS,
    MetasploitOperation,
    prepare_metasploit_parameters,
)
from pentaia.phase3_ports import (
    release_listener_port,
    reset_listener_port_reservations,
)
from pentaia.phase3_session import (
    SESSION_PREFIX,
    attach_command,
    build_console_command,
    capture_session_evidence,
    live_session_running,
    session_established,
    session_name,
    start_live_session,
    stop_live_session,
    validate_session_name,
    wait_for_session,
)

PANE_WITH_SESSION = (
    "[+] 172.16.0.64:21 - Backdoor has been spawned!\n"
    "[*] Command shell session 1 opened (172.16.0.13:4444 -> 172.16.0.64:44644)\n"
)
PANE_WITHOUT_SESSION = "[*] Started reverse TCP handler on 172.16.0.13:4444\n"


def _configure_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.13")
    monkeypatch.setenv("PENTAIA_LPORT", "4444")
    monkeypatch.delenv("PENTAIA_LPORT_MIN", raising=False)
    monkeypatch.delenv("PENTAIA_LPORT_MAX", raising=False)
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.64")
    monkeypatch.delenv("PENTAIA_PHASE3_DENYLIST", raising=False)


@pytest.fixture(autouse=True)
def isolated_listener_ports():
    reset_listener_port_reservations()
    yield
    reset_listener_port_reservations()


def _proposal() -> Phase3ActionProposal:
    # Build real runtime-owned values, which also establishes the listener port
    # reservation the console path now requires.
    parameters = prepare_metasploit_parameters(
        "validate_vsftpd_234_backdoor",
        {"rport": 21},
        target="172.16.0.64",
    )
    return Phase3ActionProposal(
        action_id="validate_vsftpd_234_backdoor",
        target="172.16.0.64",
        rationale="normalized source evidence",
        expected_effect="controlled validation",
        parameters=parameters,
    )


def _approved(proposal: Phase3ActionProposal):
    return approve_phase3_action(
        create_pending_approval(proposal),
        proposal_signature=proposal.signature(),
    )


def _install_fake_run_command(
    monkeypatch: pytest.MonkeyPatch,
    *,
    running_before: bool = False,
    new_session_ok: bool = True,
    pane: str = PANE_WITH_SESSION,
    capture_ok: bool = True,
) -> tuple[list[str], dict[str, bool]]:
    """Answer tmux probes deterministically and record issued commands."""
    issued: list[str] = []
    state = {"running": running_before}

    def fake_run_command(command: str, timeout: int):
        issued.append(command)

        if command.startswith("tmux has-session"):
            return "", "", 0 if state["running"] else 1

        if command.startswith("tmux new-session"):
            if not new_session_ok:
                return "", "failed", 1
            state["running"] = True
            return "", "", 0

        if command.startswith("tmux capture-pane"):
            return (pane, "", 0) if capture_ok else ("", "failed", 1)

        if command.startswith("tmux kill-session"):
            state["running"] = False
            return "", "", 0

        return "", "", 0

    monkeypatch.setattr(phase3_session, "run_command", fake_run_command)

    return issued, state


# --- session naming --------------------------------------------------------


def test_session_name_is_deterministic_and_prefixed() -> None:
    first = session_name(action_id="validate_vsftpd_234_backdoor", target="172.16.0.64")
    second = session_name(action_id="validate_vsftpd_234_backdoor", target="172.16.0.64")

    assert first == second
    assert first.startswith(SESSION_PREFIX)


def test_session_name_differs_per_target() -> None:
    assert session_name(
        action_id="validate_vsftpd_234_backdoor", target="172.16.0.64"
    ) != session_name(action_id="validate_vsftpd_234_backdoor", target="172.16.0.65")


def test_session_name_is_shell_and_tmux_safe() -> None:
    name = session_name(
        action_id="validate; rm -rf / tmp:evil.name",
        target="172.16.0.64",
    )

    for unsafe in [";", " ", ":", ".", "/", "$", "`"]:
        assert unsafe not in name

    assert len(name) <= 64


@pytest.mark.parametrize(
    "value",
    ["", "   ", "bad name", "bad;name", "bad:name", "bad.name", "bad/name", None, 7],
)
def test_unsafe_session_names_are_rejected(value) -> None:
    with pytest.raises(ValueError):
        validate_session_name(value)


def test_unsafe_session_names_never_reach_the_executor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issued, _ = _install_fake_run_command(monkeypatch)

    with pytest.raises(ValueError):
        stop_live_session("bad;name")

    assert issued == []


def test_attach_command_is_human_facing() -> None:
    assert attach_command("pentaia-phase3-test") == "tmux attach -t pentaia-phase3-test"

    with pytest.raises(ValueError):
        attach_command("bad;name")


# --- console command -------------------------------------------------------


def test_console_command_keeps_the_console_alive() -> None:
    operation = PREDEFINED_METASPLOIT_OPERATIONS["validate_vsftpd_234_backdoor"]

    command = build_console_command(
        operation,
        "172.16.0.64",
        {"rport": 21, "lhost": "172.16.0.13", "lport": 4444},
    )

    assert command.startswith("msfconsole -q -x ")
    assert "run -z" in command
    # The console must outlive the SSH call that starts it.
    assert "exit -y" not in command
    assert not command.startswith("timeout ")
    # The approved runtime-owned values must be what the console is told.
    assert "set LHOST 172.16.0.13" in command
    assert "set LPORT 4444" in command
    assert "set PAYLOAD cmd/unix/reverse_perl" in command


# --- evidence --------------------------------------------------------------


@pytest.mark.parametrize(
    "evidence",
    [
        "[*] Command shell session 1 opened (172.16.0.13:4444 -> 172.16.0.64:1)",
        "[*] Meterpreter session 2 opened",
    ],
)
def test_session_evidence_is_recognised(evidence: str) -> None:
    assert session_established(evidence) is True


@pytest.mark.parametrize(
    "evidence",
    ["", PANE_WITHOUT_SESSION, "[+] Backdoor has been spawned!"],
)
def test_session_evidence_without_a_session_is_not_recognised(evidence: str) -> None:
    assert session_established(evidence) is False


def test_session_evidence_must_be_text() -> None:
    with pytest.raises(ValueError, match="evidence must be a string"):
        session_established(None)  # type: ignore[arg-type]


def test_wait_for_session_returns_as_soon_as_it_is_caught(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_run_command(monkeypatch, pane=PANE_WITH_SESSION)

    slept: list[float] = []

    evidence = wait_for_session(
        "pentaia-phase3-test",
        attempts=5,
        delay=1.0,
        sleeper=slept.append,
    )

    assert "command shell session" in evidence.lower()
    assert slept == []


def test_wait_for_session_gives_up_and_returns_last_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_run_command(monkeypatch, pane=PANE_WITHOUT_SESSION)

    slept: list[float] = []

    evidence = wait_for_session(
        "pentaia-phase3-test",
        attempts=3,
        delay=1.0,
        sleeper=slept.append,
    )

    assert session_established(evidence) is False
    # Two waits between three attempts.
    assert slept == [1.0, 1.0]


@pytest.mark.parametrize("attempts", [0, -1, True, "3"])
def test_wait_for_session_validates_attempts(attempts) -> None:
    with pytest.raises(ValueError, match="attempts"):
        wait_for_session("pentaia-phase3-test", attempts=attempts)


def test_capture_session_evidence_returns_console_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_run_command(monkeypatch, pane=PANE_WITH_SESSION)

    assert "Command shell session" in capture_session_evidence("pentaia-phase3-test")


def test_capture_session_evidence_raises_when_session_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_run_command(monkeypatch, capture_ok=False)

    with pytest.raises(RuntimeError, match="Unable to read"):
        capture_session_evidence("pentaia-phase3-test")


# --- lifecycle -------------------------------------------------------------


def test_live_session_running_reflects_tmux_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_run_command(monkeypatch, running_before=True)
    assert live_session_running("pentaia-phase3-test") is True

    _install_fake_run_command(monkeypatch, running_before=False)
    assert live_session_running("pentaia-phase3-test") is False


def test_stop_live_session_kills_the_console(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issued, _ = _install_fake_run_command(monkeypatch, running_before=True)

    assert stop_live_session("pentaia-phase3-test") is True
    assert issued == ["tmux kill-session -t pentaia-phase3-test"]


# --- start_live_session ----------------------------------------------------


def test_start_live_session_holds_the_console(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch)
    issued, state = _install_fake_run_command(monkeypatch)

    proposal = _proposal()
    session = start_live_session(proposal, _approved(proposal))

    assert session.established is True
    assert session.action_id == "validate_vsftpd_234_backdoor"
    assert session.target == "172.16.0.64"
    assert session.lhost == "172.16.0.13"
    assert session.lport == 4444
    assert "command shell session" in session.evidence.lower()
    assert session.session_name in session.attach
    assert state["running"] is True

    assert any(command.startswith("tmux new-session -d -s ") for command in issued)


def test_start_live_session_refuses_when_one_is_already_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch)
    issued, _ = _install_fake_run_command(monkeypatch, running_before=True)

    proposal = _proposal()

    with pytest.raises(RuntimeError, match="already running"):
        start_live_session(proposal, _approved(proposal))

    assert not any(command.startswith("tmux new-session") for command in issued)


def test_failed_catch_does_not_leave_a_console_holding_the_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch)
    issued, state = _install_fake_run_command(monkeypatch, pane=PANE_WITHOUT_SESSION)

    # Avoid a real 30s poll: the console never catches a session here.
    monkeypatch.setattr(phase3_session, "wait_for_session", lambda _name: "")

    proposal = _proposal()
    session = start_live_session(proposal, _approved(proposal))

    assert session.established is False
    assert session.evidence == ""
    assert state["running"] is False
    assert any(command.startswith("tmux kill-session") for command in issued)


def test_start_live_session_requires_explicit_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch)
    issued, _ = _install_fake_run_command(monkeypatch)

    with pytest.raises(ValueError, match="explicit human approval"):
        start_live_session(_proposal(), None)

    assert not any(command.startswith("tmux new-session") for command in issued)


def test_start_live_session_rejects_unauthorized_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch)
    issued, _ = _install_fake_run_command(monkeypatch)

    proposal = Phase3ActionProposal(
        action_id="validate_vsftpd_234_backdoor",
        target="172.16.0.99",
        rationale="normalized source evidence",
        expected_effect="controlled validation",
        parameters={"rport": 21, "lhost": "172.16.0.13", "lport": 4444},
    )

    with pytest.raises(ValueError, match="not explicitly authorized"):
        start_live_session(proposal, _approved(proposal))

    assert not any(command.startswith("tmux new-session") for command in issued)


def test_released_reservation_blocks_before_the_console_starts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A released reservation means the approved port is no longer held for us."""
    _configure_env(monkeypatch)
    issued, _ = _install_fake_run_command(monkeypatch)

    proposal = _proposal()
    approval = _approved(proposal)

    release_listener_port(
        action_id=proposal.action_id,
        target=proposal.target,
        rport=21,
    )

    with pytest.raises(ValueError, match="reservation is no longer valid"):
        start_live_session(proposal, approval)

    assert not any(command.startswith("tmux new-session") for command in issued)


def test_stale_callback_address_blocks_before_the_console_starts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch)
    issued, _ = _install_fake_run_command(monkeypatch)

    proposal = _proposal()
    approval = _approved(proposal)
    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.14")

    with pytest.raises(ValueError, match="callback configuration changed"):
        start_live_session(proposal, approval)

    assert not any(command.startswith("tmux new-session") for command in issued)


def test_action_without_a_reverse_session_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch)
    _install_fake_run_command(monkeypatch)

    # Build the approved proposal while the real operation is still registered,
    # then strip the reverse-session capability the console path requires.
    proposal = _proposal()
    approval = _approved(proposal)

    original = PREDEFINED_METASPLOIT_OPERATIONS["validate_vsftpd_234_backdoor"]
    monkeypatch.setitem(
        PREDEFINED_METASPLOIT_OPERATIONS,
        "validate_vsftpd_234_backdoor",
        MetasploitOperation(
            action_id=original.action_id,
            module=original.module,
            establishes_reverse_session=False,
        ),
    )

    with pytest.raises(ValueError, match="does not establish a reverse session"):
        start_live_session(proposal, approval)


def test_unknown_action_id_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch)
    _install_fake_run_command(monkeypatch)

    proposal = Phase3ActionProposal(
        action_id="arbitrary_msfconsole",
        target="172.16.0.64",
        rationale="normalized source evidence",
        expected_effect="controlled validation",
        parameters={"rport": 21, "lhost": "172.16.0.13", "lport": 4444},
    )

    with pytest.raises(ValueError, match="Unsupported Phase 3 Metasploit action"):
        start_live_session(proposal, _approved(proposal))
