import pytest

from pentaia.approval import (
    Phase3ActionProposal,
    approve_phase3_action,
    create_pending_approval,
)
from pentaia import metasploit_wrapper


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
            else {"rport": 21, "lhost": "172.16.0.13"}
        ),
    )


def _approved(proposal: Phase3ActionProposal):
    pending = create_pending_approval(proposal)
    return approve_phase3_action(
        pending,
        proposal_signature=proposal.signature(),
    )


def test_approved_authorized_action_invokes_exact_predefined_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.64")
    monkeypatch.delenv("PENTAIA_PHASE3_DENYLIST", raising=False)

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
    assert result.parameters == {"rport": 21, "lhost": "172.16.0.13"}
    assert result.stdout == "session opened"
    assert result.stderr == ""
    assert result.exit_code == 0
    assert captured["timeout"] == 120

    command = str(captured["command"])
    assert command.startswith("msfconsole -q -x ")
    assert "exploit/unix/ftp/vsftpd_234_backdoor" in command
    assert "set RHOSTS 172.16.0.64" in command
    assert "set RPORT 21" in command
    assert "set LHOST 172.16.0.13" in command
    assert "run" in command


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

    original = _proposal(parameters={"rport": 21, "lhost": "172.16.0.13"})
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
