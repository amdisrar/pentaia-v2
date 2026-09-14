import json
from types import SimpleNamespace

import pytest

from pentaia.approval import Phase3ApprovalState
from pentaia.metasploit_wrapper import (
    PREDEFINED_METASPLOIT_OPERATIONS,
    MetasploitExecutionResult,
    MetasploitOperation,
)
from pentaia.phase3_session import LiveSession
from pentaia.phase3_tools import (
    _run_phase3_validation_tool,
    phase3_controlled_validation,
)


@pytest.fixture(autouse=True)
def configured_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.13")
    monkeypatch.setenv("PENTAIA_LPORT", "4444")


def test_tool_schema_hides_injected_approval() -> None:
    schema = phase3_controlled_validation.tool_call_schema.model_json_schema()

    assert "approval" not in schema["properties"]
    assert "lhost" not in schema["properties"]
    assert set(schema["properties"]) == {
        "action_id",
        "target",
        "rationale",
        "expected_effect",
        "rport",
    }


def test_tool_is_marked_state_changing_and_approval_required() -> None:
    assert phase3_controlled_validation.metadata == {
        "changes_state": True,
        "requires_human_approval": True,
        "phase": 3,
    }


def _live_session(proposal) -> LiveSession:
    return LiveSession(
        action_id=proposal.action_id,
        target=proposal.target,
        session_name="pentaia-phase3-test",
        lhost="172.16.0.13",
        lport=4444,
        console_command="msfconsole -q -x '...'",
        evidence="[*] Command shell session 1 opened",
        established=True,
        attach="tmux attach -t pentaia-phase3-test",
    )


def test_helper_holds_a_session_and_reports_the_handoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = {}
    approval = SimpleNamespace(decision="approved")

    def fake_start(proposal, provided_approval):
        captured["proposal"] = proposal
        captured["approval"] = provided_approval
        return _live_session(proposal)

    monkeypatch.setattr("pentaia.phase3_tools.start_live_session", fake_start)

    raw = _run_phase3_validation_tool(
        action_id="validate_vsftpd_234_backdoor",
        target="172.16.0.64",
        rationale="mapped normalized evidence",
        expected_effect="controlled validation",
        rport=21,
        approval=approval,  # type: ignore[arg-type]
    )
    payload = json.loads(raw)

    proposal = captured["proposal"]
    assert proposal.action_id == "validate_vsftpd_234_backdoor"
    assert proposal.target == "172.16.0.64"
    assert proposal.rationale == "mapped normalized evidence"
    assert proposal.expected_effect == "controlled validation"
    assert proposal.parameters == {"rport": 21, "lhost": "172.16.0.13", "lport": 4444}
    assert captured["approval"] is approval

    assert payload["status"] == "success"
    assert payload["changes_state"] is True
    assert payload["error"] is None
    # Evidence comes from the held console, so the outcome is a real success.
    assert payload["normalized_result"]["outcome"] == "success"
    assert payload["normalized_result"]["execution_status"] == "completed"
    assert payload["result"] is None

    # The operator needs the exact takeover details relayed to them.
    assert payload["session"]["name"] == "pentaia-phase3-test"
    assert payload["session"]["established"] is True
    assert payload["session"]["lhost"] == "172.16.0.13"
    assert payload["session"]["lport"] == 4444
    assert payload["session"]["attach"] == "tmux attach -t pentaia-phase3-test"
    assert payload["session"]["handoff"]


def test_unestablished_session_reports_failure_without_a_handoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_start(proposal, provided_approval):
        session = _live_session(proposal)
        return LiveSession(
            action_id=session.action_id,
            target=session.target,
            session_name=session.session_name,
            lhost=session.lhost,
            lport=session.lport,
            console_command=session.console_command,
            evidence="",
            established=False,
            attach=session.attach,
        )

    monkeypatch.setattr("pentaia.phase3_tools.start_live_session", fake_start)

    payload = json.loads(
        _run_phase3_validation_tool(
            action_id="validate_vsftpd_234_backdoor",
            target="172.16.0.64",
            rationale="mapped normalized evidence",
            expected_effect="controlled validation",
            rport=21,
            approval=SimpleNamespace(decision="approved"),  # type: ignore[arg-type]
        )
    )

    assert payload["status"] == "failed"
    assert payload["session"] is None
    assert payload["normalized_result"]["outcome"] == "failed"


def test_non_reverse_action_still_uses_the_bounded_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Operations without a reverse session keep the one-shot execution path."""
    original = PREDEFINED_METASPLOIT_OPERATIONS["validate_vsftpd_234_backdoor"]
    monkeypatch.setitem(
        PREDEFINED_METASPLOIT_OPERATIONS,
        "validate_vsftpd_234_backdoor",
        MetasploitOperation(
            action_id=original.action_id,
            module=original.module,
            payload=original.payload,
            establishes_reverse_session=False,
        ),
    )

    captured = {}

    # Isolate the dispatch decision: valid parameters, but an operation that
    # does not establish a reverse session.
    monkeypatch.setattr(
        "pentaia.phase3_tools.prepare_metasploit_parameters",
        lambda action_id, parameters, **kwargs: {
            "rport": 21,
            "lhost": "172.16.0.13",
            "lport": 4444,
        },
    )

    def fake_run(proposal, provided_approval):
        captured["proposal"] = proposal
        return MetasploitExecutionResult(
            action_id=proposal.action_id,
            target=proposal.target,
            module="code-owned-module",
            parameters=proposal.parameters,
            stdout="ok",
            stderr="",
            exit_code=0,
        )

    monkeypatch.setattr("pentaia.phase3_tools.run_metasploit_action", fake_run)

    payload = json.loads(
        _run_phase3_validation_tool(
            action_id="validate_vsftpd_234_backdoor",
            target="172.16.0.64",
            rationale="mapped normalized evidence",
            expected_effect="controlled validation",
            rport=21,
            approval=SimpleNamespace(decision="approved"),  # type: ignore[arg-type]
        )
    )

    assert captured["proposal"].action_id == "validate_vsftpd_234_backdoor"
    assert payload["session"] is None
    assert payload["result"] is not None
    # A clean exit with no demonstrating evidence stays conservative.
    assert payload["normalized_result"]["outcome"] == "inconclusive"


def test_helper_returns_structured_block_when_approval_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_start(proposal, approval: Phase3ApprovalState | None):
        raise ValueError("Phase 3 action requires explicit human approval.")

    monkeypatch.setattr("pentaia.phase3_tools.start_live_session", fake_start)

    payload = json.loads(
        _run_phase3_validation_tool(
            action_id="validate_vsftpd_234_backdoor",
            target="172.16.0.64",
            rationale="mapped normalized evidence",
            expected_effect="controlled validation",
            rport=21,
            approval=None,
        )
    )

    assert payload["action_id"] == "validate_vsftpd_234_backdoor"
    assert payload["changes_state"] is True
    assert payload["error"] == (
        "The requested validation was blocked by PentAiA's approval or authorization controls."
    )
    assert payload["result"] is None
    assert payload["status"] == "blocked"
    assert payload["target"] == "172.16.0.64"
    assert payload["normalized_result"]["outcome"] == "blocked"
    assert payload["normalized_result"]["execution_status"] == "not_run"


def test_helper_returns_structured_error_for_runtime_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_start(proposal, approval):
        raise RuntimeError("controlled executor unavailable")

    monkeypatch.setattr("pentaia.phase3_tools.start_live_session", fake_start)

    payload = json.loads(
        _run_phase3_validation_tool(
            action_id="validate_vsftpd_234_backdoor",
            target="172.16.0.64",
            rationale="mapped normalized evidence",
            expected_effect="controlled validation",
            rport=21,
            approval=None,
        )
    )

    assert payload["status"] == "error"
    assert payload["result"] is None
    assert payload["error"] == "The controlled validation tool is currently unavailable."
    assert payload["normalized_result"]["outcome"] == "error"
    assert payload["normalized_result"]["execution_status"] == "error"


def test_already_running_session_reports_a_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_start(proposal, approval):
        raise RuntimeError(
            "A PentAiA session named pentaia-phase3-test is already running on the Kali host."
        )

    monkeypatch.setattr("pentaia.phase3_tools.start_live_session", fake_start)

    payload = json.loads(
        _run_phase3_validation_tool(
            action_id="validate_vsftpd_234_backdoor",
            target="172.16.0.64",
            rationale="mapped normalized evidence",
            expected_effect="controlled validation",
            rport=21,
            approval=None,
        )
    )

    assert payload["status"] == "error"
    assert payload["error"] == (
        "A PentAiA validation session is already running; close it before starting another."
    )


def test_tool_action_id_is_code_owned_literal() -> None:
    schema = phase3_controlled_validation.tool_call_schema.model_json_schema()
    action_schema = schema["properties"]["action_id"]

    if "const" in action_schema:
        assert action_schema["const"] == "validate_vsftpd_234_backdoor"
    else:
        assert action_schema["enum"] == ["validate_vsftpd_234_backdoor"]
