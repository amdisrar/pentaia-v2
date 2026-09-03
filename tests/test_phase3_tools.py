import json

import pytest

from pentaia.approval import Phase3ApprovalState
from pentaia.metasploit_wrapper import MetasploitExecutionResult
from pentaia.phase3_tools import (
    _run_phase3_validation_tool,
    phase3_controlled_validation,
)


def test_tool_schema_hides_injected_approval() -> None:
    schema = phase3_controlled_validation.tool_call_schema.model_json_schema()

    assert "approval" not in schema["properties"]
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


def test_helper_routes_exact_proposal_to_controlled_wrapper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = {}
    approval = object()

    def fake_run(proposal, provided_approval):
        captured["proposal"] = proposal
        captured["approval"] = provided_approval
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
    assert proposal.parameters == {"rport": 21}
    assert captured["approval"] is approval
    assert payload["status"] == "success"
    assert payload["changes_state"] is True
    assert payload["error"] is None
    assert payload["normalized_result"]["outcome"] == "inconclusive"
    assert payload["normalized_result"]["execution_status"] == "completed"


def test_helper_returns_structured_block_when_approval_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(proposal, approval: Phase3ApprovalState | None):
        raise ValueError("Phase 3 action requires explicit human approval.")

    monkeypatch.setattr("pentaia.phase3_tools.run_metasploit_action", fake_run)

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
    assert payload["error"] == "Phase 3 action requires explicit human approval."
    assert payload["result"] is None
    assert payload["status"] == "blocked"
    assert payload["target"] == "172.16.0.64"
    assert payload["normalized_result"]["outcome"] == "blocked"
    assert payload["normalized_result"]["execution_status"] == "not_run"


def test_helper_returns_structured_error_for_runtime_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(proposal, approval):
        raise RuntimeError("controlled executor unavailable")

    monkeypatch.setattr("pentaia.phase3_tools.run_metasploit_action", fake_run)

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
    assert payload["error"] == "controlled executor unavailable"
    assert payload["normalized_result"]["outcome"] == "error"
    assert payload["normalized_result"]["execution_status"] == "error"


def test_tool_action_id_is_code_owned_literal() -> None:
    schema = phase3_controlled_validation.tool_call_schema.model_json_schema()
    action_schema = schema["properties"]["action_id"]

    if "const" in action_schema:
        assert action_schema["const"] == "validate_vsftpd_234_backdoor"
    else:
        assert action_schema["enum"] == ["validate_vsftpd_234_backdoor"]
