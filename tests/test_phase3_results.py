import json

from pentaia.approval import (
    Phase3ActionProposal,
    approve_phase3_action,
    create_pending_approval,
)
from pentaia.metasploit_wrapper import MetasploitExecutionResult
from pentaia.phase3_results import (
    PHASE3_INTERPRETATION_RULES,
    normalize_phase3_result,
)


def _proposal() -> Phase3ActionProposal:
    return Phase3ActionProposal(
        action_id="validate_vsftpd_234_backdoor",
        target="172.16.0.64",
        rationale="scanner=nuclei; template=example; cve=CVE-2011-2523",
        expected_effect="controlled validation",
        parameters={"rport": 21},
    )


def _approved(proposal: Phase3ActionProposal):
    pending = create_pending_approval(proposal)
    return approve_phase3_action(
        pending,
        proposal_signature=proposal.signature(),
    )


def _execution(exit_code: int = 0) -> MetasploitExecutionResult:
    return MetasploitExecutionResult(
        action_id="validate_vsftpd_234_backdoor",
        target="172.16.0.64",
        module="code-owned-module",
        parameters={"rport": 21},
        stdout="operation completed",
        stderr="",
        exit_code=exit_code,
    )


def test_clean_exit_is_conservatively_inconclusive() -> None:
    proposal = _proposal()
    result = normalize_phase3_result(
        proposal=proposal,
        approval=_approved(proposal),
        tool_status="success",
        execution_result=_execution(0),
    )

    assert result.execution_status == "completed"
    assert result.outcome == "inconclusive"
    assert result.exit_code == 0


def test_failed_execution_normalizes_as_failed() -> None:
    proposal = _proposal()
    result = normalize_phase3_result(
        proposal=proposal,
        approval=_approved(proposal),
        tool_status="failed",
        execution_result=_execution(1),
    )

    assert result.execution_status == "failed"
    assert result.outcome == "failed"
    assert result.exit_code == 1


def test_blocked_result_records_not_run_and_missing_approval() -> None:
    proposal = _proposal()
    result = normalize_phase3_result(
        proposal=proposal,
        approval=None,
        tool_status="blocked",
        error="approval required",
    )

    assert result.execution_status == "not_run"
    assert result.outcome == "blocked"
    assert result.approval_decision == "missing"
    assert result.exit_code is None
    assert result.error == "approval required"


def test_runtime_error_normalizes_as_error() -> None:
    proposal = _proposal()
    result = normalize_phase3_result(
        proposal=proposal,
        approval=_approved(proposal),
        tool_status="error",
        error="executor unavailable",
    )

    assert result.execution_status == "error"
    assert result.outcome == "error"
    assert result.error == "executor unavailable"


def test_result_preserves_signed_traceability_context() -> None:
    proposal = _proposal()
    approval = _approved(proposal)
    result = normalize_phase3_result(
        proposal=proposal,
        approval=approval,
        tool_status="success",
        execution_result=_execution(),
    )

    assert result.target == proposal.target
    assert result.action_id == proposal.action_id
    assert result.proposal_signature == proposal.signature()
    assert result.originating_finding_reference == proposal.rationale
    assert result.approval_decision == "approved"


def test_result_json_is_stable_and_contains_compact_evidence() -> None:
    proposal = _proposal()
    result = normalize_phase3_result(
        proposal=proposal,
        approval=_approved(proposal),
        tool_status="success",
        execution_result=_execution(),
    )

    payload = json.loads(result.to_json())
    assert payload["source_tool"] == "phase3_controlled_validation"
    assert payload["evidence"] == "stdout: operation completed"
    assert payload["outcome"] == "inconclusive"


def test_interpretation_rules_prevent_exit_code_overstatement() -> None:
    assert "exit_code=0" in PHASE3_INTERPRETATION_RULES
    assert "inconclusive" in PHASE3_INTERPRETATION_RULES
    assert "Do not claim impact" in PHASE3_INTERPRETATION_RULES
