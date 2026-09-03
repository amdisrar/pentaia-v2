import logging

from pentaia.approval import (
    Phase3ActionProposal,
    approve_phase3_action,
    create_pending_approval,
)
from pentaia.phase3_audit import (
    audit_approval,
    audit_failure,
    audit_proposal,
    audit_result,
    build_audit_context,
    user_safe_failure_message,
)
from pentaia.phase3_results import Phase3NormalizedResult


def _proposal() -> Phase3ActionProposal:
    return Phase3ActionProposal(
        action_id="validate_vsftpd_234_backdoor",
        target="172.16.0.64",
        rationale="scanner evidence containing sensitive-looking context",
        expected_effect="controlled validation",
        parameters={"rport": 21, "lhost": "172.16.0.13"},
    )


def _approved():
    proposal = _proposal()
    pending = create_pending_approval(proposal)
    return approve_phase3_action(
        pending,
        proposal_signature=proposal.signature(),
    )


def test_audit_context_uses_reference_id_instead_of_raw_finding_text() -> None:
    proposal = _proposal()
    context = build_audit_context(proposal, None)

    assert context.action_id == proposal.action_id
    assert context.target == proposal.target
    assert context.proposal_signature == proposal.signature()
    assert context.approval_decision == "missing"
    assert context.finding_reference_id
    assert proposal.rationale not in context.finding_reference_id


def test_proposal_log_does_not_include_raw_rationale(caplog) -> None:
    proposal = _proposal()

    with caplog.at_level(logging.INFO, logger="pentaia.phase3.audit"):
        audit_proposal(proposal, None)

    text = caplog.text
    assert "event=proposal" in text
    assert proposal.signature() in text
    assert proposal.rationale not in text


def test_approval_log_records_decision_without_raw_rationale(caplog) -> None:
    approval = _approved()

    with caplog.at_level(logging.INFO, logger="pentaia.phase3.audit"):
        audit_approval(approval)

    assert "event=approval" in caplog.text
    assert "decision=approved" in caplog.text
    assert approval.proposal.rationale not in caplog.text


def test_result_log_records_outcome_without_raw_evidence(caplog) -> None:
    proposal = _proposal()
    result = Phase3NormalizedResult(
        target=proposal.target,
        action_id=proposal.action_id,
        approval_decision="approved",
        proposal_signature=proposal.signature(),
        execution_status="completed",
        outcome="inconclusive",
        exit_code=0,
        evidence="raw returned evidence that should not be logged",
        source_tool="phase3_controlled_validation",
        originating_finding_reference=proposal.rationale,
        error=None,
    )

    with caplog.at_level(logging.INFO, logger="pentaia.phase3.audit"):
        audit_result(result)

    assert "event=result" in caplog.text
    assert "outcome=inconclusive" in caplog.text
    assert "evidence_chars=" in caplog.text
    assert result.evidence not in caplog.text
    assert proposal.rationale not in caplog.text


def test_failure_log_records_category_and_type_not_error_text(caplog) -> None:
    proposal = _proposal()
    secret_text = "credential-looking-value"

    with caplog.at_level(logging.WARNING, logger="pentaia.phase3.audit"):
        audit_failure(
            proposal,
            None,
            category="unavailable",
            error=RuntimeError(secret_text),
        )

    assert "event=failure" in caplog.text
    assert "category=unavailable" in caplog.text
    assert "error_type=RuntimeError" in caplog.text
    assert secret_text not in caplog.text


def test_user_safe_failure_messages_are_concise() -> None:
    assert "blocked" in user_safe_failure_message("blocked").lower()
    assert "timed out" in user_safe_failure_message("timeout").lower()
    assert "unavailable" in user_safe_failure_message("unavailable").lower()
    assert "traceback" not in user_safe_failure_message("execution").lower()
