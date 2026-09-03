import hashlib
import logging
from dataclasses import dataclass

from pentaia.approval import Phase3ActionProposal, Phase3ApprovalState
from pentaia.phase3_results import Phase3NormalizedResult

logger = logging.getLogger("pentaia.phase3.audit")


@dataclass(frozen=True)
class Phase3AuditContext:
    action_id: str
    target: str
    proposal_signature: str
    approval_decision: str
    finding_reference_id: str


def _reference_id(value: str) -> str:
    """Return a stable short identifier without logging raw evidence text."""
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:16]


def build_audit_context(
    proposal: Phase3ActionProposal,
    approval: Phase3ApprovalState | None,
) -> Phase3AuditContext:
    return Phase3AuditContext(
        action_id=proposal.action_id,
        target=proposal.target,
        proposal_signature=proposal.signature(),
        approval_decision=approval.decision if approval is not None else "missing",
        finding_reference_id=_reference_id(proposal.rationale),
    )


def audit_proposal(
    proposal: Phase3ActionProposal,
    approval: Phase3ApprovalState | None,
) -> None:
    context = build_audit_context(proposal, approval)
    logger.info(
        "phase3 event=proposal action_id=%s target=%s proposal_signature=%s approval_decision=%s finding_reference_id=%s",
        context.action_id,
        context.target,
        context.proposal_signature,
        context.approval_decision,
        context.finding_reference_id,
    )


def audit_approval(approval: Phase3ApprovalState) -> None:
    context = build_audit_context(approval.proposal, approval)
    logger.info(
        "phase3 event=approval action_id=%s target=%s proposal_signature=%s decision=%s finding_reference_id=%s",
        context.action_id,
        context.target,
        context.proposal_signature,
        context.approval_decision,
        context.finding_reference_id,
    )


def audit_result(result: Phase3NormalizedResult) -> None:
    logger.info(
        "phase3 event=result action_id=%s target=%s proposal_signature=%s approval_decision=%s execution_status=%s outcome=%s exit_code=%s finding_reference_id=%s evidence_chars=%s error_present=%s",
        result.action_id,
        result.target,
        result.proposal_signature,
        result.approval_decision,
        result.execution_status,
        result.outcome,
        result.exit_code,
        _reference_id(result.originating_finding_reference),
        len(result.evidence),
        bool(result.error),
    )


def audit_failure(
    proposal: Phase3ActionProposal,
    approval: Phase3ApprovalState | None,
    *,
    category: str,
    error: Exception | str,
) -> None:
    context = build_audit_context(proposal, approval)
    error_type = type(error).__name__ if isinstance(error, Exception) else "error"
    logger.warning(
        "phase3 event=failure action_id=%s target=%s proposal_signature=%s approval_decision=%s finding_reference_id=%s category=%s error_type=%s",
        context.action_id,
        context.target,
        context.proposal_signature,
        context.approval_decision,
        context.finding_reference_id,
        category,
        error_type,
    )


def user_safe_failure_message(category: str) -> str:
    messages = {
        "blocked": "The requested validation was blocked by PentAiA's approval or authorization controls.",
        "timeout": "The controlled validation timed out before a reliable result was returned.",
        "unavailable": "The controlled validation tool is currently unavailable.",
        "execution": "The controlled validation could not complete successfully.",
        "malformed": "The controlled validation returned an unusable result.",
    }
    return messages.get(category, "The controlled validation could not be completed.")
