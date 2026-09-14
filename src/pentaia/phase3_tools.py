import json
import logging
from typing import Annotated, Literal

from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState

from pentaia.approval import Phase3ActionProposal, Phase3ApprovalState
from pentaia.metasploit_wrapper import (
    PREDEFINED_METASPLOIT_OPERATIONS,
    prepare_metasploit_parameters,
    run_metasploit_action,
)
from pentaia.phase3_audit import (
    audit_failure,
    audit_proposal,
    audit_result,
    user_safe_failure_message,
)
from pentaia.phase3_results import normalize_phase3_result
from pentaia.phase3_session import start_live_session

logger = logging.getLogger(__name__)

Phase3ActionId = Literal["validate_vsftpd_234_backdoor"]

# Phase 3 actions that establish a reverse session leave it held open on the Kali
# host, because PentAiA never drives an interactive session itself. The operator
# takes it over from the printed console.
SESSION_HANDOFF = (
    "A reverse session is held open in the PentAiA console on the Kali host. "
    "The operator takes it over by running the attach command on Kali, listing "
    "sessions with 'sessions', and selecting one with 'sessions -i <id>'. "
    "PentAiA issues no further commands through that session."
)


def _response(
    *,
    status: str,
    action_id: str,
    target: str,
    result: dict | None = None,
    normalized_result: dict | None = None,
    session: dict | None = None,
    error: str | None = None,
) -> str:
    payload = {
        "status": status,
        "changes_state": True,
        "action_id": action_id,
        "target": target,
        "result": result,
        "normalized_result": normalized_result,
        "session": session,
        "error": error,
    }
    return json.dumps(payload, sort_keys=True)


def _base_proposal(
    *,
    action_id: Phase3ActionId,
    target: str,
    rationale: str,
    expected_effect: str,
    rport: int,
) -> Phase3ActionProposal:
    return Phase3ActionProposal(
        action_id=action_id,
        target=target,
        rationale=rationale,
        expected_effect=expected_effect,
        parameters={"rport": rport},
    )


def _runtime_failure_category(exc: RuntimeError) -> str:
    message = str(exc).lower()
    if "timed out" in message or "timeout" in message:
        return "timeout"
    if "already running" in message:
        return "conflict"
    if (
        "unavailable" in message
        or "unable to connect" in message
        or "authentication failed" in message
        or "missing kali connection configuration" in message
    ):
        return "unavailable"
    return "execution"


def _run_phase3_validation_tool(
    *,
    action_id: Phase3ActionId,
    target: str,
    rationale: str,
    expected_effect: str,
    rport: int,
    approval: Phase3ApprovalState | None,
) -> str:
    """Execute one already-approved, code-owned Phase 3 validation proposal."""
    base_proposal = _base_proposal(
        action_id=action_id,
        target=target,
        rationale=rationale,
        expected_effect=expected_effect,
        rport=rport,
    )

    logger.info(
        "Phase 3 LangChain tool requested action_id=%s target=%s",
        action_id,
        target,
    )

    operation = PREDEFINED_METASPLOIT_OPERATIONS.get(action_id)
    holds_session = operation is not None and operation.establishes_reverse_session

    try:
        parameters = prepare_metasploit_parameters(
            action_id,
            {"rport": rport},
            target=target,
        )
        proposal = Phase3ActionProposal(
            action_id=action_id,
            target=target,
            rationale=rationale,
            expected_effect=expected_effect,
            parameters=parameters,
        )
        audit_proposal(proposal, approval)

        if holds_session:
            # The approved effect is a held reverse session, so the action runs
            # once inside a detached console that keeps the shell. The console
            # pane - not a process exit status - is the evidence.
            session = start_live_session(proposal, approval)
            result = None
        else:
            session = None
            result = run_metasploit_action(proposal, approval)
    except ValueError as exc:
        proposal_for_audit = locals().get("proposal", base_proposal)
        logger.warning(
            "Phase 3 LangChain tool blocked action_id=%s target=%s error_type=%s",
            action_id,
            target,
            type(exc).__name__,
        )
        audit_failure(
            proposal_for_audit,
            approval,
            category="blocked",
            error=exc,
        )
        normalized = normalize_phase3_result(
            proposal=proposal_for_audit,
            approval=approval,
            tool_status="blocked",
            error=str(exc),
        )
        audit_result(normalized)
        return _response(
            status="blocked",
            action_id=action_id,
            target=target,
            normalized_result=normalized.to_dict(),
            error=user_safe_failure_message("blocked"),
        )
    except RuntimeError as exc:
        proposal_for_audit = locals().get("proposal", base_proposal)
        category = _runtime_failure_category(exc)
        logger.error(
            "Phase 3 LangChain tool failed action_id=%s target=%s category=%s error_type=%s",
            action_id,
            target,
            category,
            type(exc).__name__,
        )
        audit_failure(
            proposal_for_audit,
            approval,
            category=category,
            error=exc,
        )
        normalized = normalize_phase3_result(
            proposal=proposal_for_audit,
            approval=approval,
            tool_status="error",
            error=str(exc),
        )
        audit_result(normalized)
        return _response(
            status="error",
            action_id=action_id,
            target=target,
            normalized_result=normalized.to_dict(),
            error=user_safe_failure_message(category),
        )

    if holds_session:
        status = "success" if session.established else "failed"
        normalized = normalize_phase3_result(
            proposal=proposal,
            approval=approval,
            tool_status=status,
            session_evidence=session.evidence,
        )
        session_payload = (
            {
                "name": session.session_name,
                "established": True,
                "lhost": session.lhost,
                "lport": session.lport,
                "attach": session.attach,
                "handoff": SESSION_HANDOFF,
            }
            if session.established
            else None
        )
    else:
        status = "success" if result.exit_code == 0 else "failed"
        normalized = normalize_phase3_result(
            proposal=proposal,
            approval=approval,
            tool_status=status,
            execution_result=result,
        )
        session_payload = None

    audit_result(normalized)
    return _response(
        status=status,
        action_id=action_id,
        target=target,
        result=result.to_dict() if result is not None else None,
        normalized_result=normalized.to_dict(),
        session=session_payload,
    )


@tool
def phase3_controlled_validation(
    action_id: Phase3ActionId,
    target: str,
    rationale: str,
    expected_effect: str,
    rport: int,
    approval: Annotated[
        Phase3ApprovalState | None,
        InjectedState("pending_approval"),
    ],
) -> str:
    """Run one predefined Phase 3 validation action in an authorized lab.

    Use this tool only when normalized Phase 2 evidence has already mapped to the
    named supported action and the exact proposal has received explicit human
    approval. The approval value is injected from LangGraph state and is not a
    model-controlled argument. Runtime-owned callback configuration is resolved by
    PentAiA, included in the exact proposal, and revalidated before execution.

    Returns structured JSON containing both raw execution context and a conservative
    normalized result for downstream interpretation.
    """
    return _run_phase3_validation_tool(
        action_id=action_id,
        target=target,
        rationale=rationale,
        expected_effect=expected_effect,
        rport=rport,
        approval=approval,
    )


phase3_controlled_validation.metadata = {
    "changes_state": True,
    "requires_human_approval": True,
    "phase": 3,
}
