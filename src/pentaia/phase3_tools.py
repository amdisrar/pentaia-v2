import json
import logging
from typing import Annotated, Literal

from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState

from pentaia.approval import Phase3ActionProposal, Phase3ApprovalState
from pentaia.metasploit_wrapper import prepare_metasploit_parameters, run_metasploit_action
from pentaia.phase3_results import normalize_phase3_result

logger = logging.getLogger(__name__)

Phase3ActionId = Literal["validate_vsftpd_234_backdoor"]


def _response(
    *,
    status: str,
    action_id: str,
    target: str,
    result: dict | None = None,
    normalized_result: dict | None = None,
    error: str | None = None,
) -> str:
    payload = {
        "status": status,
        "changes_state": True,
        "action_id": action_id,
        "target": target,
        "result": result,
        "normalized_result": normalized_result,
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

    try:
        parameters = prepare_metasploit_parameters(
            action_id,
            {"rport": rport},
        )
        proposal = Phase3ActionProposal(
            action_id=action_id,
            target=target,
            rationale=rationale,
            expected_effect=expected_effect,
            parameters=parameters,
        )
        result = run_metasploit_action(proposal, approval)
    except ValueError as exc:
        logger.warning(
            "Phase 3 LangChain tool blocked action_id=%s target=%s error=%s",
            action_id,
            target,
            exc,
        )
        normalized = normalize_phase3_result(
            proposal=base_proposal,
            approval=approval,
            tool_status="blocked",
            error=str(exc),
        )
        return _response(
            status="blocked",
            action_id=action_id,
            target=target,
            normalized_result=normalized.to_dict(),
            error=str(exc),
        )
    except RuntimeError as exc:
        logger.error(
            "Phase 3 LangChain tool failed action_id=%s target=%s error=%s",
            action_id,
            target,
            exc,
        )
        normalized = normalize_phase3_result(
            proposal=proposal,
            approval=approval,
            tool_status="error",
            error=str(exc),
        )
        return _response(
            status="error",
            action_id=action_id,
            target=target,
            normalized_result=normalized.to_dict(),
            error=str(exc),
        )

    status = "success" if result.exit_code == 0 else "failed"
    normalized = normalize_phase3_result(
        proposal=proposal,
        approval=approval,
        tool_status=status,
        execution_result=result,
    )
    return _response(
        status=status,
        action_id=action_id,
        target=target,
        result=result.to_dict(),
        normalized_result=normalized.to_dict(),
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
