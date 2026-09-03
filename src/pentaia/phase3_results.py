import json
from dataclasses import asdict, dataclass
from typing import Literal

from pentaia.approval import Phase3ActionProposal, Phase3ApprovalState
from pentaia.metasploit_wrapper import MetasploitExecutionResult

Phase3ExecutionStatus = Literal["not_run", "completed", "failed", "error"]
Phase3Outcome = Literal["success", "failed", "inconclusive", "error", "blocked"]

PHASE3_INTERPRETATION_RULES = (
    "When a Phase 3 tool returns normalized_result, treat normalized_result.outcome as authoritative. "
    "Do not convert execution_status=completed or exit_code=0 into a successful validation claim. "
    "Describe success only when outcome=success and the returned evidence supports that statement. "
    "Describe outcome=failed as an attempted validation that did not demonstrate the expected result. "
    "Describe outcome=inconclusive as insufficient evidence to prove or disprove the expected result. "
    "Describe outcome=blocked as not executed, and outcome=error as an execution problem. "
    "Preserve the originating_finding_reference and proposal_signature when explaining traceability. "
    "Do not claim impact, access, or effect beyond what the normalized evidence explicitly demonstrates."
)


@dataclass(frozen=True)
class Phase3NormalizedResult:
    target: str
    action_id: str
    approval_decision: str
    proposal_signature: str
    execution_status: Phase3ExecutionStatus
    outcome: Phase3Outcome
    exit_code: int | None
    evidence: str
    source_tool: str
    originating_finding_reference: str
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def _compact_evidence(result: MetasploitExecutionResult | None, *, limit: int = 2000) -> str:
    if result is None:
        return ""

    parts: list[str] = []
    if result.stdout:
        parts.append(f"stdout: {result.stdout}")
    if result.stderr:
        parts.append(f"stderr: {result.stderr}")

    evidence = "\n".join(parts).strip()
    if len(evidence) <= limit:
        return evidence
    return evidence[: limit - 3] + "..."


def normalize_phase3_result(
    *,
    proposal: Phase3ActionProposal,
    approval: Phase3ApprovalState | None,
    tool_status: str,
    execution_result: MetasploitExecutionResult | None = None,
    error: str | None = None,
) -> Phase3NormalizedResult:
    approval_decision = approval.decision if approval is not None else "missing"

    if tool_status == "blocked":
        execution_status: Phase3ExecutionStatus = "not_run"
        outcome: Phase3Outcome = "blocked"
    elif tool_status == "error":
        execution_status = "error"
        outcome = "error"
    elif tool_status == "failed":
        execution_status = "failed"
        outcome = "failed"
    elif tool_status == "success":
        execution_status = "completed"
        # A clean process exit proves only that the predefined operation completed.
        # Without an explicit evidence classifier, the result remains inconclusive.
        outcome = "inconclusive"
    else:
        raise ValueError(f"Unsupported Phase 3 tool status: {tool_status}")

    return Phase3NormalizedResult(
        target=proposal.target,
        action_id=proposal.action_id,
        approval_decision=approval_decision,
        proposal_signature=proposal.signature(),
        execution_status=execution_status,
        outcome=outcome,
        exit_code=execution_result.exit_code if execution_result is not None else None,
        evidence=_compact_evidence(execution_result),
        source_tool="phase3_controlled_validation",
        originating_finding_reference=proposal.rationale,
        error=error,
    )
