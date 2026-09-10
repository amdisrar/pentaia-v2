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


# Code-owned evidence markers that demonstrate the predefined action actually
# achieved its effect. A clean process exit is never sufficient on its own
# (see PHASE3_INTERPRETATION_RULES); an outcome is upgraded to "success" only
# when returned evidence contains one of these markers.
SUCCESS_EVIDENCE_MARKERS: tuple[str, ...] = (
    "uid=0(root)",
    "meterpreter session",
    "command shell session",
)


def evidence_demonstrates_expected_effect(evidence: str) -> bool:
    """Return True only when returned evidence demonstrates the expected effect."""
    normalized = evidence.lower()
    return any(marker in normalized for marker in SUCCESS_EVIDENCE_MARKERS)


def _compact_evidence(
    result: MetasploitExecutionResult | None,
    session_evidence: str = "",
    *,
    limit: int = 2000,
) -> str:
    parts: list[str] = []

    if result is not None:
        if result.stdout:
            parts.append(f"stdout: {result.stdout}")
        if result.stderr:
            parts.append(f"stderr: {result.stderr}")

    # Evidence captured from PentAiA's own listener proves a session called back,
    # which the execution output alone cannot demonstrate.
    if session_evidence.strip():
        parts.append(f"session: {session_evidence.strip()}")

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
    session_evidence: str = "",
    error: str | None = None,
) -> Phase3NormalizedResult:
    approval_decision = approval.decision if approval is not None else "missing"
    evidence = _compact_evidence(execution_result, session_evidence)

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
        # A clean process exit proves only that the predefined operation ran.
        # The outcome is upgraded only when returned evidence demonstrates the
        # effect, so exit_code=0 can never be reported as a successful validation.
        outcome = (
            "success"
            if evidence_demonstrates_expected_effect(evidence)
            else "inconclusive"
        )
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
        evidence=evidence,
        source_tool="phase3_controlled_validation",
        originating_finding_reference=proposal.rationale,
        error=error,
    )
