import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Literal

ApprovalDecision = Literal["pending", "approved", "rejected"]


@dataclass(frozen=True)
class Phase3ActionProposal:
    action_id: str
    target: str
    rationale: str
    expected_effect: str
    parameters: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def signature(self) -> str:
        canonical = json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Phase3ApprovalState:
    proposal: Phase3ActionProposal
    decision: ApprovalDecision = "pending"
    approved_signature: str | None = None

    @property
    def is_approved(self) -> bool:
        return (
            self.decision == "approved"
            and self.approved_signature == self.proposal.signature()
        )

    @property
    def is_rejected(self) -> bool:
        return self.decision == "rejected"

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal": self.proposal.to_dict(),
            "proposal_signature": self.proposal.signature(),
            "decision": self.decision,
            "approved_signature": self.approved_signature,
        }


def create_pending_approval(
    proposal: Phase3ActionProposal,
) -> Phase3ApprovalState:
    return Phase3ApprovalState(proposal=proposal)


def approve_phase3_action(
    approval: Phase3ApprovalState,
    *,
    proposal_signature: str,
) -> Phase3ApprovalState:
    expected_signature = approval.proposal.signature()

    if approval.decision != "pending":
        raise ValueError("Phase 3 approval is no longer pending.")

    if proposal_signature != expected_signature:
        raise ValueError(
            "Phase 3 approval does not match the current proposed action."
        )

    return Phase3ApprovalState(
        proposal=approval.proposal,
        decision="approved",
        approved_signature=expected_signature,
    )


def reject_phase3_action(
    approval: Phase3ApprovalState,
) -> Phase3ApprovalState:
    if approval.decision != "pending":
        raise ValueError("Phase 3 approval is no longer pending.")

    return Phase3ApprovalState(
        proposal=approval.proposal,
        decision="rejected",
        approved_signature=None,
    )


def require_current_phase3_approval(
    approval: Phase3ApprovalState | None,
    proposal: Phase3ActionProposal,
) -> None:
    if approval is None:
        raise ValueError("Phase 3 action requires explicit human approval.")

    if approval.proposal.signature() != proposal.signature():
        raise ValueError(
            "Phase 3 approval is stale or belongs to a different action."
        )

    if not approval.is_approved:
        raise ValueError("Phase 3 action has not been explicitly approved.")


def format_approval_prompt(approval: Phase3ApprovalState) -> str:
    proposal = approval.proposal

    return (
        "Phase 3 approval required\n"
        f"Action: {proposal.action_id}\n"
        f"Target: {proposal.target}\n"
        f"Rationale: {proposal.rationale}\n"
        f"Expected effect: {proposal.expected_effect}\n"
        f"Parameters: {json.dumps(proposal.parameters, sort_keys=True)}\n"
        f"Proposal signature: {proposal.signature()}"
    )
