import logging
from collections.abc import Callable

from pentaia.approval import (
    Phase3ApprovalState,
    approve_phase3_action,
    format_approval_prompt,
    reject_phase3_action,
)
from pentaia.phase3_audit import audit_approval

logger = logging.getLogger(__name__)


def resolve_cli_approval(
    approval: Phase3ApprovalState,
    *,
    input_func: Callable[[str], str] = input,
    output_func: Callable[[str], None] = print,
) -> Phase3ApprovalState:
    """Resolve one pending approval from direct CLI input.

    Only explicit ``y``/``yes`` approves. ``n``/``no`` and blank input reject.
    Unexpected input is re-prompted and never counts as approval.
    """
    if approval.decision != "pending":
        raise ValueError("CLI approval requires a pending approval state.")

    output_func(format_approval_prompt(approval))

    while True:
        answer = input_func("\nApprove this exact action? [y/N]: ").strip().lower()

        if answer in {"y", "yes"}:
            signature = approval.proposal.signature()
            resolved = approve_phase3_action(
                approval,
                proposal_signature=signature,
            )
            audit_approval(resolved)
            logger.info(
                "CLI approval decision=approved action_id=%s target=%s proposal_signature=%s",
                approval.proposal.action_id,
                approval.proposal.target,
                signature,
            )
            return resolved

        if answer in {"", "n", "no"}:
            resolved = reject_phase3_action(approval)
            audit_approval(resolved)
            logger.info(
                "CLI approval decision=rejected action_id=%s target=%s proposal_signature=%s",
                approval.proposal.action_id,
                approval.proposal.target,
                approval.proposal.signature(),
            )
            return resolved

        output_func("Please enter 'y'/'yes' to approve or 'n'/'no' to reject.")
