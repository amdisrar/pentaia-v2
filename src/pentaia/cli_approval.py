import logging
from collections.abc import Callable

from pentaia.approval import (
    Phase3ApprovalState,
    approve_phase3_action,
    format_approval_prompt,
    reject_phase3_action,
)
from pentaia.metasploit_wrapper import PREDEFINED_METASPLOIT_OPERATIONS
from pentaia.phase3_audit import audit_approval

logger = logging.getLogger(__name__)

# Shown before the decision so the human knows the approved action leaves a file
# on the target. The marker is part of the action's behaviour, not a surprise.
ARTIFACT_NOTE = (
    "This action also writes a harmless PentAiA proof marker on the target; "
    "the exact path is reported after it succeeds."
)


def _approval_note(approval: Phase3ApprovalState) -> str | None:
    operation = PREDEFINED_METASPLOIT_OPERATIONS.get(approval.proposal.action_id)

    if operation is not None and operation.establishes_reverse_session:
        return ARTIFACT_NOTE

    return None


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

    output_func(format_approval_prompt(approval, note=_approval_note(approval)))

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
