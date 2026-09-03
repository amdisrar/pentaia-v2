import pytest

from pentaia.approval import (
    Phase3ActionProposal,
    approve_phase3_action,
    create_pending_approval,
    format_approval_prompt,
    reject_phase3_action,
    require_current_phase3_approval,
)


def make_proposal(**overrides):
    values = {
        "action_id": "lab_validation_test",
        "target": "172.16.0.64",
        "rationale": "Validate a confirmed Phase 2 finding in the authorized lab.",
        "expected_effect": "Run one predefined validation action against the lab VM.",
        "parameters": {"port": 21},
    }
    values.update(overrides)
    return Phase3ActionProposal(**values)


def test_pending_approval_contains_exact_proposal_context():
    proposal = make_proposal()
    approval = create_pending_approval(proposal)

    assert approval.decision == "pending"
    assert approval.proposal == proposal
    assert approval.approved_signature is None
    assert not approval.is_approved


def test_approval_requires_matching_proposal_signature():
    proposal = make_proposal()
    approval = create_pending_approval(proposal)

    approved = approve_phase3_action(
        approval,
        proposal_signature=proposal.signature(),
    )

    assert approved.is_approved
    require_current_phase3_approval(approved, proposal)


def test_changed_target_invalidates_existing_approval():
    proposal = make_proposal()
    approval = approve_phase3_action(
        create_pending_approval(proposal),
        proposal_signature=proposal.signature(),
    )
    changed = make_proposal(target="172.16.0.65")

    with pytest.raises(ValueError, match="stale or belongs to a different action"):
        require_current_phase3_approval(approval, changed)


def test_changed_parameters_invalidate_existing_approval():
    proposal = make_proposal()
    approval = approve_phase3_action(
        create_pending_approval(proposal),
        proposal_signature=proposal.signature(),
    )
    changed = make_proposal(parameters={"port": 22})

    with pytest.raises(ValueError, match="stale or belongs to a different action"):
        require_current_phase3_approval(approval, changed)


def test_reject_never_counts_as_approval():
    proposal = make_proposal()
    rejected = reject_phase3_action(create_pending_approval(proposal))

    assert rejected.is_rejected
    assert not rejected.is_approved

    with pytest.raises(ValueError, match="not been explicitly approved"):
        require_current_phase3_approval(rejected, proposal)


def test_missing_approval_is_blocked():
    proposal = make_proposal()

    with pytest.raises(ValueError, match="requires explicit human approval"):
        require_current_phase3_approval(None, proposal)


def test_wrong_signature_cannot_approve_action():
    proposal = make_proposal()
    approval = create_pending_approval(proposal)

    with pytest.raises(ValueError, match="does not match"):
        approve_phase3_action(
            approval,
            proposal_signature="wrong-signature",
        )


def test_approval_cannot_be_reused_after_decision():
    proposal = make_proposal()
    approved = approve_phase3_action(
        create_pending_approval(proposal),
        proposal_signature=proposal.signature(),
    )

    with pytest.raises(ValueError, match="no longer pending"):
        approve_phase3_action(
            approved,
            proposal_signature=proposal.signature(),
        )


def test_approval_prompt_shows_required_context():
    proposal = make_proposal()
    prompt = format_approval_prompt(create_pending_approval(proposal))

    assert "Action: lab_validation_test" in prompt
    assert "Target: 172.16.0.64" in prompt
    assert "Rationale:" in prompt
    assert "Expected effect:" in prompt
    assert '"port": 21' in prompt
    assert proposal.signature() in prompt
