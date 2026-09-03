import pytest
from langchain_core.messages import AIMessage

from pentaia.approval import Phase3ActionProposal, create_pending_approval
from pentaia.cli_approval import resolve_cli_approval
from pentaia.graph import (
    approval_gate_node,
    rejection_node,
    route_after_agent,
    route_from_start,
)


@pytest.fixture(autouse=True)
def configured_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.13")


def _proposal() -> Phase3ActionProposal:
    return Phase3ActionProposal(
        action_id="validate_vsftpd_234_backdoor",
        target="172.16.0.64",
        rationale="normalized source evidence",
        expected_effect="controlled validation",
        parameters={"rport": 21, "lhost": "172.16.0.13"},
    )


def _tool_message() -> AIMessage:
    proposal = _proposal()
    return AIMessage(
        content="",
        tool_calls=[
            {
                "name": "phase3_controlled_validation",
                "args": {
                    "action_id": proposal.action_id,
                    "target": proposal.target,
                    "rationale": proposal.rationale,
                    "expected_effect": proposal.expected_effect,
                    "rport": 21,
                },
                "id": "call-1",
                "type": "tool_call",
            }
        ],
    )


def test_cli_prompt_renders_exact_pending_context() -> None:
    approval = create_pending_approval(_proposal())
    output: list[str] = []

    resolved = resolve_cli_approval(
        approval,
        input_func=lambda _: "n",
        output_func=output.append,
    )

    rendered = "\n".join(output)
    assert approval.proposal.action_id in rendered
    assert approval.proposal.target in rendered
    assert approval.proposal.rationale in rendered
    assert approval.proposal.expected_effect in rendered
    assert '"rport": 21' in rendered
    assert '"lhost": "172.16.0.13"' in rendered
    assert approval.proposal.signature() in rendered
    assert resolved.is_rejected


def test_cli_yes_approves_exact_signature() -> None:
    approval = create_pending_approval(_proposal())
    resolved = resolve_cli_approval(
        approval,
        input_func=lambda _: "yes",
        output_func=lambda _: None,
    )

    assert resolved.is_approved
    assert resolved.approved_signature == approval.proposal.signature()


def test_cli_blank_rejects() -> None:
    approval = create_pending_approval(_proposal())
    resolved = resolve_cli_approval(
        approval,
        input_func=lambda _: "",
        output_func=lambda _: None,
    )

    assert resolved.is_rejected


def test_cli_invalid_input_reprompts_then_rejects() -> None:
    answers = iter(["maybe", "no"])
    output: list[str] = []
    approval = create_pending_approval(_proposal())

    resolved = resolve_cli_approval(
        approval,
        input_func=lambda _: next(answers),
        output_func=output.append,
    )

    assert resolved.is_rejected
    assert any("Please enter" in line for line in output)


def test_graph_pauses_before_state_changing_tool() -> None:
    state = {"messages": [_tool_message()]}

    assert route_after_agent(state) == "approval_gate"
    result = approval_gate_node(state)
    pending = result["pending_approval"]

    assert pending is not None
    assert pending.decision == "pending"
    assert pending.proposal.signature() == _proposal().signature()


def test_graph_resume_routes_approved_state_to_tools() -> None:
    approval = create_pending_approval(_proposal())
    approved = resolve_cli_approval(
        approval,
        input_func=lambda _: "y",
        output_func=lambda _: None,
    )

    assert route_from_start(
        {"messages": [_tool_message()], "pending_approval": approved}
    ) == "tools"


def test_graph_rejected_state_routes_to_safe_path() -> None:
    approval = create_pending_approval(_proposal())
    rejected = resolve_cli_approval(
        approval,
        input_func=lambda _: "n",
        output_func=lambda _: None,
    )

    state = {"messages": [_tool_message()], "pending_approval": rejected}
    assert route_from_start(state) == "rejection"

    result = rejection_node(state)
    assert result["pending_approval"] is None
    assert "human_rejected" in result["messages"][0].content


def test_read_only_agent_output_does_not_request_approval() -> None:
    state = {"messages": [AIMessage(content="done", tool_calls=[])]}
    assert route_after_agent(state) != "approval_gate"


def test_stale_approval_signature_changes_with_proposal() -> None:
    original = _proposal()
    changed = Phase3ActionProposal(
        action_id=original.action_id,
        target=original.target,
        rationale=original.rationale,
        expected_effect=original.expected_effect,
        parameters={"rport": 22, "lhost": "172.16.0.13"},
    )

    assert original.signature() != changed.signature()
