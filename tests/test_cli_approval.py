import pytest
from langchain_core.messages import AIMessage

from pentaia.approval import Phase3ActionProposal, create_pending_approval
from pentaia.cli_approval import resolve_cli_approval
from pentaia.graph import (
    PHASE3_TOOL_ARGUMENTS,
    approval_gate_node,
    rejection_node,
    route_after_agent,
    route_from_start,
    stale_approval_node,
)
from pentaia.phase3_ports import (
    activate_listener_port,
    listener_reservation,
    reserve_listener_port,
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
        parameters={"rport": 21, "lhost": "172.16.0.13", "lport": 4444},
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


def _reserve(proposal: Phase3ActionProposal) -> None:
    reserve_listener_port(
        action_id=proposal.action_id,
        target=proposal.target,
        rport=21,
    )


def test_rejection_releases_a_pending_reservation() -> None:
    """A rejected proposal must not keep a port out of the approved pool."""
    proposal = _proposal()
    _reserve(proposal)

    rejection_node({"messages": [_tool_message()]})

    assert (
        listener_reservation(
            action_id=proposal.action_id,
            target=proposal.target,
            rport=21,
        )
        is None
    )


def test_rejection_leaves_an_active_reservation_alone() -> None:
    """An active reservation backs a session that is still running on Kali.

    A new proposal for the same target reuses that reservation, so abandoning the
    new proposal must not free the port out from under the live session.
    """
    proposal = _proposal()
    _reserve(proposal)
    activate_listener_port(
        action_id=proposal.action_id,
        target=proposal.target,
        rport=21,
    )

    rejection_node({"messages": [_tool_message()]})

    reservation = listener_reservation(
        action_id=proposal.action_id,
        target=proposal.target,
        rport=21,
    )
    assert reservation is not None
    assert reservation.status == "active"


def test_stale_approval_releases_a_pending_reservation() -> None:
    proposal = _proposal()
    _reserve(proposal)

    stale_approval_node({"messages": [_tool_message()]})

    assert (
        listener_reservation(
            action_id=proposal.action_id,
            target=proposal.target,
            rport=21,
        )
        is None
    )


def test_stale_approval_signature_changes_with_proposal() -> None:
    original = _proposal()
    changed = Phase3ActionProposal(
        action_id=original.action_id,
        target=original.target,
        rationale=original.rationale,
        expected_effect=original.expected_effect,
        parameters={"rport": 22, "lhost": "172.16.0.13", "lport": 4444},
    )

    assert original.signature() != changed.signature()


def test_approval_prompt_tells_the_human_about_the_proof_marker() -> None:
    """The marker is part of the approved action, so it must not be a surprise."""
    output: list[str] = []

    resolve_cli_approval(
        create_pending_approval(_proposal()),
        input_func=lambda _: "n",
        output_func=output.append,
    )

    rendered = "\n".join(output)

    assert "proof marker" in rendered
    assert "the exact path is reported" in rendered


def test_prompt_without_a_note_has_no_note_line() -> None:
    from pentaia.approval import format_approval_prompt

    rendered = format_approval_prompt(create_pending_approval(_proposal()))

    assert "Note:" not in rendered


# --- malformed proposals must fail safely --------------------------------
#
# The approval gate reads the model's raw tool call, before any schema
# validation, so an incomplete or wrongly typed proposal is reachable. It must
# produce a safe blocked result rather than raising and killing the turn.


def _ai_message_with(args: dict) -> AIMessage:
    return AIMessage(
        content="",
        tool_calls=[
            {
                "name": "phase3_controlled_validation",
                "args": args,
                "id": "call-malformed",
                "type": "tool_call",
            }
        ],
    )


def _full_args() -> dict:
    return {
        "action_id": "validate_vsftpd_234_backdoor",
        "target": "172.16.0.64",
        "rationale": "normalized source evidence",
        "expected_effect": "controlled validation",
        "rport": 21,
    }


def test_proposal_is_built_from_a_complete_tool_call() -> None:
    from pentaia.graph import _proposal_from_tool_call

    proposal = _proposal_from_tool_call(_ai_message_with(_full_args()).tool_calls[0])

    assert proposal is not None
    assert proposal.target == "172.16.0.64"


@pytest.mark.parametrize(
    "missing",
    ["action_id", "target", "rationale", "expected_effect", "rport"],
)
def test_incomplete_tool_calls_produce_no_proposal(missing: str) -> None:
    from pentaia.graph import _proposal_from_tool_call

    args = _full_args()
    args.pop(missing)

    assert _proposal_from_tool_call(_ai_message_with(args).tool_calls[0]) is None


@pytest.mark.parametrize(
    "override",
    [
        {"rport": "21"},
        {"rport": 0},
        {"action_id": "arbitrary_msfconsole"},
        {"extra": "field"},
    ],
)
def test_invalid_tool_calls_produce_no_proposal(override: dict) -> None:
    from pentaia.graph import _proposal_from_tool_call

    args = {**_full_args(), **override}

    assert _proposal_from_tool_call(_ai_message_with(args).tool_calls[0]) is None


def test_gate_blocks_an_incomplete_proposal_instead_of_crashing() -> None:
    """The regression this guard exists for: KeyError('rationale') killed the turn."""
    args = _full_args()
    args.pop("rationale")

    result = approval_gate_node({"messages": [_ai_message_with(args)]})

    assert result["pending_approval"] is None
    assert "invalid_proposal" in result["messages"][0].content


def test_a_refusal_names_the_argument_that_is_missing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The agent can only correct itself if the refusal says what was wrong.

    A live rejection logged `reason=unexpected_args unexpected=[]`, which reads as
    "no argument was unexpected" and sent the reader hunting for an extra argument
    that was never there. The call was simply incomplete.
    """
    args = _full_args()
    args.pop("rport")

    with caplog.at_level("WARNING", logger="pentaia.graph"):
        result = approval_gate_node({"messages": [_ai_message_with(args)]})

    assert any(
        "missing=['rport'] unexpected=[]" in record.getMessage()
        for record in caplog.records
    )

    text = result["messages"][0].content
    assert "missing: rport" in text
    assert "Nothing was executed" in text


def test_a_refusal_names_an_argument_that_is_not_accepted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    args = {**_full_args(), "extra": "field"}

    with caplog.at_level("WARNING", logger="pentaia.graph"):
        result = approval_gate_node({"messages": [_ai_message_with(args)]})

    assert any(
        "missing=[] unexpected=['extra']" in record.getMessage()
        for record in caplog.records
    )
    assert "not accepted: extra" in result["messages"][0].content


def test_a_refusal_with_all_arguments_present_blames_the_values() -> None:
    """Names all correct, so the registry or parameter validation refused the values."""
    from pentaia.phase3_tools import phase3_controlled_validation

    args = {**_full_args(), "rport": 0}

    result = approval_gate_node({"messages": [_ai_message_with(args)]})

    text = result["messages"][0].content
    assert "not one PentAiA can run" in text
    assert "missing:" not in text
    # The model-visible schema is exactly the runtime contract, so a refusal here is
    # never about an injected argument the model was never asked for.
    assert set(PHASE3_TOOL_ARGUMENTS) == set(
        phase3_controlled_validation.tool_call_schema.model_json_schema()["required"]
    )


def test_a_refusal_from_a_non_dict_argument_list_stays_safe() -> None:
    """LangChain rejects a non-dict args at construction, so guard it directly."""
    from pentaia.graph import _invalid_proposal_text, _proposal_from_tool_call

    call = {"name": "phase3_controlled_validation", "args": "not-a-dict"}

    assert _proposal_from_tool_call(call) is None
    assert "Nothing was executed" in _invalid_proposal_text(call)


def test_gate_returns_to_the_agent_after_blocking(state: dict | None = None) -> None:
    from pentaia.graph import route_from_approval_gate

    assert route_from_approval_gate({"pending_approval": None}) == "agent"


def test_gate_ends_the_turn_when_approval_is_pending() -> None:
    from langgraph.graph import END

    from pentaia.graph import route_from_approval_gate

    result = approval_gate_node({"messages": [_tool_message()]})

    assert result["pending_approval"] is not None
    assert route_from_approval_gate(result) == END


def test_gate_blocks_two_state_changing_calls_together() -> None:
    """Two simultaneous proposals are refused, not silently reduced to one."""
    message = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "phase3_controlled_validation",
                "args": _full_args(),
                "id": f"call-{index}",
                "type": "tool_call",
            }
            for index in range(2)
        ],
    )

    result = approval_gate_node({"messages": [message]})

    assert result["pending_approval"] is None
    assert len(result["messages"]) == 2
    assert all("invalid_proposal" in m.content for m in result["messages"])


def test_target_validity_is_enforced_at_execution_not_at_the_gate() -> None:
    """The gate deliberately does not duplicate target authorization.

    An out-of-policy target is still proposed, and the wrapper rechecks
    authorization immediately before anything executes, so it fails closed there
    rather than here.
    """
    from pentaia.graph import _proposal_from_tool_call

    args = {**_full_args(), "target": "not-an-ip"}

    assert _proposal_from_tool_call(_ai_message_with(args).tool_calls[0]) is not None
