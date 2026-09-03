import pytest
from langchain_core.messages import AIMessage, HumanMessage

import pentaia
from pentaia.approval import (
    Phase3ActionProposal,
    approve_phase3_action,
    create_pending_approval,
)
from pentaia.graph import graph


def _pending_approval():
    proposal = Phase3ActionProposal(
        action_id="validate_vsftpd_234_backdoor",
        target="172.16.0.64",
        rationale="normalized source evidence",
        expected_effect="controlled validation",
        parameters={"rport": 21},
    )
    return create_pending_approval(proposal)


def test_graph_config_contains_session_thread_and_recursion_limit() -> None:
    config = pentaia.build_graph_config("session-a", recursion_limit=17)

    assert config == {
        "configurable": {"thread_id": "session-a"},
        "recursion_limit": 17,
    }


def test_graph_config_rejects_blank_session_id() -> None:
    with pytest.raises(ValueError, match="session_id"):
        pentaia.build_graph_config("   ")


@pytest.mark.parametrize("value", [0, -1, True])
def test_graph_config_rejects_invalid_recursion_limit(value) -> None:
    with pytest.raises(ValueError, match="recursion_limit"):
        pentaia.build_graph_config("session-a", recursion_limit=value)


def test_project_graph_has_checkpointer() -> None:
    assert graph.checkpointer is not None


def test_cli_turn_submits_only_new_message_with_session_config(monkeypatch) -> None:
    calls = []

    def fake_invoke(state, *, config):
        calls.append((state, config))
        return {
            "messages": [AIMessage(content="done")],
            "pending_approval": None,
        }

    monkeypatch.setattr(pentaia, "_invoke_with_spinner", fake_invoke)

    result = pentaia.run_cli_turn(
        "continue from earlier evidence",
        session_id="session-a",
        recursion_limit=19,
    )

    assert result["messages"][-1].content == "done"
    assert len(calls) == 1
    state, config = calls[0]
    assert set(state) == {"messages"}
    assert len(state["messages"]) == 1
    assert isinstance(state["messages"][0], HumanMessage)
    assert state["messages"][0].content == "continue from earlier evidence"
    assert config["configurable"]["thread_id"] == "session-a"
    assert config["recursion_limit"] == 19


def test_approval_resume_submits_only_resolved_state_on_same_session(monkeypatch) -> None:
    pending = _pending_approval()
    calls = []

    def fake_invoke(state, *, config):
        calls.append((state, config))
        if len(calls) == 1:
            return {
                "messages": [AIMessage(content="")],
                "pending_approval": pending,
            }
        return {
            "messages": [AIMessage(content="done")],
            "pending_approval": None,
        }

    def fake_resolve(approval):
        return approve_phase3_action(
            approval,
            proposal_signature=approval.proposal.signature(),
        )

    monkeypatch.setattr(pentaia, "_invoke_with_spinner", fake_invoke)
    monkeypatch.setattr(pentaia, "resolve_cli_approval", fake_resolve)

    pentaia.run_cli_turn("continue", session_id="session-a")

    assert len(calls) == 2
    first_state, first_config = calls[0]
    resumed_state, resumed_config = calls[1]

    assert set(first_state) == {"messages"}
    assert set(resumed_state) == {"pending_approval"}
    assert resumed_state["pending_approval"].is_approved
    assert first_config == resumed_config
    assert resumed_config["configurable"]["thread_id"] == "session-a"


def test_different_session_ids_build_isolated_thread_configs() -> None:
    first = pentaia.build_graph_config("session-a")
    second = pentaia.build_graph_config("session-b")

    assert first["configurable"]["thread_id"] != second["configurable"]["thread_id"]


def test_cli_turn_rejects_invalid_approval_cycle_limit_before_invoke(monkeypatch) -> None:
    invoked = False

    def fake_invoke(state, *, config):
        nonlocal invoked
        invoked = True
        return {}

    monkeypatch.setattr(pentaia, "_invoke_with_spinner", fake_invoke)

    with pytest.raises(ValueError, match="max_approval_cycles"):
        pentaia.run_cli_turn(
            "continue",
            session_id="session-a",
            max_approval_cycles=0,
        )

    assert invoked is False


def test_approval_cycle_limit_stops_without_implicit_approval(monkeypatch) -> None:
    pending = _pending_approval()
    calls = []
    approvals = []

    def fake_invoke(state, *, config):
        calls.append((state, config))
        return {
            "messages": [AIMessage(content="")],
            "pending_approval": pending,
        }

    def fake_resolve(approval):
        approvals.append(approval)
        return approve_phase3_action(
            approval,
            proposal_signature=approval.proposal.signature(),
        )

    monkeypatch.setattr(pentaia, "_invoke_with_spinner", fake_invoke)
    monkeypatch.setattr(pentaia, "resolve_cli_approval", fake_resolve)

    with pytest.raises(RuntimeError, match="Maximum approval cycles"):
        pentaia.run_cli_turn(
            "continue",
            session_id="session-a",
            max_approval_cycles=1,
        )

    assert len(approvals) == 1
    assert len(calls) == 2
