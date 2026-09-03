import json

import pytest

from pentaia.approval import approve_phase3_action, create_pending_approval
from pentaia.graph import _proposal_from_tool_call
from pentaia.metasploit_wrapper import prepare_metasploit_parameters
from pentaia.phase3_audit import user_safe_failure_message
from pentaia.phase3_tools import _run_phase3_validation_tool


def _tool_call() -> dict:
    return {
        "name": "phase3_controlled_validation",
        "args": {
            "action_id": "validate_vsftpd_234_backdoor",
            "target": "172.16.0.64",
            "rationale": "normalized source evidence",
            "expected_effect": "controlled validation",
            "rport": 21,
        },
        "id": "call-runtime-callback",
        "type": "tool_call",
    }


def test_valid_runtime_callback_is_added_to_exact_proposal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.13")

    proposal = _proposal_from_tool_call(_tool_call())

    assert proposal.parameters == {
        "rport": 21,
        "lhost": "172.16.0.13",
    }


def test_missing_runtime_callback_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PENTAIA_LHOST", raising=False)

    with pytest.raises(ValueError, match="PENTAIA_LHOST is required"):
        prepare_metasploit_parameters(
            "validate_vsftpd_234_backdoor",
            {"rport": 21},
        )


def test_invalid_runtime_callback_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_LHOST", "not-an-ip")

    with pytest.raises(ValueError, match="valid IPv4 address"):
        prepare_metasploit_parameters(
            "validate_vsftpd_234_backdoor",
            {"rport": 21},
        )


def test_changed_runtime_callback_invalidates_prior_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.13")
    approved_proposal = _proposal_from_tool_call(_tool_call())
    pending = create_pending_approval(approved_proposal)
    approved = approve_phase3_action(
        pending,
        proposal_signature=approved_proposal.signature(),
    )

    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.14")

    payload = json.loads(
        _run_phase3_validation_tool(
            action_id="validate_vsftpd_234_backdoor",
            target="172.16.0.64",
            rationale="normalized source evidence",
            expected_effect="controlled validation",
            rport=21,
            approval=approved,
        )
    )

    assert payload["status"] == "blocked"
    assert payload["error"] == user_safe_failure_message("blocked")
    assert payload["result"] is None
    assert payload["normalized_result"]["execution_status"] == "not_run"
    assert payload["normalized_result"]["outcome"] == "blocked"
