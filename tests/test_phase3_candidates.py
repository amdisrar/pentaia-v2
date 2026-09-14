import importlib
import json

import pytest
from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

from pentaia.phase3_candidates import (
    DISCOVERY_TOOL_NAME,
    candidate_context,
    candidates_from_messages,
    findings_from_tool_messages,
)

# `from pentaia import graph` would bind the compiled graph object, not the module:
# pentaia/__init__.py does `from pentaia.graph import graph`, which rebinds the
# package attribute `graph` to the CompiledStateGraph. Import the module directly.
graph = importlib.import_module("pentaia.graph")

# Real Nuclei output captured against the authorized lab target 172.16.0.64.
# One finding maps to a supported validation rule; three do not, which is what
# makes this useful: it exercises the negative path as well as the positive one.
LAB_RECORDS = [
    {
        "cve": [],
        "cvss": None,
        "evidence": "Matched at 172.16.0.64:5432. Response: true",
        "matched_at": "172.16.0.64:5432",
        "port": 5432,
        "protocol": "tcp",
        "service": "postgresql",
        "severity": "critical",
        "source_tool": "nuclei",
        "target": "172.16.0.64",
        "template_id": "pgsql-empty-password",
        "title": "Postgresql Empty Password - Detect",
    },
    {
        "cve": ["CVE-2026-4480"],
        "cvss": 9.8,
        "evidence": "Matched at 172.16.0.64:445. Response: {",
        "matched_at": "172.16.0.64:445",
        "port": 445,
        "protocol": "tcp",
        "service": "smb",
        "severity": "critical",
        "source_tool": "nuclei",
        "target": "172.16.0.64",
        "template_id": "CVE-2026-4480",
        "title": "Samba Printing Subsystem - Remote Code Execution",
    },
    {
        "cve": ["CVE-2020-1938"],
        "cvss": 9.8,
        "evidence": "Matched at 172.16.0.64:8009. Response: AB",
        "matched_at": "172.16.0.64:8009",
        "port": 8009,
        "protocol": "tcp",
        "service": "ajp",
        "severity": "critical",
        "source_tool": "nuclei",
        "target": "172.16.0.64",
        "template_id": "CVE-2020-1938",
        "title": "Ghostcat - Apache Tomcat - AJP File Read/Inclusion Vulnerability",
    },
    {
        "cve": ["CVE-2011-2523"],
        "cvss": 9.8,
        "evidence": "Matched at 172.16.0.64:6200. Response: :x:3:3:sys:/dev:/bin/sh",
        "matched_at": "172.16.0.64:6200",
        "port": 6200,
        "protocol": "tcp",
        "service": None,
        "severity": "critical",
        "source_tool": "nuclei",
        "target": "172.16.0.64",
        "template_id": "CVE-2011-2523",
        "title": "VSFTPD 2.3.4 - Backdoor Command Execution",
    },
]

LAB_PAYLOAD = json.dumps(LAB_RECORDS, indent=2, sort_keys=True)


def _discovery_message(payload: str = LAB_PAYLOAD, *, name: str = DISCOVERY_TOOL_NAME):
    return ToolMessage(content=payload, tool_call_id="call-1", name=name)


def _supported_only_payload() -> str:
    return json.dumps([LAB_RECORDS[3]], indent=2, sort_keys=True)


def _unsupported_only_payload() -> str:
    return json.dumps(LAB_RECORDS[:3], indent=2, sort_keys=True)


# --- recovering findings ---------------------------------------------------


def test_findings_are_recovered_from_the_discovery_result() -> None:
    findings = findings_from_tool_messages([_discovery_message()])

    assert len(findings) == 4
    assert {finding.template_id for finding in findings} == {
        "pgsql-empty-password",
        "CVE-2026-4480",
        "CVE-2020-1938",
        "CVE-2011-2523",
    }


def test_only_the_latest_discovery_result_is_used() -> None:
    older = _discovery_message(_unsupported_only_payload())
    newer = _discovery_message(_supported_only_payload())

    findings = findings_from_tool_messages([older, newer])

    assert [finding.template_id for finding in findings] == ["CVE-2011-2523"]


def test_unrelated_tool_results_are_ignored() -> None:
    messages = [
        HumanMessage(content="scan it"),
        ToolMessage(
            content="Starting Nmap 7.94",
            tool_call_id="call-2",
            name="nmap_service_scan",
        ),
        _discovery_message(),
    ]

    assert len(findings_from_tool_messages(messages)) == 4


def test_no_discovery_result_yields_no_findings() -> None:
    assert findings_from_tool_messages([HumanMessage(content="hello")]) == []


@pytest.mark.parametrize(
    "payload",
    [
        "Nuclei failed with exit code 1.\nboom",
        "Nuclei completed successfully and returned no vulnerability findings.",
        "Nuclei returned output that could not be parsed: bad json",
        "Nuclei execution failed: Unable to connect to Kali at 172.16.0.13:22.",
        "",
        "{}",
    ],
)
def test_unusable_discovery_results_yield_no_findings(payload: str) -> None:
    """A discovery problem must never escalate into a proposed validation action."""
    assert findings_from_tool_messages([_discovery_message(payload)]) == []


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        ("Nuclei failed with exit code 1.\nboom", "error-output"),
        (
            "Nuclei completed successfully and returned no vulnerability findings.",
            "no-findings",
        ),
        ("Nuclei returned output that could not be parsed: bad json", "error-output"),
        ("", "empty"),
        ("   ", "empty"),
        ("{not json", "unparseable-json"),
    ],
)
def test_unusable_results_are_classified_without_logging_their_text(
    payload: str,
    reason: str,
) -> None:
    from pentaia.phase3_candidates import _unusable_reason

    assert _unusable_reason(payload) == reason


# --- the deterministic lookup ----------------------------------------------


def test_supported_finding_produces_exactly_one_candidate() -> None:
    candidates = candidates_from_messages([_discovery_message()])

    assert len(candidates) == 1

    candidate = candidates[0]
    assert candidate.proposal.action_id == "validate_vsftpd_234_backdoor"
    assert candidate.proposal.target == "172.16.0.64"
    assert candidate.proposal.parameters == {"rport": 21}


def test_unsupported_findings_produce_no_candidate() -> None:
    assert candidates_from_messages([_discovery_message(_unsupported_only_payload())]) == []


def test_no_discovery_result_produces_no_candidate() -> None:
    assert candidates_from_messages([HumanMessage(content="hello")]) == []


def test_candidate_evidence_is_traceable_to_the_scanner_finding() -> None:
    candidate = candidates_from_messages([_discovery_message()])[0]

    rationale = candidate.proposal.rationale

    assert "CVE-2011-2523" in rationale
    assert "scanner=nuclei" in rationale
    assert "template=CVE-2011-2523" in rationale
    assert "172.16.0.64:6200" in rationale
    assert candidate.source_finding.template_id == "CVE-2011-2523"


def test_multiple_supported_findings_produce_multiple_candidates() -> None:
    second = dict(LAB_RECORDS[3])
    second["port"] = 21
    second["template_id"] = "CVE-2011-2523-second"
    payload = json.dumps([LAB_RECORDS[3], second], indent=2, sort_keys=True)

    candidates = candidates_from_messages([_discovery_message(payload)])

    assert len(candidates) == 2
    # Every candidate still names one code-owned action; the approval contract
    # itself is enforced by the graph, not here.
    assert {candidate.proposal.action_id for candidate in candidates} == {
        "validate_vsftpd_234_backdoor"
    }


# --- the model-facing context ----------------------------------------------


def test_no_context_when_there_are_no_candidates() -> None:
    assert candidate_context([]) is None


def test_context_lists_only_code_owned_candidates() -> None:
    candidates = candidates_from_messages([_discovery_message()])

    context = candidate_context(candidates)

    assert context is not None
    assert "action_id: validate_vsftpd_234_backdoor" in context
    assert "target: 172.16.0.64" in context
    assert "parameter rport = 21" in context
    assert "matched_cve: CVE-2011-2523" in context
    assert "template=CVE-2011-2523" in context
    # The boundaries the model must respect.
    assert "only validation actions PentAiA supports" in context
    assert "Never invent another action" in context
    assert "no candidate is listed" in context


def test_context_never_mentions_unsupported_findings_as_actions() -> None:
    candidates = candidates_from_messages([_discovery_message()])

    context = candidate_context(candidates)

    assert context is not None
    for unsupported in ["CVE-2026-4480", "CVE-2020-1938", "pgsql-empty-password"]:
        assert unsupported not in context


# --- graph wiring ----------------------------------------------------------


def test_candidate_lookup_node_records_the_context() -> None:
    state = {"messages": [_discovery_message()]}

    update = graph.candidate_lookup_node(state)

    assert "validate_vsftpd_234_backdoor" in update["validation_context"]


def test_candidate_lookup_node_is_empty_without_a_candidate() -> None:
    state = {"messages": [_discovery_message(_unsupported_only_payload())]}

    assert graph.candidate_lookup_node(state) == {"validation_context": ""}


def test_agent_node_injects_the_candidate_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    class FakeLLM:
        def invoke(self, prompt):
            captured["prompt"] = prompt
            return AIMessage(content="ok")

    monkeypatch.setattr(graph, "llm", FakeLLM())

    graph.agent_node(
        {
            "messages": [HumanMessage(content="scan it")],
            "validation_context": "CANDIDATE CONTEXT",
        }
    )

    prompt = captured["prompt"]
    assert prompt[0] is graph.SYSTEM_MESSAGE
    assert any(
        isinstance(message, SystemMessage) and message.content == "CANDIDATE CONTEXT"
        for message in prompt
    )


def test_agent_node_adds_no_context_message_when_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    class FakeLLM:
        def invoke(self, prompt):
            captured["prompt"] = prompt
            return AIMessage(content="ok")

    monkeypatch.setattr(graph, "llm", FakeLLM())

    graph.agent_node({"messages": [HumanMessage(content="scan it")], "validation_context": ""})

    assert not any(isinstance(message, SystemMessage) for message in captured["prompt"][1:])


def test_candidate_context_alone_executes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Building and rendering candidates must not touch the executor."""
    called = False

    def fake_run_command(command: str, timeout: int):
        nonlocal called
        called = True
        return "", "", 0

    monkeypatch.setattr("pentaia.kali_executor.run_command", fake_run_command)

    candidates = candidates_from_messages([_discovery_message()])
    candidate_context(candidates)

    assert called is False
