import json
from typing import Annotated, NotRequired, TypedDict

from langchain_core.messages import AIMessage, BaseMessage, SystemMessage, ToolMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from pentaia.approval import (
    Phase3ActionProposal,
    Phase3ApprovalState,
    create_pending_approval,
)
from pentaia.llm import get_llm
from pentaia.phase3_results import PHASE3_INTERPRETATION_RULES
from pentaia.phase3_tools import phase3_controlled_validation
from pentaia.tools import nmap_service_scan, nuclei_vulnerability_scan

STATE_CHANGING_TOOL_NAME = "phase3_controlled_validation"

SYSTEM_MESSAGE = SystemMessage(
    content=(
        "You are PentAiA, an AI-assisted penetration-testing agent for authorized lab systems. "
        "Use security tools only when appropriate and only against explicitly authorized targets. "
        "Use Nmap for service/version reconnaissance when you need to understand what is exposed. "
        "Use Nuclei for controlled vulnerability discovery when the user asks for vulnerability scanning "
        "or when vulnerability evidence is needed. Select only the severities requested by the user; "
        "if no severity is specified for Nuclei, use critical. "
        "You may call one tool, both tools, or neither based on the task. Do not assume a fixed tool order. "
        "After each tool result, decide whether another tool is needed or whether you can answer. "
        "Phase 2 is limited to reconnaissance, vulnerability discovery, and evidence-based assessment; "
        "do not perform exploitation. "
        "When producing a vulnerability assessment, follow these evidence rules strictly: "
        "treat a Nuclei finding as a confirmed scanner finding only when the tool output contains a matching finding; "
        "treat Nmap-only ports, services, and versions as observations, not confirmed vulnerabilities; "
        "label any inferred or possible risk as a hypothesis or potential risk rather than a confirmed finding. "
        "For each confirmed finding, preserve the tool-provided severity, affected target/service/port, CVE, CVSS, "
        "matched location, and evidence when those fields are present. "
        "Never invent missing metadata. If CVE or CVSS is null, empty, or absent, say it was not provided by the scanner; "
        "do not substitute a severity label or infer a numeric score. "
        "Prioritize findings primarily by scanner severity and CVSS when available, but do not fabricate ranking data. "
        "Recommendations should focus on remediation, validation, hardening, patching, configuration changes, "
        "or safe follow-up reconnaissance. Do not provide or execute exploitation steps in Phase 2. "
        "Base conclusions on actual tool output and do not invent findings. "
        "For Phase 3, use phase3_controlled_validation only for a code-owned supported validation action that is "
        "traceable to normalized Phase 2 evidence. The exact proposal must already have explicit human approval. "
        "Approval is injected from graph state and is not a parameter you can provide or modify. "
        "If approval is missing, stale, rejected, or the target is not authorized, the tool must remain blocked. "
        + PHASE3_INTERPRETATION_RULES
    )
)


class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    pending_approval: NotRequired[Phase3ApprovalState | None]


tools = [
    nmap_service_scan,
    nuclei_vulnerability_scan,
    phase3_controlled_validation,
]

llm = get_llm().bind_tools(tools)


def agent_node(state: AgentState) -> AgentState:
    response = llm.invoke([SYSTEM_MESSAGE, *state["messages"]])
    return {"messages": [response]}


def _last_ai_message(state: AgentState) -> AIMessage | None:
    if not state["messages"]:
        return None
    message = state["messages"][-1]
    return message if isinstance(message, AIMessage) else None


def _state_changing_calls(state: AgentState) -> list[dict]:
    message = _last_ai_message(state)
    if message is None:
        return []
    return [
        call
        for call in message.tool_calls
        if call.get("name") == STATE_CHANGING_TOOL_NAME
    ]


def _proposal_from_tool_call(call: dict) -> Phase3ActionProposal:
    args = call.get("args", {})
    return Phase3ActionProposal(
        action_id=args["action_id"],
        target=args["target"],
        rationale=args["rationale"],
        expected_effect=args["expected_effect"],
        parameters={"rport": args["rport"]},
    )


def _pending_call_matches_approval(state: AgentState) -> bool:
    approval = state.get("pending_approval")
    calls = _state_changing_calls(state)
    if approval is None or len(calls) != 1:
        return False
    return _proposal_from_tool_call(calls[0]).signature() == approval.proposal.signature()


def approval_gate_node(state: AgentState) -> AgentState:
    calls = _state_changing_calls(state)
    if len(calls) != 1:
        raise ValueError(
            "Exactly one state-changing proposal may await CLI approval at a time."
        )

    proposal = _proposal_from_tool_call(calls[0])
    return {"pending_approval": create_pending_approval(proposal)}


def rejection_node(state: AgentState) -> AgentState:
    message = _last_ai_message(state)
    if message is None or not message.tool_calls:
        return {"messages": [], "pending_approval": None}

    tool_messages = []
    for call in message.tool_calls:
        content = json.dumps(
            {
                "status": "blocked",
                "reason": "human_rejected",
                "message": "The user rejected the pending action. Nothing was executed.",
            },
            sort_keys=True,
        )
        tool_messages.append(
            ToolMessage(
                content=content,
                tool_call_id=call["id"],
                name=call.get("name"),
            )
        )

    return {"messages": tool_messages, "pending_approval": None}


def stale_approval_node(state: AgentState) -> AgentState:
    message = _last_ai_message(state)
    if message is None or not message.tool_calls:
        return {"messages": [], "pending_approval": None}

    tool_messages = [
        ToolMessage(
            content=json.dumps(
                {
                    "status": "blocked",
                    "reason": "stale_approval",
                    "message": "The approval does not match the current pending proposal. Nothing was executed.",
                },
                sort_keys=True,
            ),
            tool_call_id=call["id"],
            name=call.get("name"),
        )
        for call in message.tool_calls
    ]
    return {"messages": tool_messages, "pending_approval": None}


def route_from_start(state: AgentState) -> str:
    approval = state.get("pending_approval")
    if approval is not None and approval.decision == "approved":
        return "tools" if _pending_call_matches_approval(state) else "stale"
    if approval is not None and approval.decision == "rejected":
        return "rejection"
    return "agent"


def route_after_agent(state: AgentState) -> str:
    message = _last_ai_message(state)
    if message is None or not message.tool_calls:
        return END
    if _state_changing_calls(state):
        return "approval_gate"
    return "tools"


graph_builder = StateGraph(AgentState)

graph_builder.add_node("agent", agent_node)
graph_builder.add_node("approval_gate", approval_gate_node)
graph_builder.add_node("rejection", rejection_node)
graph_builder.add_node("stale", stale_approval_node)
graph_builder.add_node("tools", ToolNode(tools))

graph_builder.add_conditional_edges(
    START,
    route_from_start,
    {
        "agent": "agent",
        "tools": "tools",
        "rejection": "rejection",
        "stale": "stale",
    },
)

graph_builder.add_conditional_edges(
    "agent",
    route_after_agent,
    {
        "approval_gate": "approval_gate",
        "tools": "tools",
        END: END,
    },
)

graph_builder.add_edge("approval_gate", END)
graph_builder.add_edge("rejection", "agent")
graph_builder.add_edge("stale", "agent")
graph_builder.add_edge("tools", "agent")

graph = graph_builder.compile()
