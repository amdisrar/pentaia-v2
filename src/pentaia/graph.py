import json
import logging
from typing import Annotated, NotRequired, TypedDict

from langchain_core.messages import AIMessage, BaseMessage, SystemMessage, ToolMessage
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from pentaia.approval import (
    Phase3ActionProposal,
    Phase3ApprovalState,
    create_pending_approval,
)
from pentaia.llm import get_llm
from pentaia.metasploit_wrapper import prepare_metasploit_parameters
from pentaia.phase3_candidates import candidate_context, candidates_from_messages
from pentaia.phase3_ports import release_listener_port
from pentaia.phase3_results import PHASE3_INTERPRETATION_RULES
from pentaia.phase3_tools import phase3_controlled_validation
from pentaia.tools import nmap_service_scan, nuclei_vulnerability_scan

logger = logging.getLogger(__name__)

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
        "For Phase 3, call phase3_controlled_validation when the user asks to validate a supported code-owned "
        "action against an authorized lab target, or when normalized Phase 2 evidence maps to one. "
        "Calling the tool is how you raise the proposal: PentAiA then pauses and requires the human's explicit "
        "approval before anything state-changing runs. Therefore never ask for approval in chat, never tell the "
        "user to approve through some other interface, and never refuse to call the tool on the grounds that "
        "approval is not present yet. "
        "Supply only the action id, target, rationale, expected effect, and remote port. Runtime-owned material "
        "parameters are resolved by PentAiA before approval and are not model-controlled. "
        "Use the tool only for a code-owned supported action that normalized evidence supports or that the user "
        "names explicitly; never invent an unsupported action. "
        "Approval is injected into the tool from graph state and is not a parameter you can provide or modify. "
        "If approval is missing, stale, rejected, runtime configuration is invalid, or the target is not authorized, "
        "the tool call is blocked and nothing executes. "
        "When the tool establishes a reverse session, PentAiA holds that session open on the Kali host and returns "
        "its attach details in the result. Relay those details to the user: you cannot type into the session "
        "yourself and you must not claim to have done so. "
        "PentAiA may also add a code-owned candidate context describing the validation actions its Test Framework "
        "supports for the latest discovery findings. Treat that context as authoritative: those are the only "
        "validation actions available, never invent another, and when no candidate is listed you report the "
        "findings only and propose no validation. "
        + PHASE3_INTERPRETATION_RULES
    )
)


class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    pending_approval: NotRequired[Phase3ApprovalState | None]
    # Code-owned candidate context derived from the latest discovery result. It is
    # context for the model to explain and recommend from, never an execution path.
    validation_context: NotRequired[str]


tools = [
    nmap_service_scan,
    nuclei_vulnerability_scan,
    phase3_controlled_validation,
]

llm = get_llm().bind_tools(tools)


def agent_node(state: AgentState) -> AgentState:
    prompt: list[BaseMessage] = [SYSTEM_MESSAGE]

    context = state.get("validation_context")
    if context:
        prompt.append(SystemMessage(content=context))

    prompt.extend(state["messages"])

    response = llm.invoke(prompt)
    return {"messages": [response]}


def candidate_lookup_node(state: AgentState) -> AgentState:
    """Deterministically check the latest discovery findings against the registry.

    Code decides whether a supported validation exists; the model only ever sees
    the result. An unsupported finding produces no candidate, so there is nothing
    for the model to propose.
    """
    candidates = candidates_from_messages(state["messages"])
    context = candidate_context(candidates)

    if candidates:
        logger.info(
            "Phase 3 candidate lookup matched candidates=%s actions=%s",
            len(candidates),
            sorted({candidate.proposal.action_id for candidate in candidates}),
        )

    return {"validation_context": context or ""}


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
    action_id = args["action_id"]
    parameters = prepare_metasploit_parameters(
        action_id,
        {"rport": args["rport"]},
        target=args["target"],
    )
    return Phase3ActionProposal(
        action_id=action_id,
        target=args["target"],
        rationale=args["rationale"],
        expected_effect=args["expected_effect"],
        parameters=parameters,
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


def _abandon_reservations(state: AgentState) -> None:
    """Release listener ports reserved for a proposal that is being abandoned.

    A rejected or stale approval must not keep a port out of the approved pool.
    """
    for call in _state_changing_calls(state):
        args = call.get("args", {})
        if not isinstance(args, dict):
            continue

        try:
            released = release_listener_port(
                action_id=args["action_id"],
                target=args["target"],
                rport=args["rport"],
            )
        except (KeyError, ValueError):
            continue

        if released:
            logger.info(
                "Phase 3 listener port released for abandoned proposal action_id=%s target=%s",
                args.get("action_id"),
                args.get("target"),
            )


def rejection_node(state: AgentState) -> AgentState:
    message = _last_ai_message(state)
    if message is None or not message.tool_calls:
        return {"messages": [], "pending_approval": None}

    _abandon_reservations(state)

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

    _abandon_reservations(state)

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
graph_builder.add_node("candidate_lookup", candidate_lookup_node)
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
# Every discovery result passes through the deterministic candidate lookup before
# the model sees it again, so a supported finding is surfaced by code, not guessed.
graph_builder.add_edge("tools", "candidate_lookup")
graph_builder.add_edge("candidate_lookup", "agent")

# The in-memory checkpointer preserves one CLI conversation by LangGraph thread_id.
# The CLI owns that thread/session identifier; it is never exposed to the model.
checkpointer = InMemorySaver()
graph = graph_builder.compile(checkpointer=checkpointer)
