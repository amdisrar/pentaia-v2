from typing import Annotated, NotRequired, TypedDict

from langchain_core.messages import BaseMessage, SystemMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition

from pentaia.approval import Phase3ApprovalState
from pentaia.llm import get_llm
from pentaia.tools import nmap_service_scan, nuclei_vulnerability_scan

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
        "Base conclusions on actual tool output and do not invent findings."
    )
)


class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    pending_approval: NotRequired[Phase3ApprovalState | None]


tools = [
    nmap_service_scan,
    nuclei_vulnerability_scan,
]

llm = get_llm().bind_tools(tools)


def agent_node(state: AgentState) -> AgentState:
    response = llm.invoke(
        [SYSTEM_MESSAGE, *state["messages"]]
    )

    return {
        "messages": [response],
    }


graph_builder = StateGraph(AgentState)

graph_builder.add_node("agent", agent_node)
graph_builder.add_node("tools", ToolNode(tools))

graph_builder.add_edge(START, "agent")

graph_builder.add_conditional_edges(
    "agent",
    tools_condition,
    {
        "tools": "tools",
        END: END,
    },
)

graph_builder.add_edge("tools", "agent")

graph = graph_builder.compile()
