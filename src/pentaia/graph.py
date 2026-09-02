from typing import Annotated, TypedDict
from langchain_core.messages import BaseMessage, SystemMessage

from langchain_core.messages import BaseMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition

from pentaia.llm import get_llm
from pentaia.tools import nmap_service_scan

SYSTEM_MESSAGE = SystemMessage(
    content=(
        "You are PentAiA, an AI-assisted penetration-testing agent for authorized lab systems. "
        "Use security tools only when appropriate and only against explicitly authorized targets. "
        "Base conclusions on actual tool output and do not invent findings."
    )
)


class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]


tools = [nmap_service_scan]

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
