from langchain_core.messages import ToolMessage

from pentaia.llm import get_llm
from pentaia.tools import nmap_service_scan


llm = get_llm()
llm_with_tools = llm.bind_tools([nmap_service_scan])

user_message = (
    "Run an Nmap service scan against my authorized lab system "
    "at 172.16.0.13 and summarize the result."
)

response = llm_with_tools.invoke(user_message)

print("INITIAL TOOL CALLS:")
print(response.tool_calls)

tool_call = response.tool_calls[0]

tool_result = nmap_service_scan.invoke(tool_call["args"])

tool_message = ToolMessage(
    content=tool_result,
    tool_call_id=tool_call["id"],
)

final_response = llm_with_tools.invoke(
    [
        ("human", user_message),
        response,
        tool_message,
    ]
)

print("\nFINAL RESPONSE:")
print(final_response.text)