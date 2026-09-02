from langchain_core.messages import HumanMessage

from pentaia.graph import graph


result = graph.invoke(
    {
        "messages": [
            HumanMessage(
                content=(
                    "Run an Nmap service scan against my authorized lab "
                    "system at 172.16.0.13 and summarize the result."
                )
            )
        ]
    }
)

final_message = result["messages"][-1]

print(final_message.text)
