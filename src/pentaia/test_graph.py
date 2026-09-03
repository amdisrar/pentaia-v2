from uuid import uuid4

from langchain_core.messages import HumanMessage

from pentaia import build_graph_config
from pentaia.graph import graph


def main() -> None:
    """Run the legacy manual graph smoke check outside pytest collection."""
    session_id = f"manual-graph-{uuid4().hex}"
    config = build_graph_config(session_id)

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
        },
        config=config,
    )

    final_message = result["messages"][-1]
    print(final_message.text)


if __name__ == "__main__":
    main()
