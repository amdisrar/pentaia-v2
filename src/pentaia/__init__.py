import itertools
import sys
import threading
import time

from langchain_core.messages import HumanMessage

from pentaia.graph import graph


def show_spinner(stop_event: threading.Event) -> None:
    spinner = itertools.cycle("|/-\\")

    while not stop_event.is_set():
        sys.stdout.write(f"\rPentAiA is working... {next(spinner)}")
        sys.stdout.flush()
        time.sleep(0.1)

    sys.stdout.write("\r" + " " * 40 + "\r")
    sys.stdout.flush()


def main() -> None:
    print("PentAiA v2")
    print("Type 'exit' or 'quit' to stop.\n")

    while True:
        try:
            user_input = input("PentAiA> ").strip()

            if not user_input:
                continue

            if user_input.lower() in {"exit", "quit"}:
                print("Goodbye.")
                break

            stop_event = threading.Event()

            spinner_thread = threading.Thread(
                target=show_spinner,
                args=(stop_event,),
                daemon=True,
            )

            spinner_thread.start()

            try:
                result = graph.invoke(
                    {
                        "messages": [
                            HumanMessage(content=user_input)
                        ]
                    }
                )
            finally:
                stop_event.set()
                spinner_thread.join()

            final_message = result["messages"][-1]

            print(f"{final_message.text}\n")

        
        except Exception as exc:
            print(f"\nPentAiA error: {exc}\n")

        except KeyboardInterrupt:
                    print("\nGoodbye.")
                    break