import itertools
import sys
import threading
import time
import logging

from pentaia.logging_config import setup_logging

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

    setup_logging()
    logger = logging.getLogger(__name__)

    logger.info("PentAiA started")

    print("PentAiA v2")
    print("Type 'exit' or 'quit' to stop.\n")

    while True:
        try:
            user_input = input("PentAiA> ").strip()

            if not user_input:
                continue

            if user_input.lower() in {"exit", "quit"}:
                logger.info("PentAiA stopped")
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

        
        except Exception:
            logger.exception("Unhandled PentAiA error")
            print("\nPentAiA encountered an error. Check logs/pentaia.log for details.\n")

        except KeyboardInterrupt:
            logger.info("PentAiA stopped by user")
            print("\nGoodbye.")
            break