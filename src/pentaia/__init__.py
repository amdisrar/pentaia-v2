import logging
import sys
import threading
import time

from langchain_core.messages import HumanMessage

from pentaia.graph import graph
from pentaia.logging_config import setup_logging


def show_spinner(stop_event: threading.Event) -> None:
    track_width = 18
    position = 0
    direction = 1

    while not stop_event.is_set():
        snake = "~~~>" if direction > 0 else "<~~~"
        frame = " " * position + snake
        frame = frame.ljust(track_width + len(snake))

        sys.stdout.write(f"\rPentAiA is working... {frame}")
        sys.stdout.flush()
        time.sleep(0.12)

        if position >= track_width:
            direction = -1
        elif position <= 0:
            direction = 1

        position += direction

    sys.stdout.write("\r" + " " * 60 + "\r")
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
            print(
                "\nPentAiA encountered an error. "
                "Check logs/pentaia.log for details.\n"
            )

        except KeyboardInterrupt:
            logger.info("PentAiA stopped by user")
            print("\nGoodbye.")
            break
