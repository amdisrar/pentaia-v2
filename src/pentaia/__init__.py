import logging
import sys
import threading
import time
from uuid import uuid4

from langchain_core.messages import HumanMessage

from pentaia.cli_approval import resolve_cli_approval
from pentaia.graph import graph
from pentaia.logging_config import setup_logging

DEFAULT_RECURSION_LIMIT = 32
DEFAULT_MAX_APPROVAL_CYCLES = 4


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


def _validate_positive_int(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer.")
    return value


def build_graph_config(
    session_id: str,
    *,
    recursion_limit: int = DEFAULT_RECURSION_LIMIT,
) -> dict:
    """Build validated LangGraph config for one CLI conversation session."""
    if not isinstance(session_id, str) or not session_id.strip():
        raise ValueError("session_id must be a non-empty string.")

    recursion_limit = _validate_positive_int("recursion_limit", recursion_limit)

    return {
        "configurable": {"thread_id": session_id.strip()},
        "recursion_limit": recursion_limit,
    }


def _invoke_with_spinner(state: dict, *, config: dict) -> dict:
    stop_event = threading.Event()
    spinner_thread = threading.Thread(
        target=show_spinner,
        args=(stop_event,),
        daemon=True,
    )
    spinner_thread.start()
    try:
        return graph.invoke(state, config=config)
    finally:
        stop_event.set()
        spinner_thread.join()


def run_cli_turn(
    user_input: str,
    *,
    session_id: str,
    recursion_limit: int = DEFAULT_RECURSION_LIMIT,
    max_approval_cycles: int = DEFAULT_MAX_APPROVAL_CYCLES,
) -> dict:
    """Run one user turn while preserving checkpointed state for the CLI session."""
    if not isinstance(user_input, str) or not user_input.strip():
        raise ValueError("user_input must be a non-empty string.")

    max_approval_cycles = _validate_positive_int(
        "max_approval_cycles",
        max_approval_cycles,
    )
    config = build_graph_config(session_id, recursion_limit=recursion_limit)

    logger = logging.getLogger(__name__)
    logger.info(
        "CLI turn started session_id=%s recursion_limit=%s max_approval_cycles=%s",
        session_id,
        recursion_limit,
        max_approval_cycles,
    )

    # Only the new user message is submitted. Earlier messages and workflow state
    # are restored by LangGraph from the checkpointer for this thread_id.
    result = _invoke_with_spinner(
        {"messages": [HumanMessage(content=user_input.strip())]},
        config=config,
    )

    approval_cycles = 0
    while True:
        pending = result.get("pending_approval")
        if pending is None or pending.decision != "pending":
            return result

        approval_cycles += 1
        if approval_cycles > max_approval_cycles:
            logger.error(
                "CLI approval cycle limit reached session_id=%s limit=%s",
                session_id,
                max_approval_cycles,
            )
            raise RuntimeError(
                "Maximum approval cycles reached for this CLI turn; nothing was auto-approved."
            )

        resolved = resolve_cli_approval(pending)

        # Resume only with the human-owned approval update. The pending tool call
        # and prior messages remain in the checkpointed thread state.
        result = _invoke_with_spinner(
            {"pending_approval": resolved},
            config=config,
        )


def main() -> None:
    setup_logging()
    logger = logging.getLogger(__name__)

    session_id = uuid4().hex
    logger.info("PentAiA started session_id=%s", session_id)

    print("PentAiA v2")
    print("Type 'exit' or 'quit' to stop.\n")

    while True:
        try:
            user_input = input("PentAiA> ").strip()

            if not user_input:
                continue

            if user_input.lower() in {"exit", "quit"}:
                logger.info("PentAiA stopped session_id=%s", session_id)
                print("Goodbye.")
                break

            result = run_cli_turn(
                user_input,
                session_id=session_id,
            )
            final_message = result["messages"][-1]
            print(f"{final_message.text}\n")

        except Exception:
            logger.exception("Unhandled PentAiA error session_id=%s", session_id)
            print(
                "\nPentAiA encountered an error. "
                "Check logs/pentaia.log for details.\n"
            )

        except KeyboardInterrupt:
            logger.info("PentAiA stopped by user session_id=%s", session_id)
            print("\nGoodbye.")
            break
