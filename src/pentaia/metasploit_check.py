import logging

from pentaia.kali_executor import run_command

logger = logging.getLogger(__name__)


def check_metasploit() -> dict[str, str | int | bool]:
    """Perform a harmless Metasploit availability/version check on Kali."""
    stdout, stderr, exit_code = run_command(
        "command -v msfconsole && msfconsole --version",
        timeout=60,
    )

    available = exit_code == 0 and bool(stdout.strip())

    result: dict[str, str | int | bool] = {
        "available": available,
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
    }

    if available:
        logger.info("Metasploit availability check succeeded exit_code=%s", exit_code)
    else:
        logger.warning(
            "Metasploit availability check failed exit_code=%s stderr_chars=%s",
            exit_code,
            len(stderr),
        )

    return result
