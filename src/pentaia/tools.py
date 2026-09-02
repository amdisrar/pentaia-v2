from langchain_core.tools import tool

from pentaia.nmap_wrapper import nmap_scan


@tool
def nmap_service_scan(target: str) -> str:
    """Run an authorized Nmap service/version scan against one IPv4 lab target.

    Use this tool only for authorized lab systems.
    The input must be a single IPv4 address.
    """

    try:
        stdout, stderr, exit_code = nmap_scan(target)

    except ValueError as exc:
        return f"Target validation failed: {exc}"

    except RuntimeError as exc:
        return f"Nmap execution failed: {exc}"

    if exit_code != 0:
        return (
            f"Nmap failed with exit code {exit_code}.\n"
            f"{stderr or 'No error output was returned.'}"
        )

    if not stdout:
        return "Nmap completed but returned no output."

    return stdout
