from langchain_core.tools import tool

from pentaia.nmap_wrapper import nmap_scan


@tool
def nmap_service_scan(target: str) -> str:
    """Run an authorized Nmap service/version scan against one IPv4 lab target.

    Use this tool only for authorized lab systems.
    The input must be a single IPv4 address.
    """

    stdout, stderr, exit_code = nmap_scan(target)

    if exit_code != 0:
        return f"Nmap failed with exit code {exit_code}.\n{stderr}"

    return stdout
