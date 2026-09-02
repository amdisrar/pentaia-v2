import logging

from langchain_core.tools import tool

from pentaia.nmap_wrapper import nmap_scan
from pentaia.nuclei_wrapper import nuclei_scan

logger = logging.getLogger(__name__)


@tool
def nmap_service_scan(target: str) -> str:
    """Run an authorized Nmap service/version scan against one IPv4 lab target.

    Use this tool only for authorized lab systems.
    The input must be a single IPv4 address.
    """
    logger.info("Tool selected: nmap_service_scan target=%s", target)

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


@tool
def nuclei_vulnerability_scan(target: str) -> str:
    """Run an authorized Nuclei vulnerability scan against one lab target.

    Use this tool only for explicitly authorized lab systems.
    The input may be a single IPv4 address or a validated http/https URL.
    Nuclei options are controlled by PentAiA and are not user configurable.
    """
    logger.info("Tool selected: nuclei_vulnerability_scan target=%s", target)

    try:
        stdout, stderr, exit_code = nuclei_scan(target)

    except ValueError as exc:
        return f"Target validation failed: {exc}"

    except RuntimeError as exc:
        return f"Nuclei execution failed: {exc}"

    if exit_code != 0:
        return (
            f"Nuclei failed with exit code {exit_code}.\n"
            f"{stderr or 'No error output was returned.'}"
        )

    if not stdout:
        return "Nuclei completed successfully and returned no vulnerability findings."

    return stdout
