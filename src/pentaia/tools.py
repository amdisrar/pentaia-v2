import logging
from time import perf_counter
from typing import Literal

from langchain_core.tools import tool

from pentaia.findings import findings_to_json, parse_nuclei_jsonl
from pentaia.logging_config import setup_logging
from pentaia.nmap_wrapper import nmap_scan
from pentaia.nuclei_wrapper import nuclei_scan

setup_logging()
logger = logging.getLogger(__name__)

NucleiSeverity = Literal[
    "info",
    "low",
    "medium",
    "high",
    "critical",
]


def _elapsed_ms(started_at: float) -> int:
    return round((perf_counter() - started_at) * 1000)


@tool
def nmap_service_scan(target: str) -> str:
    """Run an authorized Nmap service/version scan against one IPv4 lab target.

    Use this tool only for authorized lab systems.
    The input must be a single IPv4 address.
    """
    started_at = perf_counter()
    logger.info("Tool selected: nmap_service_scan target=%s", target)

    try:
        stdout, stderr, exit_code = nmap_scan(target)

    except ValueError as exc:
        logger.warning(
            "Nmap validation failed target=%s elapsed_ms=%s error=%s",
            target,
            _elapsed_ms(started_at),
            exc,
        )
        return f"Target validation failed: {exc}"

    except RuntimeError as exc:
        logger.error(
            "Nmap execution failed target=%s elapsed_ms=%s error=%s",
            target,
            _elapsed_ms(started_at),
            exc,
        )
        return f"Nmap execution failed: {exc}"

    if exit_code != 0:
        logger.error(
            "Nmap completed unsuccessfully target=%s exit_code=%s elapsed_ms=%s",
            target,
            exit_code,
            _elapsed_ms(started_at),
        )
        return (
            f"Nmap failed with exit code {exit_code}.\n"
            f"{stderr or 'No error output was returned.'}"
        )

    if not stdout:
        logger.info(
            "Nmap completed with empty output target=%s elapsed_ms=%s",
            target,
            _elapsed_ms(started_at),
        )
        return "Nmap completed but returned no output."

    logger.info(
        "Nmap completed successfully target=%s elapsed_ms=%s",
        target,
        _elapsed_ms(started_at),
    )
    return stdout


@tool
def nuclei_vulnerability_scan(
    target: str,
    severities: list[NucleiSeverity] | None = None,
) -> str:
    """Run an authorized Nuclei vulnerability scan against one lab target.

    Use this tool only for explicitly authorized lab systems.
    The target may be a single IPv4 address or a validated http/https URL.
    Select severities from info, low, medium, high, and critical according to
    the user's request. If the user does not specify severity, use critical.
    PentAiA validates all severity values and does not allow arbitrary Nuclei
    command-line options.

    Returns compact normalized JSON findings for reliable downstream analysis.
    """
    started_at = perf_counter()
    logger.info(
        "Tool selected: nuclei_vulnerability_scan target=%s severities=%s",
        target,
        severities,
    )

    try:
        stdout, stderr, exit_code = nuclei_scan(target, severities)

    except ValueError as exc:
        logger.warning(
            "Nuclei validation failed target=%s severities=%s elapsed_ms=%s error=%s",
            target,
            severities,
            _elapsed_ms(started_at),
            exc,
        )
        return f"Target or scan-option validation failed: {exc}"

    except RuntimeError as exc:
        logger.error(
            "Nuclei execution failed target=%s severities=%s elapsed_ms=%s error=%s",
            target,
            severities,
            _elapsed_ms(started_at),
            exc,
        )
        return f"Nuclei execution failed: {exc}"

    if exit_code != 0:
        logger.error(
            "Nuclei completed unsuccessfully target=%s severities=%s exit_code=%s elapsed_ms=%s",
            target,
            severities,
            exit_code,
            _elapsed_ms(started_at),
        )
        return (
            f"Nuclei failed with exit code {exit_code}.\n"
            f"{stderr or 'No error output was returned.'}"
        )

    if not stdout:
        logger.info(
            "Nuclei completed with no findings target=%s severities=%s elapsed_ms=%s",
            target,
            severities,
            _elapsed_ms(started_at),
        )
        return "Nuclei completed successfully and returned no vulnerability findings."

    try:
        findings = parse_nuclei_jsonl(stdout)
    except ValueError as exc:
        logger.exception(
            "Nuclei output parse failed target=%s severities=%s elapsed_ms=%s",
            target,
            severities,
            _elapsed_ms(started_at),
        )
        return f"Nuclei returned output that could not be parsed: {exc}"

    logger.info(
        "Nuclei completed successfully target=%s severities=%s findings=%s elapsed_ms=%s",
        target,
        severities,
        len(findings),
        _elapsed_ms(started_at),
    )
    return findings_to_json(findings)
