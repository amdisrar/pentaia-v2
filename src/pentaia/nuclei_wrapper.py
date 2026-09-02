import os
import shlex
from urllib.parse import urlsplit

from pentaia.kali_executor import run_command
from pentaia.validation import validate_nuclei_target


DEFAULT_NUCLEI_DENYLIST = {"172.16.0.1"}
ALLOWED_NUCLEI_SEVERITIES = (
    "info",
    "low",
    "medium",
    "high",
    "critical",
)
DEFAULT_NUCLEI_SEVERITIES = ("critical",)


def _get_nuclei_denylist() -> set[str]:
    configured = os.getenv("PENTAIA_NUCLEI_DENYLIST", "")
    values = {
        item.strip()
        for item in configured.split(",")
        if item.strip()
    }

    return DEFAULT_NUCLEI_DENYLIST | values


def _target_host(target: str) -> str:
    if "://" not in target:
        return target

    return urlsplit(target).hostname or ""


def _validate_severities(severities: list[str] | None) -> str:
    requested = severities or list(DEFAULT_NUCLEI_SEVERITIES)
    normalized = []

    for severity in requested:
        value = severity.strip().lower()

        if value not in ALLOWED_NUCLEI_SEVERITIES:
            allowed = ", ".join(ALLOWED_NUCLEI_SEVERITIES)
            raise ValueError(
                f"Unsupported Nuclei severity: {severity}. "
                f"Allowed values: {allowed}."
            )

        if value not in normalized:
            normalized.append(value)

    if not normalized:
        raise ValueError("At least one Nuclei severity must be selected.")

    return ",".join(normalized)


def nuclei_scan(
    target: str,
    severities: list[str] | None = None,
) -> tuple[str, str, int]:
    validated_target = validate_nuclei_target(target)
    validated_severities = _validate_severities(severities)
    host = _target_host(validated_target)

    if host in _get_nuclei_denylist():
        raise ValueError(
            f"Nuclei scanning is blocked for protected target: {host}"
        )

    safe_target = shlex.quote(validated_target)

    command = (
        f"nuclei -target {safe_target} "
        "-jsonl -silent "
        f"-severity {validated_severities} "
        "-timeout 5 -retries 0"
    )

    return run_command(
        command,
        timeout=120,
    )
