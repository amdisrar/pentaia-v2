import os
import shlex
from urllib.parse import urlsplit

from pentaia.kali_executor import run_command
from pentaia.validation import validate_nuclei_target


DEFAULT_NUCLEI_DENYLIST = {"172.16.0.1"}


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


def nuclei_scan(target: str) -> tuple[str, str, int]:
    validated_target = validate_nuclei_target(target)
    host = _target_host(validated_target)

    if host in _get_nuclei_denylist():
        raise ValueError(
            f"Nuclei scanning is blocked for protected target: {host}"
        )

    safe_target = shlex.quote(validated_target)

    command = (
        f"nuclei -target {safe_target} "
        "-jsonl -silent "
        "-severity low,medium,high,critical "
        "-timeout 5 -retries 0"
    )

    return run_command(
        command,
        timeout=120,
    )
