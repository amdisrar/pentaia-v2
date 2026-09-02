from pentaia.kali_executor import run_command
from pentaia.validation import validate_ipv4


def nuclei_scan(target: str) -> tuple[str, str, int]:
    validated_target = validate_ipv4(target)

    command = (
        f"nuclei -target {validated_target} "
        "-jsonl -silent "
        "-severity low,medium,high,critical "
        "-timeout 5 -retries 0"
    )

    return run_command(
        command,
        timeout=120,
    )
