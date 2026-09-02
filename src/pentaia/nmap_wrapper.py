from pentaia.kali_executor import run_command
from pentaia.validation import validate_ipv4


def nmap_scan(target: str) -> tuple[str, str, int]:
    validated_target = validate_ipv4(target)

    command = f"nmap -sV {validated_target}"

    return run_command(
        command,
        timeout=120,
    )