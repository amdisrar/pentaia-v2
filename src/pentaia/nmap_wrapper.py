from pentaia.kali_executor import run_command


def nmap_scan(target: str) -> tuple[str, str, int]:
    command = f"nmap -sV {target}"

    return run_command(
        command,
        timeout=120,
    )
