from pentaia.discovery_profiles import (
    NMAP_DEFAULT_PROFILE,
    NMAP_TIMEOUT_SECONDS,
    build_nmap_options,
    validate_nmap_ports,
    validate_nmap_profile,
)
from pentaia.kali_executor import run_command
from pentaia.validation import validate_ipv4


def nmap_scan(
    target: str,
    *,
    profile: str = NMAP_DEFAULT_PROFILE,
    ports: list[int] | None = None,
) -> tuple[str, str, int]:
    """Run one code-owned Nmap profile against a validated IPv4 target.

    The profile name and the optional port selection are validated against the
    code-owned registry, and every native option emitted here comes from that
    registry. No model-supplied option text reaches the command.
    """
    validated_target = validate_ipv4(target)
    resolved_profile = validate_nmap_profile(profile)
    selected_ports = validate_nmap_ports(ports)
    options = build_nmap_options(resolved_profile, selected_ports)

    command = f"nmap {' '.join(options)} {validated_target}"

    return run_command(
        command,
        timeout=NMAP_TIMEOUT_SECONDS,
    )