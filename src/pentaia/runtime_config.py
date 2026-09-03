import ipaddress
import os

PENTAIA_LHOST_ENV = "PENTAIA_LHOST"


def validate_callback_ipv4(value: object) -> str:
    """Validate and normalize one runtime-owned callback/listener IPv4 address."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("PENTAIA_LHOST is required for this Phase 3 action.")

    candidate = value.strip()
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise ValueError("PENTAIA_LHOST must be a valid IPv4 address.") from exc

    if parsed.version != 4:
        raise ValueError("PENTAIA_LHOST must be a valid IPv4 address.")

    return str(parsed)


def get_phase3_callback_address() -> str:
    """Read the callback/listener address from runtime configuration and fail closed."""
    return validate_callback_ipv4(os.getenv(PENTAIA_LHOST_ENV))
