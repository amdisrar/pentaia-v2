import ipaddress
import os

PENTAIA_LHOST_ENV = "PENTAIA_LHOST"
PENTAIA_LPORT_ENV = "PENTAIA_LPORT"
DEFAULT_LISTENER_PORT = 4444


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


def _is_port_number(value: object) -> bool:
    """True only for a genuine integer port, never a bool."""
    return isinstance(value, int) and not isinstance(value, bool)


def validate_listener_port(value: object) -> int:
    """Validate and normalize one PentAiA-owned listener port."""
    candidate = value

    if isinstance(candidate, str):
        stripped = candidate.strip()
        if not stripped.isdigit():
            raise ValueError("PENTAIA_LPORT must be a TCP port number.")
        candidate = int(stripped)

    # bool is an int subclass and must never be accepted as a port.
    if not _is_port_number(candidate):
        raise ValueError("PENTAIA_LPORT must be a TCP port number.")

    if not 1 <= candidate <= 65535:
        raise ValueError("PENTAIA_LPORT must be between 1 and 65535.")

    return candidate


def get_phase3_listener_port() -> int:
    """Read the reverse-session listener port from runtime configuration."""
    configured = os.getenv(PENTAIA_LPORT_ENV, "")

    if not configured.strip():
        return DEFAULT_LISTENER_PORT

    return validate_listener_port(configured)
