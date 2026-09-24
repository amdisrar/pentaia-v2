"""Typed configuration for the Phase 4 web application.

This is a foundation, not the full Phase 4 configuration surface. P4-02 needs enough
to start the application and reach its liveness endpoint; later issues add their own
settings (authentication provider selection in P4-07, the SQLite data directory in
P4-09). Guessing at those now would put unused, untested settings into the contract.

Only non-sensitive application settings live here. Identity-provider secrets, session
signing material, SSH credentials and API keys are not read by this module and must
never be exposed through an HTTP response.

The conventions follow ``pentaia.runtime_config``: a named constant per setting,
validation that raises ``ValueError`` naming the variable, and a reader that fails
closed rather than silently substituting a default for a value that was set but is
wrong.
"""

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass

from dotenv import load_dotenv

HOST_ENV = "PENTAIA_WEB_HOST"
PORT_ENV = "PENTAIA_WEB_PORT"
DOCS_ENV = "PENTAIA_WEB_DOCS"

# Loopback by default. The Phase 4 deployment places a reverse proxy on the same
# host, so the application never needs to listen on a public interface, and a secure
# default is worth more here than convenience.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000

# FastAPI serves /docs, /redoc and /openapi.json by default. The Phase 4 deployment
# assumes production debug output is disabled, and the OpenAPI document describes the
# entire browser-facing surface, so documentation is opt-in rather than opt-out.
DEFAULT_DOCS_ENABLED = False

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


@dataclass(frozen=True)
class WebAppConfig:
    """Non-sensitive runtime settings for the Phase 4 web application."""

    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    docs_enabled: bool = DEFAULT_DOCS_ENABLED


def validate_web_host(value: object) -> str:
    """Validate and normalize one HTTP bind address.

    The host and the port are separate settings, so ``host:port`` is a mistake worth
    catching at startup rather than at bind time. A colon is still allowed when the
    value is a genuine IPv6 literal.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{HOST_ENV} must be a non-empty host or IP address.")

    candidate = value.strip()

    if any(character.isspace() for character in candidate) or "/" in candidate:
        raise ValueError(
            f"{HOST_ENV} must be a bare host or IP address, not a URL or path."
        )

    if ":" in candidate:
        try:
            ipaddress.IPv6Address(candidate)
        except ValueError as exc:
            raise ValueError(
                f"{HOST_ENV} must be a bare host or IP address; set the port with "
                f"{PORT_ENV} instead."
            ) from exc

    return candidate


def _is_port_number(value: object) -> bool:
    """True only for a genuine integer port, never a bool."""
    return isinstance(value, int) and not isinstance(value, bool)


def validate_web_port(value: object) -> int:
    """Validate and normalize one TCP port, never accepting a bool as a port."""
    candidate = value

    if isinstance(candidate, str):
        stripped = candidate.strip()
        if not stripped.isdigit():
            raise ValueError(f"{PORT_ENV} must be a TCP port number.")
        candidate = int(stripped)

    # bool is an int subclass and must never be accepted as a port.
    if not _is_port_number(candidate):
        raise ValueError(f"{PORT_ENV} must be a TCP port number.")

    if not 1 <= candidate <= 65535:
        raise ValueError(f"{PORT_ENV} must be between 1 and 65535.")

    return candidate


def validate_docs_enabled(value: object) -> bool:
    """Validate the interactive API documentation switch."""
    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        candidate = value.strip().lower()
        if candidate in _TRUE_VALUES:
            return True
        if candidate in _FALSE_VALUES:
            return False

    allowed = ", ".join(sorted(_TRUE_VALUES | _FALSE_VALUES))
    raise ValueError(f"{DOCS_ENV} must be one of: {allowed}.")


def _read(environ: Mapping[str, str], name: str, default: str) -> str:
    """Read one setting, defaulting only when it is genuinely absent.

    An empty or blank value is passed through to validation and rejected there. That
    is deliberate: silently treating a malformed setting as unset hides a
    configuration mistake.
    """
    value = environ.get(name)

    return default if value is None else value


def load_webapp_config(environ: Mapping[str, str] | None = None) -> WebAppConfig:
    """Load and validate the web application configuration.

    Passing ``environ`` reads only that mapping, which keeps tests hermetic and
    independent of the developer's ``.env``. With no mapping, ``.env`` is loaded the
    same way the existing CLI loads it, and the process environment stays
    authoritative because ``load_dotenv`` does not override variables already set.
    """
    if environ is None:
        load_dotenv()
        environ = os.environ

    host = validate_web_host(_read(environ, HOST_ENV, DEFAULT_HOST))
    port = validate_web_port(_read(environ, PORT_ENV, str(DEFAULT_PORT)))
    docs_enabled = validate_docs_enabled(_read(environ, DOCS_ENV, "false"))

    return WebAppConfig(host=host, port=port, docs_enabled=docs_enabled)
