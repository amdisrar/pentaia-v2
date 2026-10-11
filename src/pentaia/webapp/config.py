"""Typed configuration for the Phase 4 web application.

This is not the full Phase 4 configuration surface. P4-02 needed enough to start the
application and reach its liveness endpoint; P4-07 adds authentication-provider
selection, and P4-08 adds the session, trusted-proxy and login-throttling settings that
belong to the hardened login flow. Later issues add their own settings (the SQLite data
directory in P4-09). Guessing at those now would put unused, untested settings into the
contract.

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
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from dotenv import load_dotenv

from pentaia.appstore.config import StoreConfig, load_store_config

HOST_ENV = "PENTAIA_WEB_HOST"
PORT_ENV = "PENTAIA_WEB_PORT"
DOCS_ENV = "PENTAIA_WEB_DOCS"
AUTH_PROVIDER_ENV = "PENTAIA_AUTH_PROVIDER"
PUBLIC_ORIGIN_ENV = "PENTAIA_PUBLIC_ORIGIN"
SESSION_IDLE_TIMEOUT_ENV = "PENTAIA_SESSION_IDLE_TIMEOUT"
SESSION_ABSOLUTE_LIFETIME_ENV = "PENTAIA_SESSION_ABSOLUTE_LIFETIME"
TRUSTED_PROXIES_ENV = "PENTAIA_TRUSTED_PROXIES"
LOGIN_MAX_ATTEMPTS_ENV = "PENTAIA_LOGIN_MAX_ATTEMPTS"
LOGIN_WINDOW_SECONDS_ENV = "PENTAIA_LOGIN_WINDOW_SECONDS"
LOGIN_MAX_KEYS_ENV = "PENTAIA_LOGIN_MAX_KEYS"

# Loopback by default. The Phase 4 deployment places a reverse proxy on the same
# host, so the application never needs to listen on a public interface, and a secure
# default is worth more here than convenience.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000

# FastAPI serves /docs, /redoc and /openapi.json by default. The Phase 4 deployment
# assumes production debug output is disabled, and the OpenAPI document describes the
# entire browser-facing surface, so documentation is opt-in rather than opt-out.
DEFAULT_DOCS_ENABLED = False

#: Every authentication backend Phase 4 defines. Both are valid configuration values;
#: which of them can actually be *built* is decided by
#: ``pentaia.webapp.auth.selection``, so that RADIUS keeps its place in the contract
#: while issue #56 is deferred.
SUPPORTED_AUTH_PROVIDERS = ("ad", "radius")

# Session timeouts are the architecture's defaults: idle 30 minutes, absolute 12 hours.
# The absolute lifetime is never extended by activity, so the bounds below exist to
# catch a typo rather than to offer a range of policies.
DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS = 30 * 60
DEFAULT_SESSION_ABSOLUTE_LIFETIME_SECONDS = 12 * 60 * 60
MIN_SESSION_TIMEOUT_SECONDS = 60
MAX_SESSION_IDLE_TIMEOUT_SECONDS = 24 * 60 * 60
MIN_SESSION_ABSOLUTE_LIFETIME_SECONDS = 300
MAX_SESSION_ABSOLUTE_LIFETIME_SECONDS = 7 * 24 * 60 * 60

#: The reverse proxy runs on the same host, so loopback is the only default that trusts
#: anything. Setting this to a blank value trusts no peer at all, which is safe: every
#: request is then keyed by the address it actually came from.
DEFAULT_TRUSTED_PROXIES = ("127.0.0.1",)

#: Login throttling. Five failures per username/address pair in a fifteen-minute window,
#: with aggregate caps that stop one address spraying many usernames and stop many
#: addresses converging on one username.
DEFAULT_LOGIN_MAX_ATTEMPTS = 5
DEFAULT_LOGIN_WINDOW_SECONDS = 15 * 60
DEFAULT_LOGIN_MAX_KEYS = 10_000
MAX_LOGIN_ATTEMPTS = 1000
MIN_LOGIN_WINDOW_SECONDS = 30
MAX_LOGIN_WINDOW_SECONDS = 24 * 60 * 60
MIN_LOGIN_MAX_KEYS = 100
MAX_LOGIN_MAX_KEYS = 1_000_000

_TRUST_EVERY_PEER_MESSAGE = (
    f"{TRUSTED_PROXIES_ENV} must not trust every peer; list the proxy address or "
    "network explicitly."
)

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


@dataclass(frozen=True)
class WebAppConfig:
    """Non-sensitive runtime settings for the Phase 4 web application."""

    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    docs_enabled: bool = DEFAULT_DOCS_ENABLED
    #: Selected authentication backend, or ``None`` when the deployment has not chosen
    #: one. ``None`` means no provider is constructed and nobody can authenticate; it
    #: never means anonymous access.
    auth_provider: str | None = None
    #: Idle timeout in seconds. Activity refreshes this; it never extends
    #: ``session_absolute_lifetime``.
    session_idle_timeout: int = DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS
    #: Absolute session lifetime in seconds, fixed at session creation and never
    #: extended. Validated to be at least the idle timeout, otherwise the idle timer
    #: could never fire.
    session_absolute_lifetime: int = DEFAULT_SESSION_ABSOLUTE_LIFETIME_SECONDS
    #: Peers whose ``X-Forwarded-For`` header is believed. Addresses or CIDR networks;
    #: an empty tuple trusts nobody, and a wildcard is refused rather than honoured.
    trusted_proxies: tuple[str, ...] = DEFAULT_TRUSTED_PROXIES
    #: Failed logins allowed per username/address pair before the pair is throttled.
    login_max_attempts: int = DEFAULT_LOGIN_MAX_ATTEMPTS
    #: Length of the throttling window, and of a lockout, in seconds.
    login_window_seconds: int = DEFAULT_LOGIN_WINDOW_SECONDS
    #: Upper bound on throttling state, so it cannot be grown without limit.
    login_max_keys: int = DEFAULT_LOGIN_MAX_KEYS
    #: Application store configuration: memory (the default) or the durable SQLite
    #: store, which requires ``PENTAIA_DATA_DIR``. ``PENTAIA_STORE_MODE=sqlite`` is the
    #: explicit operational choice; the memory mode cannot be entered by accident and
    #: records nothing durable.
    store: StoreConfig = field(default_factory=StoreConfig)
    #: The origin this deployment is reachable at, as ``scheme://host:port``, or ``None``
    #: when it has not been declared. When set it is the only authority the browser's
    #: ``Origin`` header is compared against, so full scheme and port verification is
    #: possible without trusting any forwarded header.
    public_origin: str | None = None

    def __post_init__(self) -> None:
        """Normalize the setting that is compared for security.

        ``load_webapp_config`` validates it, but a configuration built directly — as tests
        and embedding code do — must not be able to hold a raw value that would silently
        fail every origin comparison. Normalizing here means every consumer sees the same
        canonical form, and an unusable value is refused where it is supplied.
        """
        object.__setattr__(
            self, "public_origin", validate_public_origin(self.public_origin)
        )


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


def _is_whole_number(value: object) -> bool:
    """True only for a genuine integer, never a bool."""
    return isinstance(value, int) and not isinstance(value, bool)


def _whole_number(value: object, *, field: str) -> int:
    """Coerce one setting to an integer, accepting the string an environment supplies."""
    candidate = value

    if isinstance(candidate, str):
        stripped = candidate.strip()
        if not stripped.isdigit():
            raise ValueError(f"{field} must be a whole number.")
        candidate = int(stripped)

    if not _is_whole_number(candidate):
        raise ValueError(f"{field} must be a whole number.")

    return candidate


def validate_web_port(value: object) -> int:
    """Validate and normalize one TCP port, never accepting a bool as a port."""
    candidate = value

    if isinstance(candidate, str):
        stripped = candidate.strip()
        if not stripped.isdigit():
            raise ValueError(f"{PORT_ENV} must be a TCP port number.")
        candidate = int(stripped)

    # bool is an int subclass and must never be accepted as a port.
    if not _is_whole_number(candidate):
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


def _is_string_setting(value: object) -> bool:
    """True only for a string setting, which is all an environment can supply.

    Exists so the type check reads as a value check: a wrong type is reported the same
    way as any other invalid setting, as ``ValueError`` naming the variable, which is
    what every validator in ``pentaia.runtime_config`` does.
    """
    return isinstance(value, str)


def validate_auth_provider(value: object) -> str | None:
    """Validate the selected authentication backend.

    Both Phase 4 providers are accepted as configuration values. Whether the selected
    one can actually be constructed is decided by
    ``pentaia.webapp.auth.selection``; this function only rejects values that are not
    providers at all, so an unknown name fails at startup instead of being silently
    ignored.

    Absent or blank means no provider is configured, which is a valid state: the
    application starts, but nothing can authenticate. Blank is treated as unset rather
    than rejected because leaving the setting empty is the documented way to run the
    web application without authentication during development.
    """
    if value is None:
        return None

    if not _is_string_setting(value):
        raise ValueError(
            f"{AUTH_PROVIDER_ENV} must be one of: {', '.join(SUPPORTED_AUTH_PROVIDERS)}."
        )

    candidate = value.strip().lower()

    if not candidate:
        return None

    if candidate not in SUPPORTED_AUTH_PROVIDERS:
        raise ValueError(
            f"{AUTH_PROVIDER_ENV} must be one of: "
            f"{', '.join(SUPPORTED_AUTH_PROVIDERS)} (got {candidate!r})."
        )

    return candidate


def _bounded_seconds(
    value: object,
    *,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    """Validate one whole number of seconds inside an inclusive range."""
    candidate = _whole_number(value, field=field)

    if not minimum <= candidate <= maximum:
        raise ValueError(f"{field} must be between {minimum} and {maximum} seconds.")

    return candidate


def validate_session_idle_timeout(value: object) -> int:
    """Validate the idle timeout, in seconds."""
    return _bounded_seconds(
        value,
        field=SESSION_IDLE_TIMEOUT_ENV,
        minimum=MIN_SESSION_TIMEOUT_SECONDS,
        maximum=MAX_SESSION_IDLE_TIMEOUT_SECONDS,
    )


def validate_session_absolute_lifetime(value: object) -> int:
    """Validate the absolute session lifetime, in seconds."""
    return _bounded_seconds(
        value,
        field=SESSION_ABSOLUTE_LIFETIME_ENV,
        minimum=MIN_SESSION_ABSOLUTE_LIFETIME_SECONDS,
        maximum=MAX_SESSION_ABSOLUTE_LIFETIME_SECONDS,
    )


def validate_trusted_proxies(value: object) -> tuple[str, ...]:
    """Validate the peers whose forwarded headers are believed.

    Each entry must be an IP address or a CIDR network. A wildcard is refused rather
    than honoured: trusting every peer would make ``X-Forwarded-For`` authoritative for
    anyone who can reach the application, which is exactly what the throttling key must
    not allow. A blank value is valid and means no peer is trusted.
    """
    if not _is_string_setting(value):
        raise ValueError(
            f"{TRUSTED_PROXIES_ENV} must be a comma-separated list of IP addresses or "
            "networks."
        )

    entries = tuple(entry.strip() for entry in value.split(",") if entry.strip())

    for entry in entries:
        if entry == "*":
            raise ValueError(_TRUST_EVERY_PEER_MESSAGE)

        network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None

        try:
            if "/" in entry:
                network = ipaddress.ip_network(entry, strict=False)
            else:
                ipaddress.ip_address(entry)
        except ValueError:
            raise ValueError(
                f"{TRUSTED_PROXIES_ENV} entries must be IP addresses or networks "
                f"(got {entry!r})."
            ) from None

        # ``0.0.0.0/0`` and ``::/0`` mean the same thing as a wildcard, so they are
        # refused for the same reason.
        if network is not None and network.prefixlen == 0:
            raise ValueError(_TRUST_EVERY_PEER_MESSAGE)

    return entries


#: Scheme to default port, for normalizing an origin so two spellings of one origin are
#: equal (``https://host`` and ``https://host:443``).
DEFAULT_ORIGIN_PORTS = {"http": 80, "https": 443}


def normalize_origin(value: object) -> str | None:
    """Return one origin as ``scheme://host:port``, or ``None`` if it is not an origin.

    Only a scheme, a host and an optional port survive: a path, query, fragment or
    embedded credential makes the value something other than an origin and it is refused
    rather than trimmed. The port is made explicit so ``https://host`` and
    ``https://host:443`` compare equal.
    """
    if not isinstance(value, str):
        return None

    candidate = value.strip()

    if not candidate:
        return None

    parsed = urlsplit(candidate)
    scheme = parsed.scheme.lower()

    if scheme not in DEFAULT_ORIGIN_PORTS:
        return None

    if parsed.hostname is None or parsed.username or parsed.password:
        return None

    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        return None

    try:
        port = parsed.port or DEFAULT_ORIGIN_PORTS[scheme]
    except ValueError:
        return None

    host = parsed.hostname.lower()

    if ":" in host:
        host = f"[{host}]"

    return f"{scheme}://{host}:{port}"


def validate_public_origin(value: object) -> str | None:
    """Validate the deployment's declared public origin.

    Setting it is what makes full-origin verification possible: the browser's ``Origin``
    is compared against this value including scheme and port, so nothing has to be
    inferred from ``Host`` or from a forwarded header. Leaving it unset is valid — the
    safer fallback described in ``require_csrf`` then applies — but a deployed instance
    should set it.
    """
    if value is None:
        return None

    if not _is_string_setting(value):
        raise ValueError(
            f"{PUBLIC_ORIGIN_ENV} must be an origin such as https://pentaia.example.test."
        )

    if not value.strip():
        return None

    normalized = normalize_origin(value)

    if normalized is None:
        raise ValueError(
            f"{PUBLIC_ORIGIN_ENV} must be an origin with an http or https scheme, a host "
            "and an optional port: no path, query, fragment or credentials."
        )

    return normalized


def validate_login_max_attempts(value: object) -> int:
    """Validate the per-username/address failure allowance."""
    candidate = _whole_number(value, field=LOGIN_MAX_ATTEMPTS_ENV)

    if not 1 <= candidate <= MAX_LOGIN_ATTEMPTS:
        raise ValueError(
            f"{LOGIN_MAX_ATTEMPTS_ENV} must be between 1 and {MAX_LOGIN_ATTEMPTS}."
        )

    return candidate


def validate_login_window_seconds(value: object) -> int:
    """Validate the throttling window, in seconds."""
    return _bounded_seconds(
        value,
        field=LOGIN_WINDOW_SECONDS_ENV,
        minimum=MIN_LOGIN_WINDOW_SECONDS,
        maximum=MAX_LOGIN_WINDOW_SECONDS,
    )


def validate_login_max_keys(value: object) -> int:
    """Validate the upper bound on throttling state."""
    candidate = _whole_number(value, field=LOGIN_MAX_KEYS_ENV)

    if not MIN_LOGIN_MAX_KEYS <= candidate <= MAX_LOGIN_MAX_KEYS:
        raise ValueError(
            f"{LOGIN_MAX_KEYS_ENV} must be between {MIN_LOGIN_MAX_KEYS} and "
            f"{MAX_LOGIN_MAX_KEYS}."
        )

    return candidate


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
    auth_provider = validate_auth_provider(_read(environ, AUTH_PROVIDER_ENV, ""))
    session_idle_timeout = validate_session_idle_timeout(
        _read(environ, SESSION_IDLE_TIMEOUT_ENV, str(DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS))
    )
    session_absolute_lifetime = validate_session_absolute_lifetime(
        _read(
            environ,
            SESSION_ABSOLUTE_LIFETIME_ENV,
            str(DEFAULT_SESSION_ABSOLUTE_LIFETIME_SECONDS),
        )
    )

    # An idle timeout at or beyond the absolute lifetime can never fire, so the session
    # would silently outlive the policy the operator believes is in force.
    if session_idle_timeout > session_absolute_lifetime:
        raise ValueError(
            f"{SESSION_IDLE_TIMEOUT_ENV} must not exceed {SESSION_ABSOLUTE_LIFETIME_ENV}."
        )

    trusted_proxies = (
        DEFAULT_TRUSTED_PROXIES
        if TRUSTED_PROXIES_ENV not in environ
        else validate_trusted_proxies(environ[TRUSTED_PROXIES_ENV])
    )
    login_max_attempts = validate_login_max_attempts(
        _read(environ, LOGIN_MAX_ATTEMPTS_ENV, str(DEFAULT_LOGIN_MAX_ATTEMPTS))
    )
    login_window_seconds = validate_login_window_seconds(
        _read(environ, LOGIN_WINDOW_SECONDS_ENV, str(DEFAULT_LOGIN_WINDOW_SECONDS))
    )
    login_max_keys = validate_login_max_keys(
        _read(environ, LOGIN_MAX_KEYS_ENV, str(DEFAULT_LOGIN_MAX_KEYS))
    )
    public_origin = validate_public_origin(_read(environ, PUBLIC_ORIGIN_ENV, ""))
    store = load_store_config(environ)

    return WebAppConfig(
        host=host,
        port=port,
        docs_enabled=docs_enabled,
        auth_provider=auth_provider,
        session_idle_timeout=session_idle_timeout,
        session_absolute_lifetime=session_absolute_lifetime,
        trusted_proxies=trusted_proxies,
        login_max_attempts=login_max_attempts,
        login_window_seconds=login_window_seconds,
        login_max_keys=login_max_keys,
        public_origin=public_origin,
        store=store,
    )
