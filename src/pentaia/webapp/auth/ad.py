"""Active Directory authentication over LDAPS.

The Phase 4 default is a **direct-user bind**: the supplied username and password are
bound straight to Active Directory over LDAPS, with no search and no service account.
That choice is deliberate:

* it proves the supplied password rather than merely looking a user up,
* it needs no stored privileged directory credential,
* it needs no directory read right at all, and
* it constructs no LDAP filter, so there is no filter-injection surface to get wrong.

Transport rules that are not configurable, because a deployment must not be able to
turn them off:

* **LDAPS only.** ``use_ssl=True`` is hardcoded; there is no plaintext path and no
  ``ldap://`` fallback for password authentication.
* **Certificate validation is mandatory.** ``tls`` is always built with
  ``ssl.CERT_REQUIRED``, and ldap3 verifies the server name after the handshake. There
  is no "ignore verification" switch, and attempting to configure one is refused rather
  than ignored.
* **No directory read.** ``get_info=NONE`` is set because ldap3 defaults to ``SCHEMA``,
  which would perform a schema search on connect.
* **No referral chasing.** ``auto_referrals=False``, so a bind is never redirected to a
  host the operator did not configure.
* **Bounded timeouts.** Every connection and read carries a configured timeout.
* **UPN usernames only.** The supplied username must be ``local@domain``. The down-level
  ``DOMAIN\\user`` form is refused rather than converted; see
  :func:`validate_upn_username` for why.

ldap3 is the only library this application knows about for LDAP: it is pure Python (no
native build dependency), supports LDAPS with an explicit validation mode and a custom
CA bundle, supports direct bind, and exposes bounded connect/receive timeouts with a
usable exception taxonomy. All library-specific handling is confined to
:class:`Ldap3DirectoryBinder`, so no other module imports an LDAP type.
"""

import logging
import os
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from dotenv import load_dotenv
from ldap3 import NONE, SIMPLE, Connection, Server, Tls
from ldap3.core import exceptions as ldap_exceptions

from pentaia.webapp.auth.base import (
    AuthOutcome,
    AuthProvider,
    AuthResult,
    ProviderMisconfigured,
    ProviderRejected,
    ProviderUnavailable,
)
from pentaia.webapp.identity import (
    AUTH_SOURCE_AD,
    AuthenticatedIdentity,
    normalize_username,
)

logger = logging.getLogger(__name__)

HOST_ENV = "PENTAIA_AD_HOST"
PORT_ENV = "PENTAIA_AD_PORT"
CA_FILE_ENV = "PENTAIA_AD_CA_FILE"
CONNECT_TIMEOUT_ENV = "PENTAIA_AD_CONNECT_TIMEOUT"
RECEIVE_TIMEOUT_ENV = "PENTAIA_AD_RECEIVE_TIMEOUT"

DEFAULT_AD_PORT = 636
DEFAULT_CONNECT_TIMEOUT_SECONDS = 5.0
DEFAULT_RECEIVE_TIMEOUT_SECONDS = 5.0

#: Upper bound on any single authentication operation. A directory that cannot answer
#: within this is treated as unavailable rather than being allowed to hold a request.
MAX_TIMEOUT_SECONDS = 60.0

#: Settings that would weaken transport security. Certificate validation and LDAPS are
#: mandatory, so rather than silently ignoring these an attempt to set one is refused.
#: Failing loudly is the point: an operator who believes they disabled verification must
#: not be left thinking it took effect.
UNSUPPORTED_INSECURE_SETTINGS = (
    "PENTAIA_AD_USE_SSL",
    "PENTAIA_AD_VERIFY_TLS",
    "PENTAIA_AD_TLS_VERIFY",
    "PENTAIA_AD_INSECURE",
    "PENTAIA_AD_INSECURE_SKIP_VERIFY",
)


def validate_ad_host(value: object) -> str:
    """Validate one LDAPS host.

    A bare host is required. A URL is refused explicitly, because ``ldap://`` in this
    setting is usually an attempt to reach a plaintext endpoint and must never be
    accepted as a silent downgrade.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{HOST_ENV} is required and must be a non-empty hostname or IP.")

    candidate = value.strip()

    if "://" in candidate:
        raise ValueError(
            f"{HOST_ENV} must be a bare host, not a URL. LDAPS is always used and "
            "there is no plaintext fallback."
        )

    if any(character.isspace() for character in candidate) or "/" in candidate:
        raise ValueError(
            f"{HOST_ENV} must be a bare hostname or IP address, not a URL or path."
        )

    if ":" in candidate:
        # A colon is only acceptable in a genuine IPv6 literal; otherwise it is a
        # host:port mistake.
        import ipaddress

        try:
            ipaddress.IPv6Address(candidate)
        except ValueError as exc:
            raise ValueError(
                f"{HOST_ENV} must be a bare host; set the port with {PORT_ENV} instead."
            ) from exc

    return candidate


def _is_number(value: object) -> bool:
    """True for a genuine int/float, never a bool."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_port_number(value: object) -> bool:
    """True only for a genuine integer port, never a bool."""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_ca_path_value(value: object) -> bool:
    """True for the shapes a CA setting may legitimately take."""
    return isinstance(value, (str, Path))


def validate_ad_port(value: object) -> int:
    """Validate the LDAPS port."""
    candidate = value

    if isinstance(candidate, str):
        stripped = candidate.strip()
        if not stripped.isdigit():
            raise ValueError(f"{PORT_ENV} must be a TCP port number.")
        candidate = int(stripped)

    if not _is_port_number(candidate):
        raise ValueError(f"{PORT_ENV} must be a TCP port number.")

    if not 1 <= candidate <= 65535:
        raise ValueError(f"{PORT_ENV} must be between 1 and 65535.")

    return candidate


def validate_ad_timeout(value: object, *, field: str) -> float:
    """Validate one bounded timeout in seconds."""
    candidate: object = value

    if isinstance(candidate, str):
        stripped = candidate.strip()
        try:
            candidate = float(stripped)
        except ValueError as exc:
            raise ValueError(f"{field} must be a number of seconds.") from exc

    if not _is_number(candidate):
        raise ValueError(f"{field} must be a number of seconds.")

    seconds = float(candidate)  # type: ignore[arg-type]

    if not 0 < seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError(f"{field} must be greater than 0 and at most {MAX_TIMEOUT_SECONDS:g}.")

    return seconds


def validate_upn_username(value: object) -> str:
    """Validate and normalize one Active Directory UPN.

    Active Directory is the only Phase 4 provider that requires this shape, so the rule
    lives here rather than in the shared identity model: RADIUS may legitimately
    authenticate other normalized username forms, and the generic
    :class:`~pentaia.webapp.identity.AuthenticatedIdentity` must not be narrowed.

    PentAiA builds the canonical identity from the username it was given, so accepting
    both ``user@example.com`` and ``DOMAIN\\user`` would give one AD principal two
    different PentAiA identities. Converting between them is not an option either: it
    would mean guessing a UPN suffix, and resolving it properly would require exactly
    the directory search this provider exists to avoid. The down-level form is refused.

    The Phase 4 normalization rules are applied first, so the value is trimmed,
    lower-cased, and rejected for whitespace, ``:`` or control characters before the UPN
    shape is considered. No dot is required in the domain part, so a single-label UPN
    suffix still works.
    """
    normalized = normalize_username(value)

    if "\\" in normalized:
        raise ValueError(
            "the down-level DOMAIN\\user form is not accepted; supply a UPN such as "
            "user@example.com."
        )

    if normalized.count("@") != 1:
        raise ValueError("username must be a UPN of the form local@domain.")

    local_part, _, domain_part = normalized.partition("@")

    if not local_part or not domain_part:
        raise ValueError("a UPN must have a non-empty local part and domain.")

    for part, label in ((local_part, "local part"), (domain_part, "domain")):
        if part.startswith(".") or part.endswith(".") or ".." in part:
            raise ValueError(f"the UPN {label} is malformed.")

    return normalized


def validate_ca_file(value: object) -> Path | None:
    """Validate the optional private CA bundle, failing closed when it is unusable."""
    if value is None:
        return None

    # A blank setting means "no private CA bundle", so the system trust store is used.
    if isinstance(value, str) and not value.strip():
        return None

    # Anything that is not a path or a string is a configuration error like any other,
    # and reported the same way as the other validators in this module.
    if not _is_ca_path_value(value):
        raise ValueError(f"{CA_FILE_ENV} must be a filesystem path.")

    candidate = Path(value.strip()) if isinstance(value, str) else Path(value)

    if not candidate.exists():
        raise ValueError(f"{CA_FILE_ENV} does not exist: {candidate}")

    if not candidate.is_file():
        raise ValueError(f"{CA_FILE_ENV} is not a regular file: {candidate}")

    if not os.access(candidate, os.R_OK):
        raise ValueError(f"{CA_FILE_ENV} is not readable: {candidate}")

    return candidate


@dataclass(frozen=True)
class ADConfig:
    """Frozen Active Directory provider configuration.

    Only what a direct-user bind actually needs. There is no base DN, no search filter
    and no service-account bind credential, because a direct bind requires none of them;
    adding them would create configuration an operator could set without it having any
    effect.
    """

    host: str
    port: int = DEFAULT_AD_PORT
    ca_file: Path | None = None
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT_SECONDS
    receive_timeout: float = DEFAULT_RECEIVE_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        object.__setattr__(self, "host", validate_ad_host(self.host))
        object.__setattr__(self, "port", validate_ad_port(self.port))
        object.__setattr__(
            self,
            "connect_timeout",
            validate_ad_timeout(self.connect_timeout, field=CONNECT_TIMEOUT_ENV),
        )
        object.__setattr__(
            self,
            "receive_timeout",
            validate_ad_timeout(self.receive_timeout, field=RECEIVE_TIMEOUT_ENV),
        )
        object.__setattr__(self, "ca_file", validate_ca_file(self.ca_file))


def _read(environ: Mapping[str, str], name: str, default: str | None) -> str | None:
    value = environ.get(name)

    return default if value is None else value


def load_ad_config(environ: Mapping[str, str] | None = None) -> ADConfig:
    """Load and validate the AD provider configuration.

    Fails closed on a missing host, an invalid port or timeout, an unusable CA file, and
    on an attempt to configure a weaker transport. A supplied mapping is read on its own
    so tests stay independent of the developer's ``.env``.
    """
    if environ is None:
        load_dotenv()
        environ = os.environ

    attempted = sorted(
        name for name in UNSUPPORTED_INSECURE_SETTINGS if environ.get(name) is not None
    )

    if attempted:
        raise ValueError(
            "LDAPS with certificate validation is mandatory and cannot be disabled; "
            f"remove: {', '.join(attempted)}."
        )

    # Defaults apply only when a variable is absent. A variable that is present but
    # blank is passed through to validation and rejected there, because silently
    # treating a malformed setting as unset hides a configuration mistake. The CA path
    # is the one exception: it is optional, so blank means "no private CA bundle".
    return ADConfig(
        host=_read(environ, HOST_ENV, ""),
        port=_read(environ, PORT_ENV, str(DEFAULT_AD_PORT)),
        ca_file=_read(environ, CA_FILE_ENV, None),
        connect_timeout=_read(
            environ, CONNECT_TIMEOUT_ENV, str(DEFAULT_CONNECT_TIMEOUT_SECONDS)
        ),
        receive_timeout=_read(
            environ, RECEIVE_TIMEOUT_ENV, str(DEFAULT_RECEIVE_TIMEOUT_SECONDS)
        ),
    )


def build_tls(config: ADConfig) -> Tls:
    """Build the LDAPS TLS settings.

    ``validate`` is hardcoded to ``ssl.CERT_REQUIRED``: there is no parameter, no
    environment variable and no code path that lowers it. ldap3 then additionally
    matches the presented certificate against the server name, so both the chain and the
    hostname are checked.

    ``version`` is left unset, which makes ldap3 use ``ssl.create_default_context``:
    secure protocol defaults, and either the system trust store or, when configured,
    only the supplied private CA bundle.
    """
    return Tls(
        validate=ssl.CERT_REQUIRED,
        ca_certs_file=str(config.ca_file) if config.ca_file is not None else None,
    )


class DirectoryBinder(Protocol):
    """The narrow transport seam a direct bind needs.

    Exists so the provider can be tested without a directory, and so no other module
    depends on an LDAP type. Implementations report failure with the neutral
    ``Provider*`` errors.
    """

    def bind(self, *, username: str, password: str) -> None:
        """Attempt one direct bind. Returns normally on success."""
        ...


class Ldap3DirectoryBinder:
    """Direct-bind transport over LDAPS, implemented with ldap3.

    The only place in the application that imports an LDAP type. Every library failure
    is translated into the provider-neutral error contract.
    """

    def __init__(self, config: ADConfig) -> None:
        self._config = config

    def bind(self, *, username: str, password: str) -> None:
        config = self._config

        server = Server(
            config.host,
            port=config.port,
            # LDAPS only. There is no plaintext path and no downgrade branch.
            use_ssl=True,
            tls=build_tls(config),
            connect_timeout=config.connect_timeout,
            # A direct bind needs no directory read. ldap3 defaults to SCHEMA, which
            # would perform a schema search on connect and require read rights.
            get_info=NONE,
        )

        connection = Connection(
            server,
            user=username,
            password=password,
            authentication=SIMPLE,
            auto_bind=False,
            # Never follow a referral to a host the operator did not configure.
            auto_referrals=False,
            raise_exceptions=True,
            receive_timeout=config.receive_timeout,
        )

        try:
            try:
                bound = connection.bind()
            except ldap_exceptions.LDAPInvalidCredentialsResult as exc:
                raise ProviderRejected("the directory rejected the credentials") from exc
            except ldap_exceptions.LDAPBindError as exc:
                raise ProviderRejected("the directory refused the bind") from exc
            except ldap_exceptions.LDAPSSLConfigurationError as exc:
                raise ProviderMisconfigured("the LDAPS configuration is invalid") from exc
            except ldap_exceptions.LDAPCommunicationError as exc:
                # A failed handshake can surface as a communication error, so look
                # through the cause chain before calling it a network problem.
                if _caused_by_tls_failure(exc):
                    raise ProviderMisconfigured(
                        "the LDAPS certificate or TLS negotiation was refused"
                    ) from exc
                raise ProviderUnavailable("the directory could not be reached") from exc
            except TimeoutError as exc:
                raise ProviderUnavailable("the directory did not answer in time") from exc
            except (ssl.SSLError, ssl.CertificateError) as exc:
                raise ProviderMisconfigured(
                    "the LDAPS certificate or TLS negotiation was refused"
                ) from exc
            except ldap_exceptions.LDAPException as exc:
                raise ProviderUnavailable(
                    "the directory returned an unexpected error"
                ) from exc
        finally:
            _unbind_quietly(connection)

        if not bound:
            raise ProviderRejected("the directory refused the bind")


def _caused_by_tls_failure(error: BaseException) -> bool:
    """True when a failure chain contains a TLS or certificate error."""
    seen: set[int] = set()
    current: BaseException | None = error

    while current is not None and id(current) not in seen:
        seen.add(id(current))

        if isinstance(current, (ssl.SSLError, ssl.CertificateError)):
            return True

        current = current.__cause__ or current.__context__

    return False


def _unbind_quietly(connection: Connection) -> None:
    """Release the socket without masking the classification of the real failure."""
    try:
        connection.unbind()
    except Exception:  # noqa: BLE001 - a failed teardown must not change the outcome
        logger.debug("Unbinding the LDAPS connection failed; ignoring.")


class ADAuthProvider:
    """Active Directory authentication over LDAPS.

    Satisfies the provider-neutral ``AuthProvider`` contract, so a caller never learns
    whether AD or RADIUS produced a result.
    """

    name = AUTH_SOURCE_AD

    def __init__(self, config: ADConfig, *, binder: DirectoryBinder | None = None) -> None:
        self._config = config
        self._binder = binder if binder is not None else Ldap3DirectoryBinder(config)

    def authenticate(self, username: object, password: object) -> AuthResult:
        """Authenticate one attempt and always return a normalized result.

        The password is used for the bind and nothing else: it is never stored, logged,
        returned, or attached to the identity. Two conditions are refused *before* any
        connection is made, because both would otherwise reach the directory:

        * a username that does not satisfy the Phase 4 identity rules, and
        * an empty or non-string password, which LDAP simple bind can treat as an
          anonymous "unauthenticated bind" that succeeds without proving anything.
        """
        if not isinstance(password, str) or password == "":
            logger.warning(
                "AD authentication rejected reason=empty_password host=%s port=%s",
                self._config.host,
                self._config.port,
            )

            return AuthResult(AuthOutcome.REJECTED)

        try:
            normalized_username = validate_upn_username(username)
        except ValueError:
            # The supplied value is deliberately not logged: it failed validation and
            # may be an attack string rather than an identity. A down-level name and a
            # malformed one are both simply not a UPN this provider will bind.
            logger.warning(
                "AD authentication rejected reason=malformed_username host=%s port=%s",
                self._config.host,
                self._config.port,
            )

            return AuthResult(AuthOutcome.REJECTED)

        try:
            self._binder.bind(username=normalized_username, password=password)
        except ProviderRejected:
            logger.info(
                "AD authentication rejected reason=credentials_rejected host=%s port=%s",
                self._config.host,
                self._config.port,
            )

            return AuthResult(AuthOutcome.REJECTED)
        except ProviderUnavailable as exc:
            logger.warning(
                "AD authentication unavailable reason=%s host=%s port=%s",
                type(exc).__name__,
                self._config.host,
                self._config.port,
            )

            return AuthResult(AuthOutcome.UNAVAILABLE)
        except ProviderMisconfigured as exc:
            logger.error(
                "AD authentication misconfigured reason=%s host=%s port=%s",
                type(exc).__name__,
                self._config.host,
                self._config.port,
            )

            return AuthResult(AuthOutcome.MISCONFIGURED)
        except Exception as exc:  # noqa: BLE001 - unknown failures must fail closed
            # An unclassified failure is not a reason to admit anyone. Only the
            # exception type is logged: a library message could echo a credential.
            logger.error(
                "AD authentication failed closed reason=%s host=%s port=%s",
                type(exc).__name__,
                self._config.host,
                self._config.port,
            )

            return AuthResult(AuthOutcome.UNAVAILABLE)

        identity = AuthenticatedIdentity.from_provider(
            auth_source=AUTH_SOURCE_AD,
            username=normalized_username,
        )

        logger.info(
            "AD authentication succeeded user_id=%s host=%s port=%s",
            identity.user_id,
            self._config.host,
            self._config.port,
        )

        return AuthResult(AuthOutcome.SUCCESS, identity=identity)


def build_ad_provider(config: ADConfig | None = None) -> AuthProvider:
    """Build the AD provider, loading configuration when none is supplied.

    Provider *selection* is P4-07; this only assembles the AD provider once a deployment
    has decided to use it.
    """
    return ADAuthProvider(config if config is not None else load_ad_config())
