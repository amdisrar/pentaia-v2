"""Provider-neutral authentication contract for Phase 4.

Phase 4 has two enterprise authentication backends: Active Directory over LDAPS
(P4-05) and RADIUS (P4-06). Both must present the same result to the rest of the
application, so session creation, accounting and the API never depend on which provider
authenticated a request. Nothing here mentions LDAP, TLS or RADIUS.

The four outcomes are the ones the architecture names, and only one of them is a
success. There is deliberately no outcome meaning "probably fine": every ambiguous or
unexpected condition is classified as a failure and fails closed.

The neutral exceptions exist so a provider's transport layer can report *what* went
wrong without leaking library types or library messages upwards. They are translated
into ``AuthResult`` before the result leaves the provider.
"""

import enum
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from pentaia.webapp.identity import AuthenticatedIdentity


class AuthOutcome(enum.Enum):
    """Normalized authentication outcome."""

    #: The credentials were proven and an identity was produced.
    SUCCESS = "success"
    #: The credentials were refused, or the request could not be a valid attempt.
    REJECTED = "rejected"
    #: The provider could not be reached or did not answer in time.
    UNAVAILABLE = "unavailable"
    #: The application's own provider configuration is wrong or unsafe.
    MISCONFIGURED = "misconfigured"


@dataclass(frozen=True)
class AuthResult:
    """The normalized result of one authentication attempt.

    Carries no diagnostic free text. Everything that could echo a credential, a
    library message or directory detail stays server-side in the log, so this object is
    safe to pass to accounting or to a session layer without review.
    """

    outcome: AuthOutcome
    identity: AuthenticatedIdentity | None = None

    def __post_init__(self) -> None:
        if self.outcome is AuthOutcome.SUCCESS:
            if self.identity is None:
                raise ValueError("a successful result must carry an identity.")
        elif self.identity is not None:
            raise ValueError("only a successful result may carry an identity.")

    @property
    def authenticated(self) -> bool:
        """True only for an explicit success."""
        return self.outcome is AuthOutcome.SUCCESS


class ProviderError(Exception):
    """Base class for provider transport failures.

    These never reach a browser. A provider translates them into an ``AuthResult``
    whose outcome fails closed.
    """


class ProviderRejected(ProviderError):
    """The provider refused the credentials."""


class ProviderUnavailable(ProviderError):
    """The provider could not be reached, or timed out."""


class ProviderMisconfigured(ProviderError):
    """Local provider configuration or TLS setup is wrong or unsafe."""


@runtime_checkable
class AuthProvider(Protocol):
    """One configured authentication backend.

    ``name`` is the canonical application auth-source token (for example ``"ad"`` or
    ``"radius"``) and is what ends up in the canonical ``user_id``. Phase 4 activates
    one provider per deployment; provider selection is P4-07.

    Runtime checkable so a test can assert a concrete provider satisfies the contract
    without importing it.
    """

    name: str

    def authenticate(self, username: object, password: object) -> AuthResult:
        """Authenticate one attempt and always return a normalized result.

        Implementations must not raise for a failed authentication, must not retain the
        password, and must not distinguish "wrong password" from "no such user" in
        anything a caller could expose.
        """
        ...
