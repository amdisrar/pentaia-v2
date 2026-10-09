"""Phase 4 authentication providers.

``base`` holds the provider-neutral contract the rest of the application uses: the
outcome enum, the result model, and the neutral transport errors. ``ad`` implements
Active Directory over LDAPS (P4-05); the RADIUS provider (P4-06) will sit beside it
behind the same contract. ``selection`` is where the configured provider name (P4-07)
becomes one built provider, and it is the only module that decides which backends a
deployment may have.

Only the contract is re-exported here, never a concrete provider or the selector, so
importing this package does not pick a backend.

Nothing outside this package should import an LDAP or RADIUS type.
"""

from pentaia.webapp.auth.base import (
    AuthOutcome,
    AuthProvider,
    AuthResult,
    ProviderError,
    ProviderMisconfigured,
    ProviderRejected,
    ProviderUnavailable,
)

__all__ = [
    "AuthOutcome",
    "AuthProvider",
    "AuthResult",
    "ProviderError",
    "ProviderMisconfigured",
    "ProviderRejected",
    "ProviderUnavailable",
]
