"""Phase 4 authentication providers.

``base`` holds the provider-neutral contract the rest of the application uses: the
outcome enum, the result model, and the neutral transport errors. ``ad`` implements
Active Directory over LDAPS (P4-05); the RADIUS provider (P4-06) will sit beside it
behind the same contract.

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
