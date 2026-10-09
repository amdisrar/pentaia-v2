"""Authentication provider selection.

Phase 4 defines exactly one active authentication backend per deployment. This module is
where a *configured* provider name becomes a *constructed* provider, and it is the only
place that decides which backends may be built.

Two facts are deliberately kept apart:

* :data:`pentaia.webapp.config.SUPPORTED_AUTH_PROVIDERS` is the configuration contract —
  the set of names Phase 4 defines. ``radius`` is in it and stays in it.
* :data:`IMPLEMENTED_AUTH_PROVIDERS` is what this build can actually construct. RADIUS is
  deferred (issue #56), so selecting it fails closed with that stated plainly.

There is **no fallback of any kind**. A configured provider is either built or the
application refuses to start; a failing provider is never quietly replaced by another
mechanism. That is the security property of this module, and it is asserted behaviourally
in ``tests/test_webapp_auth_selection.py`` rather than only by reading the source.

A provider named in the configuration contract but absent from the builders fails closed
automatically, so adding a name to the contract without implementing it cannot quietly
start a deployment whose active provider is not the one the operator chose.
"""

from collections.abc import Callable, Mapping

from pentaia.webapp.auth.ad import build_ad_provider, load_ad_config
from pentaia.webapp.auth.base import AuthProvider, ProviderMisconfigured
from pentaia.webapp.config import validate_auth_provider
from pentaia.webapp.identity import AUTH_SOURCE_AD, AUTH_SOURCE_RADIUS

ProviderBuilder = Callable[[Mapping[str, str] | None], AuthProvider]


def _build_ad(environ: Mapping[str, str] | None) -> AuthProvider:
    """Build the Active Directory provider from its own configuration loader."""
    return build_ad_provider(load_ad_config(environ))


#: The only way a provider comes into existence. A name missing here cannot be built.
_BUILDERS: dict[str, ProviderBuilder] = {
    AUTH_SOURCE_AD: _build_ad,
}

#: Backends this build can construct. RADIUS is a supported Phase 4 provider that is not
#: implemented yet, so it is intentionally absent.
IMPLEMENTED_AUTH_PROVIDERS: tuple[str, ...] = tuple(_BUILDERS)

#: Why a supported provider cannot be built, stated for the operator.
_UNIMPLEMENTED_REASONS: dict[str, str] = {
    AUTH_SOURCE_RADIUS: (
        "radius is a supported Phase 4 authentication provider but is not implemented in "
        "this build (see issue #56)"
    ),
}


def build_auth_provider(
    provider: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> AuthProvider:
    """Construct the configured authentication provider.

    Raises rather than degrading in every failure case:

    * an unrecognised name is a configuration error (``ValueError``);
    * a recognised but unimplemented name fails closed (``ProviderMisconfigured``);
    * a provider whose own configuration is invalid propagates that failure untouched.

    ``environ`` is passed to the provider's configuration loader so tests stay
    independent of the developer's ambient environment.
    """
    selected = validate_auth_provider(provider)

    if selected is None:
        raise ValueError("No authentication provider was selected.")

    builder = _BUILDERS.get(selected)

    if builder is None:
        reason = _UNIMPLEMENTED_REASONS.get(
            selected, f"{selected!r} has no implementation in this build"
        )

        # Deliberately not a fallback: an unimplemented selection stops the application
        # rather than being replaced by something that would authenticate differently.
        raise ProviderMisconfigured(
            f"{reason}. Select one of: {', '.join(IMPLEMENTED_AUTH_PROVIDERS)}. "
            "No fallback provider was used."
        )

    return builder(environ)
