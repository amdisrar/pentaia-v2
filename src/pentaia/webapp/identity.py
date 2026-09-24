"""Application-owned authenticated identity for Phase 4.

This is the identity contract that the Phase 4 authentication providers will produce.
It is deliberately independent of any provider: an AD/LDAPS bind (P4-05) and a RADIUS
access-request (P4-06) both normalise to one of these objects, and nothing downstream
needs to know which provider authenticated the request.

The identity key is provider-scoped, as the architecture fixes it:

    user_id = "<auth_source>:<normalized_username>"

Scoping by provider keeps identities from colliding across providers (an AD
``user@example.com`` is not the same principal as a RADIUS ``user@example.com``), and
deriving the key from the normalised username means no directory read right is needed
just to name a user. A later phase may migrate to a rename-stable provider identifier
such as an AD ``objectGUID`` if that becomes worth the extra directory lookup.

No credential material belongs here. The identity carries what later components need
to attribute an action, and nothing that could be replayed.
"""

import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

#: Provider keys Phase 4 ships. These are the values the provider-selection setting
#: (P4-07) will accept. They are declared for reuse rather than enforced here, so that
#: adding a provider is a configuration decision and not a change to this model.
AUTH_SOURCE_AD = "ad"
AUTH_SOURCE_RADIUS = "radius"

#: A provider key is a short lower-case token. The shape is validated rather than
#: membership, so a new provider name cannot be blocked by this module.
_AUTH_SOURCE_PATTERN = re.compile(r"^[a-z][a-z0-9_-]*$")
MAX_AUTH_SOURCE_LENGTH = 32

#: The user-id key is ``"<auth_source>:<normalized_username>"``, so a colon inside a
#: username would make the key ambiguous. Whitespace and control characters are
#: rejected as well: they would let a crafted username forge log lines or split a key.
_FORBIDDEN_USERNAME_CHARACTERS = re.compile(r"[\s:\x00-\x1f\x7f]")
MAX_USERNAME_LENGTH = 256

MAX_DISPLAY_NAME_LENGTH = 256


def validate_auth_source(value: object) -> str:
    """Validate and normalize one authentication-provider key."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("auth_source must be a non-empty provider name.")

    candidate = value.strip().lower()

    if len(candidate) > MAX_AUTH_SOURCE_LENGTH or not _AUTH_SOURCE_PATTERN.match(candidate):
        raise ValueError(
            "auth_source must be a short lower-case provider token, for example "
            f"'{AUTH_SOURCE_AD}' or '{AUTH_SOURCE_RADIUS}'."
        )

    return candidate


def normalize_username(value: object) -> str:
    """Validate and normalize one provider username.

    Normalization is lower-casing plus trimming surrounding whitespace, which is the
    whole of what the architecture requires. Anything that would make the identity key
    ambiguous or unloggable is refused instead of silently rewritten.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("username must be a non-empty string.")

    candidate = value.strip().lower()

    if len(candidate) > MAX_USERNAME_LENGTH:
        raise ValueError(f"username must be at most {MAX_USERNAME_LENGTH} characters.")

    if _FORBIDDEN_USERNAME_CHARACTERS.search(candidate):
        raise ValueError("username must not contain whitespace, control characters or ':'.")

    return candidate


def build_user_id(*, auth_source: str, username: str) -> str:
    """Build the canonical provider-scoped identity key."""
    return f"{validate_auth_source(auth_source)}:{normalize_username(username)}"


def _as_utc(value: object, *, field: str) -> datetime:
    """Accept only an unambiguous, timezone-aware timestamp and store it as UTC.

    A wrong type is a programming error and raises ``TypeError``; a naive timestamp is
    bad input and raises ``ValueError``. The public validators in this module keep
    raising ``ValueError`` for both, matching the existing configuration validators in
    ``pentaia.runtime_config``.
    """
    if not isinstance(value, datetime):
        raise TypeError(f"{field} must be a datetime.")

    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field} must be timezone-aware.")

    return value.astimezone(UTC)


@dataclass(frozen=True)
class AuthenticatedIdentity:
    """One authenticated principal, owned by the application rather than a provider.

    Construct this through :meth:`from_provider`. Direct construction is checked
    anyway: ``user_id`` must equal the canonical key for the given provider and
    username, so an inconsistent identity cannot exist even by accident.
    """

    user_id: str
    username: str
    display_name: str
    auth_source: str
    authenticated_at: datetime

    def __post_init__(self) -> None:
        auth_source = validate_auth_source(self.auth_source)
        username = normalize_username(self.username)

        if auth_source != self.auth_source:
            raise ValueError("auth_source must already be normalized.")

        if username != self.username:
            raise ValueError("username must already be normalized.")

        expected = build_user_id(auth_source=auth_source, username=username)

        if self.user_id != expected:
            raise ValueError(f"user_id must be '{expected}'.")

        if not isinstance(self.display_name, str) or not self.display_name.strip():
            raise ValueError("display_name must be a non-empty string.")

        if len(self.display_name) > MAX_DISPLAY_NAME_LENGTH:
            raise ValueError(
                f"display_name must be at most {MAX_DISPLAY_NAME_LENGTH} characters."
            )

        object.__setattr__(
            self,
            "authenticated_at",
            _as_utc(self.authenticated_at, field="authenticated_at"),
        )

    @classmethod
    def from_provider(
        cls,
        *,
        auth_source: object,
        username: object,
        display_name: object | None = None,
        authenticated_at: datetime | None = None,
    ) -> "AuthenticatedIdentity":
        """Build a normalized identity from a provider's successful authentication.

        ``display_name`` falls back to the normalized username when the provider has
        no better label, so every identity has something safe to show. The password,
        token or assertion that proved the identity is never passed here and has no
        field to be stored in.
        """
        source = validate_auth_source(auth_source)
        normalized_username = normalize_username(username)

        if display_name is None or (isinstance(display_name, str) and not display_name.strip()):
            resolved_display_name = normalized_username
        elif isinstance(display_name, str):
            resolved_display_name = display_name.strip()
        else:
            raise ValueError("display_name must be a string when provided.")

        return cls(
            user_id=build_user_id(auth_source=source, username=normalized_username),
            username=normalized_username,
            display_name=resolved_display_name,
            auth_source=source,
            authenticated_at=authenticated_at or datetime.now(UTC),
        )
