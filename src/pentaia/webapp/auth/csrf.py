"""CSRF protection for the browser surface.

Two states need protecting, and the architecture names both (*"per-session CSRF token
on every state-changing browser request"*, and login must not be forceable from another
origin):

* **Before authentication** there is no session to bind a token to. The token is
  therefore *server-bound*: :class:`PreAuthTokenStore` issues a random 256-bit value and
  keeps a digest of it server-side, together with the client address it was issued to, so
  a presented token is only accepted if the server issued it, it has not expired, and it
  is presented by the same client. This is the synchronizer-token pattern rather than
  plain double-submit: nothing depends on the client's ability to hold a cookie, and an
  attacker who cannot read a same-origin response cannot obtain a token at all.

  Binding to the client address is what stops a token that leaks by any other route from
  being replayed by a different client. It is a deliberate, small availability risk: a
  client whose address changes between loading the form and submitting it is refused and
  recovers by asking for a new token, which a reload does. Treating the address as
  part of the token's context, rather than trusting the value alone, is the stronger
  position for the one request that is reachable without a session.
* **After authentication** the authoritative token is the one inside the server-side
  session record. It is compared in constant time against the request header, and it is
  never exposed in a URL, in browser persistent storage, or in a log.

Both checks reject missing, malformed and oversized values *before* any comparison, so a
huge or hostile header cannot make the comparison do unbounded work.

The browser obtains the token from ``GET /api/auth/csrf`` and holds it in memory only.
That call is also how a reloaded page recovers the token: unauthenticated it issues a
fresh pre-authentication token, authenticated it returns the session's own token, which
never changes for the life of the session.
"""

import hashlib
import hmac
import logging
import re
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

logger = logging.getLogger(__name__)

#: Request header carrying the CSRF token. Not a cookie name and not a URL parameter.
CSRF_HEADER_NAME = "X-PentAiA-CSRF"

#: 32 bytes = 256 bits, matching the session identifier.
CSRF_TOKEN_BYTES = 32

#: Longest token accepted at all. Anything longer is refused without comparison.
MAX_CSRF_TOKEN_LENGTH = 512

#: How long an issued pre-authentication token stays usable.
PRE_AUTH_TOKEN_TTL_SECONDS = 15 * 60

#: Upper bound on live pre-authentication tokens, so issuing them cannot exhaust memory.
MAX_PRE_AUTH_TOKENS = 4096

#: ``token_urlsafe`` emits exactly this alphabet.
_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def generate_csrf_token() -> str:
    """Return a fresh 256-bit CSRF token, URL-safe encoded."""
    return secrets.token_urlsafe(CSRF_TOKEN_BYTES)


def token_is_well_formed(value: object) -> bool:
    """True only for a plausible token: right type, bounded length, known alphabet."""
    if not isinstance(value, str):
        return False

    if not value or len(value) > MAX_CSRF_TOKEN_LENGTH:
        return False

    return _TOKEN_PATTERN.match(value) is not None


def tokens_match(expected: object, presented: object) -> bool:
    """Constant-time comparison of a presented token against an expected one.

    Both sides are validated first; a malformed value fails without reaching the
    comparison, so this never raises and never short-circuits on a length difference in
    a way that leaks the expected token's length.
    """
    if not token_is_well_formed(expected) or not token_is_well_formed(presented):
        return False

    return hmac.compare_digest(expected, presented)


def _digest(token: str) -> str:
    """Key material for the pre-authentication store; the raw token is not kept."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _as_utc(value: object, *, field: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field} must be a datetime.")

    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field} must be timezone-aware.")

    return value.astimezone(UTC)


class PreAuthTokenStore(Protocol):
    """Issuance and checking of pre-authentication CSRF tokens.

    A token is only live for the client address it was issued to, so the store's methods
    all take that address. Nothing here trusts a token as a bare bearer value.
    """

    def issue(self, *, client_ip: str, now: datetime | None = None) -> str:
        """Issue a fresh token bound to ``client_ip``. Only the digest is retained."""
        ...

    def is_live(
        self, token: object, *, client_ip: str, now: datetime | None = None
    ) -> bool:
        """True when this client was issued this token and it has not expired."""
        ...

    def consume(
        self, token: object, *, client_ip: str, now: datetime | None = None
    ) -> bool:
        """Invalidate a token, reporting whether it was live for this client."""
        ...


@dataclass(frozen=True)
class _PreAuthRecord:
    """One issued token: when it stops being usable, and who it was issued to."""

    expires_at: datetime
    client_ip: str


class InMemoryPreAuthTokenStore:
    """Process-local pre-authentication tokens.

    Holds digests only, so a dump of this store does not yield a usable token. Each
    record also holds the client address the token was issued to, and a token presented
    from anywhere else is not live: a value that leaks is useless without also coming
    from the same client. Entries expire, and the store is bounded: at the cap the entry
    closest to expiry is dropped, which a legitimate client recovers from automatically
    by asking for another token.

    P4-09 does not need to replace this: nothing here is required to survive a restart,
    because an interrupted login simply starts again.
    """

    def __init__(
        self,
        *,
        ttl_seconds: int = PRE_AUTH_TOKEN_TTL_SECONDS,
        max_tokens: int = MAX_PRE_AUTH_TOKENS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a positive number of seconds.")

        if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens <= 0:
            raise ValueError("max_tokens must be a positive integer.")

        self._ttl = timedelta(seconds=ttl_seconds)
        self._max_tokens = max_tokens
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._tokens: dict[str, _PreAuthRecord] = {}
        self._lock = threading.Lock()

    def issue(self, *, client_ip: str, now: datetime | None = None) -> str:
        moment = self._moment(now)
        token = generate_csrf_token()

        with self._lock:
            self._purge(moment)

            if len(self._tokens) >= self._max_tokens:
                # Bounded by dropping the entry closest to expiry. The client affected
                # recovers by requesting another token, so this cannot lock anyone out.
                oldest = min(
                    self._tokens, key=lambda key: self._tokens[key].expires_at
                )
                self._tokens.pop(oldest, None)

            self._tokens[_digest(token)] = _PreAuthRecord(
                expires_at=moment + self._ttl,
                client_ip=str(client_ip),
            )

        return token

    def is_live(
        self, token: object, *, client_ip: str, now: datetime | None = None
    ) -> bool:
        if not token_is_well_formed(token):
            return False

        moment = self._moment(now)

        with self._lock:
            record = self._tokens.get(_digest(token))

        if record is None or moment >= record.expires_at:
            return False

        # Constant-time comparison here would be theatre: the address is not a secret,
        # and the token lookup above has already narrowed this to one record.
        return record.client_ip == str(client_ip)

    def consume(
        self, token: object, *, client_ip: str, now: datetime | None = None
    ) -> bool:
        if not token_is_well_formed(token):
            return False

        moment = self._moment(now)
        key = _digest(token)

        with self._lock:
            record = self._tokens.get(key)

            if record is None or moment >= record.expires_at:
                return False

            # The address is checked *before* the record is removed, so a client that
            # presents somebody else's token cannot destroy it as a side effect.
            if record.client_ip != str(client_ip):
                return False

            self._tokens.pop(key, None)

        return True

    # -- inspection (tests and diagnostics only) ----------------------------

    @property
    def active_count(self) -> int:
        """Number of live records. Contains no tokens."""
        with self._lock:
            return len(self._tokens)

    # -- internals ----------------------------------------------------------

    def _moment(self, now: datetime | None) -> datetime:
        return _as_utc(now if now is not None else self._clock(), field="now")

    def _purge(self, moment: datetime) -> None:
        for key in [
            key
            for key, record in self._tokens.items()
            if moment >= record.expires_at
        ]:
            self._tokens.pop(key, None)
