"""Server-side web sessions for Phase 4.

The browser holds an opaque identifier in a cookie. The authoritative record lives
server-side, and the browser is never a bearer of identity: a request's identity is
whatever the session record says, or nothing.

Design notes that matter for review:

* **256-bit identifiers.** :func:`generate_session_id` draws 32 bytes from
  ``secrets`` and encodes them URL-safe. The identifier is a bearer credential, so it
  is treated like one.
* **The store never holds the raw identifier.** Records are keyed by a SHA-256 digest
  of the identifier. A memory dump, a debug ``repr`` or a future durable store leak
  therefore does not hand over a usable session. Lookups hash the presented value.
* **A separate safe label.** Each session carries a random ``sess-…`` label that is
  independent of the identifier and safe to log and account against. Correlation uses
  the label; the raw identifier is never logged.
* **In-memory storage is deliberate for P4-04.** The interface below is the seam P4-09
  replaces with a durable repository. Sessions do not survive a restart and are not
  shared between processes, which is the known limitation this abstraction exists to
  remove.
* **Session fixation.** An identifier is issued only by :meth:`SessionStore.create`,
  which always generates a fresh 256-bit value, so an authenticated session can never
  inherit an identifier a client chose or already knows. Because this build has no
  pre-authentication session at all, there is nothing to carry over at login; P4-08
  wires the cookie-side handling for the login flow itself.

Timeouts follow the architecture defaults, idle 30 minutes and absolute 12 hours.
They are constructor arguments rather than environment configuration because P4-08
owns making them configurable and validated.
"""

import hashlib
import logging
import secrets
import threading
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol, TypedDict

from pentaia.webapp.identity import AuthenticatedIdentity

logger = logging.getLogger(__name__)

#: 32 bytes = 256 bits of entropy per session identifier.
SESSION_ID_BYTES = 32

#: Cookie carrying the opaque session identifier. Named after the application, not
#: the stack, so the cookie does not advertise the framework.
SESSION_COOKIE_NAME = "pentaia_session"
SESSION_COOKIE_PATH = "/"

DEFAULT_IDLE_TIMEOUT_SECONDS = 30 * 60
DEFAULT_ABSOLUTE_LIFETIME_SECONDS = 12 * 60 * 60

#: Session labels are 64 bits of randomness, independent of the session identifier.
LABEL_BYTES = 8
LABEL_PREFIX = "sess-"

EXPIRY_IDLE = "idle"
EXPIRY_ABSOLUTE = "absolute"


def generate_session_id() -> str:
    """Return a fresh 256-bit session identifier, URL-safe encoded."""
    return secrets.token_urlsafe(SESSION_ID_BYTES)


def _digest(session_id: str) -> str:
    """Key material for the store: the raw identifier is never stored."""
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def _generate_label() -> str:
    return f"{LABEL_PREFIX}{secrets.token_hex(LABEL_BYTES)}"


def _as_utc(value: object, *, field: str) -> datetime:
    """Coerce one timestamp, rejecting anything ambiguous.

    Wrong type raises ``TypeError`` (a programming error); a naive timestamp raises
    ``ValueError`` (bad input).
    """
    if not isinstance(value, datetime):
        raise TypeError(f"{field} must be a datetime.")

    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field} must be timezone-aware.")

    return value.astimezone(UTC)


def _positive_seconds(value: object, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{field} must be a positive number of seconds.")

    return value


@dataclass(frozen=True)
class WebSession:
    """The authoritative server-side session record.

    Contains no credential material and, by construction, no session identifier: the
    identifier is returned exactly once by :meth:`SessionStore.create` and the store
    keeps only its digest. ``label`` is the value to log or account against.
    """

    label: str
    identity: AuthenticatedIdentity
    created_at: datetime
    last_activity_at: datetime
    absolute_expires_at: datetime
    idle_timeout_seconds: int

    def __post_init__(self) -> None:
        if not isinstance(self.label, str) or not self.label.startswith(LABEL_PREFIX):
            raise ValueError(f"label must start with '{LABEL_PREFIX}'.")

        object.__setattr__(self, "created_at", _as_utc(self.created_at, field="created_at"))
        object.__setattr__(
            self,
            "last_activity_at",
            _as_utc(self.last_activity_at, field="last_activity_at"),
        )
        object.__setattr__(
            self,
            "absolute_expires_at",
            _as_utc(self.absolute_expires_at, field="absolute_expires_at"),
        )
        object.__setattr__(
            self,
            "idle_timeout_seconds",
            _positive_seconds(self.idle_timeout_seconds, field="idle_timeout_seconds"),
        )

    @property
    def auth_source(self) -> str:
        """The provider that authenticated this session."""
        return self.identity.auth_source

    def idle_expires_at(self) -> datetime:
        """When the idle timer would expire if nothing else happened."""
        return self.last_activity_at + timedelta(seconds=self.idle_timeout_seconds)

    def expiry_reason(self, now: datetime) -> str | None:
        """Why the session is no longer valid, or ``None`` while it is valid.

        The absolute lifetime is checked first: activity may refresh the idle timer but
        must never extend the absolute lifetime, so a session that has reached its
        absolute expiry is expired even if it was active a moment ago.
        """
        moment = _as_utc(now, field="now")

        if moment >= self.absolute_expires_at:
            return EXPIRY_ABSOLUTE

        if moment >= self.idle_expires_at():
            return EXPIRY_IDLE

        return None

    def is_expired(self, now: datetime) -> bool:
        return self.expiry_reason(now) is not None

    def with_activity(self, now: datetime) -> "WebSession":
        """Record activity, refreshing the idle timer only."""
        return replace(self, last_activity_at=_as_utc(now, field="now"))


@dataclass(frozen=True)
class IssuedSession:
    """A newly created session together with its identifier.

    The identifier exists only in this object, which is returned exactly once per
    session. Logging, storing or placing an ``IssuedSession`` into graph state would
    leak a live credential, so ``__repr__`` redacts it.
    """

    session_id: str
    session: WebSession

    def __repr__(self) -> str:
        return f"IssuedSession(label={self.session.label!r}, session_id=<redacted>)"

    __str__ = __repr__


class SessionStore(Protocol):
    """Server-side session storage.

    The interface is the seam P4-09 replaces with a durable repository. Every method
    that reads takes the current time, so expiry behaviour is deterministic in tests.
    """

    def create(self, identity: AuthenticatedIdentity, *, now: datetime | None = None) -> IssuedSession:
        """Create a new independent session for an identity."""
        ...

    def resolve(self, session_id: str, *, now: datetime | None = None) -> WebSession | None:
        """Return the live session for an identifier, refreshing its idle timer."""
        ...

    def invalidate(self, session_id: str) -> bool:
        """Destroy one session by its identifier."""
        ...

    def invalidate_label(self, label: str) -> bool:
        """Destroy one session by its safe label."""
        ...

    def invalidate_user(self, user_id: str) -> int:
        """Destroy every session belonging to one user."""
        ...

    def purge_expired(self, *, now: datetime | None = None) -> int:
        """Destroy every expired session and report how many were removed."""
        ...


class InMemorySessionStore:
    """Process-local session storage.

    Adequate for a single-process Phase 4 application and for tests, and deliberately
    the smallest implementation that exercises the real lifecycle. Sessions do not
    survive a restart and are not shared between workers; P4-09 moves this behind the
    same interface onto durable storage.

    A lock guards the dictionaries because FastAPI may run synchronous dependencies in
    a worker thread, so two requests can reach the store concurrently.
    """

    def __init__(
        self,
        *,
        idle_timeout_seconds: int = DEFAULT_IDLE_TIMEOUT_SECONDS,
        absolute_lifetime_seconds: int = DEFAULT_ABSOLUTE_LIFETIME_SECONDS,
    ) -> None:
        self._idle_timeout_seconds = _positive_seconds(
            idle_timeout_seconds, field="idle_timeout_seconds"
        )
        self._absolute_lifetime_seconds = _positive_seconds(
            absolute_lifetime_seconds, field="absolute_lifetime_seconds"
        )
        self._records: dict[str, WebSession] = {}
        self._labels: dict[str, str] = {}
        self._lock = threading.Lock()

    # -- lifecycle ----------------------------------------------------------

    def create(
        self,
        identity: AuthenticatedIdentity,
        *,
        now: datetime | None = None,
    ) -> IssuedSession:
        """Issue a new session. Every call produces a new, independent identifier."""
        moment = _as_utc(now or datetime.now(UTC), field="now")

        # A wrong type here is a programming error rather than bad input, so it raises
        # TypeError. Value validation elsewhere in this module raises ValueError.
        if not isinstance(identity, AuthenticatedIdentity):
            raise TypeError("identity must be an AuthenticatedIdentity.")

        session_id = generate_session_id()
        key = _digest(session_id)

        with self._lock:
            label = _generate_label()
            while label in self._labels:
                label = _generate_label()

            session = WebSession(
                label=label,
                identity=identity,
                created_at=moment,
                last_activity_at=moment,
                absolute_expires_at=moment
                + timedelta(seconds=self._absolute_lifetime_seconds),
                idle_timeout_seconds=self._idle_timeout_seconds,
            )

            self._records[key] = session
            self._labels[label] = key

        logger.info(
            "Web session created session_label=%s user_id=%s auth_source=%s",
            session.label,
            identity.user_id,
            identity.auth_source,
        )

        return IssuedSession(session_id=session_id, session=session)

    def resolve(
        self,
        session_id: str,
        *,
        now: datetime | None = None,
    ) -> WebSession | None:
        """Return the live session for an identifier, or ``None``.

        Fails closed for an unknown identifier, and destroys a session that has reached
        either timeout rather than returning it. A live session records the activity.
        """
        if not isinstance(session_id, str) or not session_id:
            return None

        moment = _as_utc(now or datetime.now(UTC), field="now")
        key = _digest(session_id)

        with self._lock:
            session = self._records.get(key)

            if session is None:
                return None

            reason = session.expiry_reason(moment)

            if reason is not None:
                self._discard(key)
                logger.info(
                    "Web session rejected session_label=%s reason=%s",
                    session.label,
                    reason,
                )

                return None

            refreshed = session.with_activity(moment)
            self._records[key] = refreshed

        return refreshed

    # -- invalidation -------------------------------------------------------

    def invalidate(self, session_id: str) -> bool:
        """Destroy the session for one identifier."""
        if not isinstance(session_id, str) or not session_id:
            return False

        with self._lock:
            return self._discard(_digest(session_id))

    def invalidate_label(self, label: str) -> bool:
        """Destroy one session by its safe label."""
        if not isinstance(label, str) or not label:
            return False

        with self._lock:
            key = self._labels.get(label)

            if key is None:
                return False

            return self._discard(key)

    def invalidate_user(self, user_id: str) -> int:
        """Destroy every session belonging to one user, returning the count."""
        if not isinstance(user_id, str) or not user_id:
            return 0

        with self._lock:
            keys = [
                key
                for key, session in self._records.items()
                if session.identity.user_id == user_id
            ]

            for key in keys:
                self._discard(key)

            return len(keys)

    def purge_expired(self, *, now: datetime | None = None) -> int:
        """Destroy every expired session, returning the count removed."""
        moment = _as_utc(now or datetime.now(UTC), field="now")

        with self._lock:
            keys = [
                key
                for key, session in self._records.items()
                if session.is_expired(moment)
            ]

            for key in keys:
                self._discard(key)

            return len(keys)

    # -- internals ----------------------------------------------------------

    def _discard(self, key: str) -> bool:
        session = self._records.pop(key, None)

        if session is None:
            return False

        self._labels.pop(session.label, None)
        logger.info("Web session invalidated session_label=%s", session.label)

        return True

    # -- inspection (tests and diagnostics only) ----------------------------

    @property
    def active_count(self) -> int:
        """Number of live records. Contains no identifiers."""
        with self._lock:
            return len(self._records)

    def holds_raw_identifier(self, session_id: str) -> bool:
        """True if the raw identifier is present anywhere in the store.

        Always ``False`` for this implementation, because records are keyed by digest.
        It exists so a test can assert the property directly rather than by inspection.
        """
        with self._lock:
            if session_id in self._records:
                return True

            return any(
                session_id in (key, session.label, session.identity.user_id)
                for key, session in self._records.items()
            )


class SessionCookieSettings(TypedDict):
    """Cookie attributes for the session identifier."""

    key: str
    httponly: bool
    secure: bool
    samesite: Literal["lax", "strict", "none"]
    path: str


def session_cookie_settings() -> SessionCookieSettings:
    """Cookie attributes for the session identifier.

    The full cookie lifecycle belongs to P4-08; P4-04 fixes the name and the attributes
    the architecture requires so that later work cannot weaken them by accident. The
    cookie carries only the opaque identifier: no identity, no authorization and no
    expiry state, all of which stay server-side.

    ``secure`` is unconditional here. A deployment that terminates TLS at the same-host
    reverse proxy, as the architecture specifies, always serves the cookie over HTTPS.
    """
    return {
        "key": SESSION_COOKIE_NAME,
        "httponly": True,
        "secure": True,
        "samesite": "lax",
        "path": SESSION_COOKIE_PATH,
    }
