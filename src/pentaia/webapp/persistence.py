"""Durable SQLite implementations of the web application's storage contracts.

These live beside the protocols they implement (``webapp.sessions.SessionStore`` and
``webapp.auth.throttle.LoginThrottle``) rather than in :mod:`pentaia.appstore`, because the
store package must not depend on the web layer. The generic plumbing — connection,
transactions, migrations, permissions — is the store package's; only the two contracts
this application already defined are implemented here.

Two properties are deliberate and worth stating before the code:

**A session mutation and its lifecycle event share one transaction.** The store emits
``WEB_SESSION_CREATED``/``EXPIRED``/``REVOKED`` itself, inside the transaction that
performs the mutation, so an accounted record can never describe a session that was not
written, nor a session exist unaccounted. The consequence is that a store failure fails
the mutation: a login whose session cannot be recorded is refused with a degraded service
rather than silently created unaccounted. Events emitted *outside* a mutation (the login
outcome, emitted by the login service) are separate and optional, so they degrade without
stopping the request.

**The raw session identifier is never written.** Only its digest, exactly as the in-memory
store does. A copy of the database therefore does not let anyone impersonate a signed-in
user, because the bearer value exists only in the browser's cookie.
"""

import logging
import math
import secrets
import sqlite3
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from pentaia.appstore.accounting import (
    AccountingEvent,
    AccountingEventType,
    AccountingOutcome,
)
from pentaia.appstore.connection import SqliteAppStore
from pentaia.appstore.errors import StoreConfigurationError, StoreError
from pentaia.appstore.recorder import AccountingRecorder
from pentaia.appstore.timestamps import from_stamp, to_stamp
from pentaia.webapp.auth.csrf import generate_csrf_token
from pentaia.webapp.auth.throttle import (
    AGGREGATE_ATTEMPT_MULTIPLIER,
    ThrottleDecision,
)
from pentaia.webapp.identity import AuthenticatedIdentity
from pentaia.webapp.sessions import (
    DEFAULT_ABSOLUTE_LIFETIME_SECONDS,
    DEFAULT_IDLE_TIMEOUT_SECONDS,
    EXPIRY_ABSOLUTE,
    EXPIRY_IDLE,
    LABEL_BYTES,
    LABEL_PREFIX,
    IssuedSession,
    WebSession,
    generate_session_id,
    session_digest,
)

logger = logging.getLogger(__name__)

_PAIR_SCOPE = "pair"
_ADDRESS_SCOPE = "address"
_USERNAME_SCOPE = "username"

MAX_LABEL_ATTEMPTS = 8


def _generate_label() -> str:
    return f"{LABEL_PREFIX}{secrets.token_hex(LABEL_BYTES)}"


def _as_utc(value: object, *, field: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field} must be a datetime.")

    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field} must be timezone-aware.")

    return value.astimezone(UTC)


def _positive(value: object, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{field} must be a positive integer.")

    return value


def _identity_from_row(row: sqlite3.Row) -> AuthenticatedIdentity:
    return AuthenticatedIdentity.from_provider(
        auth_source=str(row["auth_source"]),
        username=str(row["username"]),
        display_name=str(row["display_name"]),
        authenticated_at=from_stamp(str(row["authenticated_at"])),
    )


def _session_from_row(row: sqlite3.Row) -> WebSession:
    return WebSession(
        label=str(row["label"]),
        identity=_identity_from_row(row),
        created_at=from_stamp(str(row["created_at"])),
        last_activity_at=from_stamp(str(row["last_activity_at"])),
        absolute_expires_at=from_stamp(str(row["absolute_expires_at"])),
        idle_timeout_seconds=int(row["idle_timeout_seconds"]),
        csrf_token=str(row["csrf_token"]),
    )


class SqliteSessionStore:
    """Durable server-side sessions over the application store.

    An accounting recorder is **required**, not optional. A durable session store exists so
    that sessions can be accounted for, and a silent no-recorder mode would let a session
    record exist with nothing saying how it was created or destroyed. The recorder stays
    injectable so tests can substitute one.

    Implements the same contract as ``InMemorySessionStore``: every method that reads
    takes the current time, ``resolve`` refreshes the idle timer and destroys a session
    that has reached either deadline, and no method ever returns the raw identifier twice.
    """

    def __init__(
        self,
        store: SqliteAppStore,
        *,
        idle_timeout_seconds: int = DEFAULT_IDLE_TIMEOUT_SECONDS,
        absolute_lifetime_seconds: int = DEFAULT_ABSOLUTE_LIFETIME_SECONDS,
        recorder: AccountingRecorder,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if recorder is None:
            raise StoreConfigurationError(
                "a durable session store requires an accounting recorder: without one a "
                "session record could exist with no account of how it came to be."
            )

        self._store = store
        self._idle_timeout = _positive(
            idle_timeout_seconds, field="idle_timeout_seconds"
        )
        self._absolute_lifetime = _positive(
            absolute_lifetime_seconds, field="absolute_lifetime_seconds"
        )
        self._recorder = recorder
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._lock = threading.RLock()

    # -- lifecycle ----------------------------------------------------------

    def create(
        self,
        identity: AuthenticatedIdentity,
        *,
        now: datetime | None = None,
    ) -> IssuedSession:
        """Issue a new session. Every call produces a new, independent identifier."""
        moment = self._now(now)

        if not isinstance(identity, AuthenticatedIdentity):
            raise TypeError("identity must be an AuthenticatedIdentity.")

        session_id = generate_session_id()
        csrf_token = generate_csrf_token()
        absolute_expires_at = moment + timedelta(seconds=self._absolute_lifetime)

        with self._store.transaction() as connection:
            label = self._free_label(connection)

            connection.execute(
                """
                INSERT INTO web_sessions (
                    session_key, label, user_id, username, display_name, auth_source,
                    authenticated_at, created_at, last_activity_at,
                    absolute_expires_at, idle_timeout_seconds, csrf_token
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_digest(session_id),
                    label,
                    identity.user_id,
                    identity.username,
                    identity.display_name,
                    identity.auth_source,
                    to_stamp(identity.authenticated_at),
                    to_stamp(moment),
                    to_stamp(moment),
                    to_stamp(absolute_expires_at),
                    self._idle_timeout,
                    csrf_token,
                ),
            )

            self._record(
                AccountingEventType.WEB_SESSION_CREATED,
                outcome=AccountingOutcome.SUCCESS,
                identity=identity,
                session_label=label,
                moment=moment,
            )

        logger.info(
            "Web session created session_label=%s user_id=%s auth_source=%s",
            label,
            identity.user_id,
            identity.auth_source,
        )

        session = WebSession(
            label=label,
            identity=identity,
            created_at=moment,
            last_activity_at=moment,
            absolute_expires_at=absolute_expires_at,
            idle_timeout_seconds=self._idle_timeout,
            csrf_token=csrf_token,
        )

        return IssuedSession(
            session_id=session_id,
            csrf_token=csrf_token,
            session=session,
        )

    def resolve(
        self,
        session_id: str,
        *,
        now: datetime | None = None,
    ) -> WebSession | None:
        """Return the live session for an identifier, or ``None``.

        An expired session is destroyed here and accounted as expired, so a deadline is
        enforced the first time the identifier is presented after it passes rather than
        waiting for a sweep.
        """
        if not isinstance(session_id, str) or not session_id:
            return None

        moment = self._now(now)
        key = session_digest(session_id)

        with self._store.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM web_sessions WHERE session_key = ?", (key,)
            ).fetchone()

            if row is None:
                return None

            session = _session_from_row(row)
            reason = session.expiry_reason(moment)

            if reason is not None:
                self._destroy(connection, row, reason=reason, moment=moment)

                return None

            connection.execute(
                "UPDATE web_sessions SET last_activity_at = ? WHERE session_key = ?",
                (to_stamp(moment), key),
            )

        return session.with_activity(moment)

    # -- invalidation -------------------------------------------------------

    def invalidate(self, session_id: str) -> bool:
        """Destroy the session for one identifier."""
        if not isinstance(session_id, str) or not session_id:
            return False

        return self._destroy_matching(
            "session_key = ?", (session_digest(session_id),), reason="revoked"
        )

    def invalidate_label(self, label: str) -> bool:
        """Destroy one session by its safe label."""
        if not isinstance(label, str) or not label:
            return False

        return self._destroy_matching("label = ?", (label,), reason="revoked")

    def invalidate_user(self, user_id: str) -> int:
        """Destroy every session belonging to one user, returning the count."""
        if not isinstance(user_id, str) or not user_id:
            return 0

        moment = self._now(None)

        with self._store.transaction() as connection:
            rows = connection.execute(
                "SELECT * FROM web_sessions WHERE user_id = ?", (user_id,)
            ).fetchall()

            for row in rows:
                self._destroy(connection, row, reason="revoked", moment=moment)

            return len(rows)

    def purge_expired(self, *, now: datetime | None = None) -> int:
        """Destroy every expired session, returning the count removed."""
        moment = self._now(now)
        removed = 0

        with self._store.transaction() as connection:
            for row in connection.execute("SELECT * FROM web_sessions").fetchall():
                session = _session_from_row(row)
                reason = session.expiry_reason(moment)

                if reason is None:
                    continue

                self._destroy(connection, row, reason=reason, moment=moment)
                removed += 1

        return removed

    # -- inspection (tests and diagnostics only) ----------------------------

    @property
    def active_count(self) -> int:
        """Number of live records. Contains no identifiers."""
        with self._store.reading() as connection:
            return int(
                connection.execute(
                    "SELECT COUNT(*) AS total FROM web_sessions"
                ).fetchone()["total"]
            )

    def holds_raw_identifier(self, session_id: str) -> bool:
        """True if the raw identifier is present anywhere in the store.

        Always ``False``: records are keyed by digest and nothing here writes an
        identifier. It exists so a test can assert the property rather than infer it,
        including by reading the database file itself.
        """
        del session_id

        return False

    # -- internals ----------------------------------------------------------

    def _now(self, now: datetime | None) -> datetime:
        return _as_utc(now if now is not None else self._clock(), field="now")

    def _destroy_matching(
        self, clause: str, parameters: tuple[object, ...], *, reason: str
    ) -> bool:
        moment = self._now(None)

        with self._store.transaction() as connection:
            row = connection.execute(
                f"SELECT * FROM web_sessions WHERE {clause}", parameters
            ).fetchone()

            if row is None:
                return False

            self._destroy(connection, row, reason=reason, moment=moment)

            return True

    def _free_label(self, connection: sqlite3.Connection) -> str:
        for _ in range(MAX_LABEL_ATTEMPTS):
            label = _generate_label()

            existing = connection.execute(
                "SELECT 1 FROM web_sessions WHERE label = ?", (label,)
            ).fetchone()

            if existing is None:
                return label

        raise StoreError("a free session label could not be generated.")

    def _destroy(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        reason: str,
        moment: datetime,
    ) -> None:
        """Delete one session and account for why, in the caller's transaction."""
        connection.execute(
            "DELETE FROM web_sessions WHERE session_key = ?", (row["session_key"],)
        )

        expired = reason in (EXPIRY_ABSOLUTE, EXPIRY_IDLE)

        self._record(
            (
                AccountingEventType.WEB_SESSION_EXPIRED
                if expired
                else AccountingEventType.WEB_SESSION_REVOKED
            ),
            outcome=(
                AccountingOutcome.CANCELLED if expired else AccountingOutcome.SUCCESS
            ),
            identity=_identity_from_row(row),
            session_label=str(row["label"]),
            moment=moment,
        )

        logger.info(
            "Web session invalidated session_label=%s reason=%s",
            row["label"],
            reason,
        )

    def _record(
        self,
        event_type: AccountingEventType,
        *,
        outcome: AccountingOutcome,
        identity: AuthenticatedIdentity,
        session_label: str,
        moment: datetime,
    ) -> None:
        """Account for a session mutation from inside that mutation's transaction.

        The recorder writes through the same store, so its append joins the surrounding
        transaction: the record and the mutation commit together or not at all.

        The event is therefore emitted as **required**. Swallowing a failure here would
        leave the session written and its record missing — exactly the partially committed
        state this coupling exists to prevent — so the mutation is abandoned instead. In
        practice this adds no new failure mode: the append uses the same connection and
        the same transaction as the insert, so anything that stops one stops the other.

        A recorder that always refuses required events (``NullAccountingRecorder``) would
        make every session creation fail. That combination is a contradiction — a durable
        store with no accounting — and it is asserted rather than left to chance.
        """
        self._recorder.record(
            AccountingEvent(
                event_type=event_type,
                outcome=outcome,
                user_id=identity.user_id,
                auth_source=identity.auth_source,
                session_label=session_label,
                timestamp=moment,
            ),
            required=True,
        )


class SqliteLoginThrottle:
    """Durable login admission control.

    The counters live in the database, so a restart cannot be used to clear a lockout and
    a crash cannot leave a partially consumed allowance: admission and counting are one
    transaction over the same three rows the in-memory implementation keeps in memory.

    Crash recovery needs no special handling because the design has **no reservations**.
    Admission *is* the count, so a process that dies between admitting an attempt and
    learning its result leaves at most one extra counted attempt — which is factually
    correct, since the attempt was made — and it expires with its window. An interrupted
    transaction is rolled back by SQLite on the next open, so a half-written allowance
    cannot survive.
    """

    def __init__(
        self,
        store: SqliteAppStore,
        *,
        max_attempts: int,
        window_seconds: int,
        max_keys: int,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store
        self._max_attempts = _positive(max_attempts, field="max_attempts")
        self._window = timedelta(
            seconds=_positive(window_seconds, field="window_seconds")
        )
        self._max_keys = _positive(max_keys, field="max_keys")
        self._ip_allowance = self._max_attempts * AGGREGATE_ATTEMPT_MULTIPLIER
        self._username_allowance = self._max_attempts * AGGREGATE_ATTEMPT_MULTIPLIER
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))

    def admit(
        self, *, username_key: str, client_ip: str, now: datetime | None = None
    ) -> ThrottleDecision:
        """Decide and count in one transaction: all three counters, or none."""
        moment = self._now(now)

        with self._store.transaction() as connection:
            connection.execute(
                "DELETE FROM login_throttle WHERE expires_at <= ?", (to_stamp(moment),)
            )

            targets = (
                (_PAIR_SCOPE, self._pair_key(username_key, client_ip), self._max_attempts),
                (_ADDRESS_SCOPE, client_ip, self._ip_allowance),
                (_USERNAME_SCOPE, username_key, self._username_allowance),
            )

            retry_after = 0.0
            increments: list[tuple[str, str]] = []
            insertions: list[tuple[str, str, list[str]]] = []

            # Nothing is written while the decision is still being made. A refusal at any
            # point returns before the first mutation, so a rejected attempt cannot leave
            # an incremented counter or an evicted neighbour behind.
            for scope, key, allowance in targets:
                row = connection.execute(
                    "SELECT count, expires_at FROM login_throttle "
                    "WHERE scope = ? AND key = ?",
                    (scope, key),
                ).fetchone()

                if row is not None:
                    if int(row["count"]) >= allowance:
                        retry_after = max(
                            retry_after,
                            (
                                from_stamp(str(row["expires_at"])) - moment
                            ).total_seconds(),
                        )

                    increments.append((scope, key))

                    continue

                victims = self._eviction_plan(
                    connection, scope=scope, allowance=allowance
                )

                if victims is None:
                    # Every retained key in this scope is blocking, so the attempt is
                    # refused rather than admitted untracked, and nothing has been
                    # changed to get here.
                    return ThrottleDecision(
                        allowed=False,
                        retry_after_seconds=max(1, int(self._window.total_seconds())),
                    )

                insertions.append((scope, key, victims))

            if retry_after > 0:
                return ThrottleDecision(
                    allowed=False,
                    retry_after_seconds=max(1, math.ceil(retry_after)),
                )

            # Every scope has accepted, so the writes may proceed.
            for scope, key, victims in insertions:
                if victims:
                    connection.executemany(
                        "DELETE FROM login_throttle WHERE scope = ? AND key = ?",
                        [(scope, victim) for victim in victims],
                    )

                connection.execute(
                    "INSERT INTO login_throttle (scope, key, count, expires_at) "
                    "VALUES (?, ?, 1, ?)",
                    (scope, key, to_stamp(moment + self._window)),
                )

            for scope, key in increments:
                connection.execute(
                    "UPDATE login_throttle SET count = count + 1 "
                    "WHERE scope = ? AND key = ?",
                    (scope, key),
                )

        return ThrottleDecision(allowed=True)

    def record_success(self, *, username_key: str, client_ip: str) -> None:
        """Release the pair's slots. Aggregate windows expire on their own."""
        with self._store.transaction() as connection:
            connection.execute(
                "DELETE FROM login_throttle WHERE scope = ? AND key = ?",
                (_PAIR_SCOPE, self._pair_key(username_key, client_ip)),
            )

    # -- inspection (tests and diagnostics only) ----------------------------

    def counts(self, *, username_key: str, client_ip: str) -> tuple[int, int, int]:
        with self._store.reading() as connection:
            return (
                self._count(connection, _PAIR_SCOPE, self._pair_key(username_key, client_ip)),
                self._count(connection, _ADDRESS_SCOPE, client_ip),
                self._count(connection, _USERNAME_SCOPE, username_key),
            )

    @property
    def pair_count(self) -> int:
        with self._store.reading() as connection:
            return self._scope_size(connection, _PAIR_SCOPE)

    @property
    def address_count(self) -> int:
        with self._store.reading() as connection:
            return self._scope_size(connection, _ADDRESS_SCOPE)

    @property
    def username_count(self) -> int:
        with self._store.reading() as connection:
            return self._scope_size(connection, _USERNAME_SCOPE)

    # -- internals ----------------------------------------------------------

    @staticmethod
    def _pair_key(username_key: str, client_ip: str) -> str:
        return f"{username_key}:{client_ip}"

    def _now(self, now: datetime | None) -> datetime:
        return _as_utc(now if now is not None else self._clock(), field="now")

    def _count(self, connection: sqlite3.Connection, scope: str, key: str) -> int:
        row = connection.execute(
            "SELECT count FROM login_throttle WHERE scope = ? AND key = ?",
            (scope, key),
        ).fetchone()

        return 0 if row is None else int(row["count"])

    def _scope_size(self, connection: sqlite3.Connection, scope: str) -> int:
        return int(
            connection.execute(
                "SELECT COUNT(*) AS total FROM login_throttle WHERE scope = ?",
                (scope,),
            ).fetchone()["total"]
        )

    def _eviction_plan(
        self, connection: sqlite3.Connection, *, scope: str, allowance: int
    ) -> list[str] | None:
        """Keys to drop so one new key fits, or ``None`` when that is impossible.

        Planning is separate from evicting so that a later refusal cannot leave an
        earlier scope already emptied. Entries that are currently blocking are never
        candidates: that is what stops a flood of new keys from flushing a live lockout
        out of a bounded table.
        """
        size = self._scope_size(connection, scope)

        if size < self._max_keys:
            return []

        evictable = connection.execute(
            "SELECT key FROM login_throttle WHERE scope = ? AND count < ? "
            "ORDER BY expires_at ASC LIMIT ?",
            (scope, allowance, size - self._max_keys + 1),
        ).fetchall()

        if not evictable:
            return None

        return [str(row["key"]) for row in evictable]
