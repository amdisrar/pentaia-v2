"""Versioned schema migrations for the application store.

Migrations are **genuinely transactional**, which is the whole reason the statements are
executed one at a time instead of through :meth:`sqlite3.Connection.executescript`:
``executescript`` issues an implicit ``COMMIT`` before it runs, so anything it executes
can no longer be rolled back as a unit. A migration here therefore runs each statement
with ``execute()`` inside an explicit transaction, and a failure anywhere leaves the
database at its previous version with no partial schema.

Three refusals are deliberate:

* a schema **newer** than this code understands is refused rather than downgraded;
* a failure is reported, never papered over by dropping the database;
* a version row is written only in the same transaction as the statements it describes,
  so the recorded version can never claim work that is not there.
"""

import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from pentaia.appstore.errors import MigrationFailed, SchemaTooNew, StoreUnavailable

logger = logging.getLogger(__name__)

#: Version bookkeeping. Created before any migration runs, and itself idempotent.
SCHEMA_MIGRATIONS_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
)
"""


@dataclass(frozen=True)
class Migration:
    """One schema version, as an ordered list of single statements."""

    version: int
    description: str
    statements: tuple[str, ...]


_MIGRATION_1 = Migration(
    version=1,
    description="application store: sessions, login throttling, accounting",
    statements=(
        """
        CREATE TABLE web_sessions (
            session_key          TEXT PRIMARY KEY,
            label                TEXT NOT NULL UNIQUE,
            user_id              TEXT NOT NULL,
            username             TEXT NOT NULL,
            display_name         TEXT NOT NULL,
            auth_source          TEXT NOT NULL,
            authenticated_at     TEXT NOT NULL,
            created_at           TEXT NOT NULL,
            last_activity_at     TEXT NOT NULL,
            absolute_expires_at  TEXT NOT NULL,
            idle_timeout_seconds INTEGER NOT NULL,
            csrf_token           TEXT NOT NULL
        )
        """,
        "CREATE INDEX web_sessions_user_id ON web_sessions (user_id)",
        """
        CREATE INDEX web_sessions_absolute_expires_at
            ON web_sessions (absolute_expires_at)
        """,
        """
        CREATE TABLE login_throttle (
            scope      TEXT NOT NULL,
            key        TEXT NOT NULL,
            count      INTEGER NOT NULL,
            expires_at TEXT NOT NULL,
            PRIMARY KEY (scope, key)
        )
        """,
        "CREATE INDEX login_throttle_expires_at ON login_throttle (expires_at)",
        """
        CREATE TABLE accounting_events (
            sequence             INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id             TEXT NOT NULL UNIQUE,
            recorded_at          TEXT NOT NULL,
            event_type           TEXT NOT NULL,
            outcome              TEXT NOT NULL,
            user_id              TEXT,
            auth_source          TEXT,
            session_label        TEXT,
            conversation_id      TEXT,
            langgraph_thread_id  TEXT,
            request_id           TEXT,
            duration_ms          INTEGER,
            action_id            TEXT,
            target               TEXT,
            proposal_signature   TEXT,
            requester_user_id    TEXT,
            approver_user_id     TEXT,
            error_type           TEXT,
            canonical_event      TEXT NOT NULL,
            previous_record_hash TEXT NOT NULL,
            record_hash          TEXT NOT NULL
        )
        """,
        """
        CREATE INDEX accounting_events_type_recorded_at
            ON accounting_events (event_type, recorded_at)
        """,
        """
        CREATE INDEX accounting_events_user_recorded_at
            ON accounting_events (user_id, recorded_at)
        """,
        """
        CREATE TABLE accounting_chain_state (
            id           INTEGER PRIMARY KEY CHECK (id = 1),
            head_hash    TEXT NOT NULL,
            record_count INTEGER NOT NULL,
            updated_at   TEXT NOT NULL
        )
        """,
    ),
)

#: Every migration, in ascending version order. Appending is the only supported change;
#: an existing migration is never edited, because its statements are already applied on
#: real databases.
MIGRATIONS: tuple[Migration, ...] = (_MIGRATION_1,)

LATEST_VERSION = MIGRATIONS[-1].version


@contextmanager
def _transaction(connection: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """A small local BEGIN/COMMIT wrapper, independent of any store handle.

    ``BEGIN IMMEDIATE`` takes the write lock up front, so a second initialiser waits
    rather than reading a stale version and racing the first one.
    """
    if connection.in_transaction:
        raise StoreUnavailable(
            "schema migrations manage their own transactions and must not run inside "
            "another transaction."
        )

    connection.execute("BEGIN IMMEDIATE")

    try:
        yield connection
    except BaseException:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            logger.warning("Rolling back a migration did not complete.")

        raise

    connection.execute("COMMIT")


def current_version(connection: sqlite3.Connection) -> int:
    """Return the highest applied schema version, or ``0`` for a fresh database."""
    try:
        row = connection.execute(
            "SELECT MAX(version) AS version FROM schema_migrations"
        ).fetchone()
    except sqlite3.OperationalError:
        # The version table does not exist yet: a brand new database file.
        return 0

    if row is None or row[0] is None:
        return 0

    return int(row[0])


def pending_migrations(connection: sqlite3.Connection) -> tuple[Migration, ...]:
    """Migrations that still need to run, without applying them."""
    applied = current_version(connection)

    return tuple(migration for migration in MIGRATIONS if migration.version > applied)


def apply_migrations(connection: sqlite3.Connection) -> int:
    """Bring the schema up to date and return the resulting version.

    Idempotent: running it twice performs no work the second time. Safe against a
    concurrent initialiser: the version is re-read inside each migration's transaction,
    so whichever process loses the race finds the work already done and skips it.
    """
    try:
        with _transaction(connection):
            connection.execute(SCHEMA_MIGRATIONS_SQL)
    except sqlite3.Error as exc:
        raise StoreUnavailable(
            "the application store schema could not be initialised."
        ) from exc

    applied = current_version(connection)

    if applied > LATEST_VERSION:
        raise SchemaTooNew(
            f"the application database is at schema version {applied} but this build "
            f"understands up to {LATEST_VERSION}. Refusing to use it."
        )

    for migration in MIGRATIONS:
        if migration.version <= applied:
            continue

        try:
            with _transaction(connection):
                # Re-read under the write lock: another process may have applied this
                # migration while this one waited for the lock.
                if current_version(connection) >= migration.version:
                    continue

                for statement in migration.statements:
                    connection.execute(statement)

                connection.execute(
                    "INSERT INTO schema_migrations (version, description) VALUES (?, ?)",
                    (migration.version, migration.description),
                )
        except sqlite3.Error as exc:
            raise MigrationFailed(
                f"schema migration {migration.version} failed and was rolled back; the "
                f"database is still at version {current_version(connection)}."
            ) from exc

        logger.info(
            "Applied application store migration version=%s description=%s",
            migration.version,
            migration.description,
        )

    return current_version(connection)
