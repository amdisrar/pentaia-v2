"""SQLite connection, filesystem protections and the store handle.

One connection per store instance, guarded by one lock, with explicit transaction
control (``isolation_level=None``). Two reasons:

* The initial Phase 4 deployment is a single application process, so serialising access
  through one lock is simple, eliminates a class of lock-ordering bugs, and makes every
  multi-statement operation trivially atomic.
* Explicit transaction control is what lets a session mutation and its accounting event
  share one transaction instead of two commits.

The handle is re-entrant: :meth:`SqliteAppStore.transaction` may be entered again from
inside a transaction it already opened, and the inner use joins it. That is what lets a
caller group work that is normally independent without the individual operations
knowing they are being grouped.

Nothing here recreates, truncates or deletes a database. A database that fails its
integrity check is reported, not repaired: silent repair would destroy the evidence an
audit trail exists to preserve.
"""

import logging
import os
import sqlite3
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from pentaia.appstore.config import (
    DATABASE_FILENAME,
    DIRECTORY_MODE,
    FILE_MODE,
    StoreConfig,
)
from pentaia.appstore.errors import StoreUnavailable

logger = logging.getLogger(__name__)

#: Pragmas applied to every connection. ``trusted_schema=OFF`` prevents a crafted schema
#: from running functions during a parse, and ``foreign_keys=ON`` keeps the schema honest.
_PRAGMAS: tuple[str, ...] = (
    "foreign_keys = ON",
    "trusted_schema = OFF",
    "journal_mode = WAL",
    "synchronous = FULL",
)

#: SQLite results that mean "the database file itself is unusable" rather than "this
#: statement failed".
_CORRUPTION_MESSAGES = ("malformed", "not a database", "corrupt", "file is encrypted")


@dataclass(frozen=True)
class StorePaths:
    """Every path the store owns, so permissions can be applied to all of them."""

    directory: Path
    database: Path
    wal: Path
    shm: Path

    @classmethod
    def for_config(cls, config: StoreConfig) -> "StorePaths":
        if config.data_dir is None:
            raise StoreUnavailable("the durable store has no configured data directory.")

        directory = config.data_dir

        return cls(
            directory=directory,
            database=directory / DATABASE_FILENAME,
            wal=directory / f"{DATABASE_FILENAME}-wal",
            shm=directory / f"{DATABASE_FILENAME}-shm",
        )

    def enforce_permissions(self) -> None:
        """Apply owner-only permissions to whichever of these paths exist.

        The WAL and shared-memory sidecars appear only once SQLite starts writing, so
        this is called again after the first write rather than only at creation.
        """
        for path, mode in (
            (self.directory, DIRECTORY_MODE),
            (self.database, FILE_MODE),
            (self.wal, FILE_MODE),
            (self.shm, FILE_MODE),
        ):
            if not path.exists():
                continue

            try:
                current = stat.S_IMODE(path.stat().st_mode)

                if current != mode:
                    os.chmod(path, mode)
            except OSError as exc:
                raise StoreUnavailable(
                    f"the application store path could not be secured: {path}"
                ) from exc


def prepare_paths(config: StoreConfig) -> StorePaths:
    """Validate and create the data directory, then fix its permissions.

    Refusals are deliberate and fail closed:

    * a configured path that exists and is not a directory is refused;
    * a path that is a symlink is refused, so the store's location cannot be redirected
      by swapping a link;
    * a directory that is not writable is refused rather than reported later as a
      mysterious SQLite error.
    """
    paths = StorePaths.for_config(config)
    directory = paths.directory

    if directory.is_symlink():
        raise StoreUnavailable(
            "the application store directory must not be a symbolic link."
        )

    if directory.exists() and not directory.is_dir():
        raise StoreUnavailable(
            "the application store path exists and is not a directory."
        )

    if paths.database.is_symlink():
        raise StoreUnavailable(
            "the application database must not be a symbolic link."
        )

    try:
        directory.mkdir(parents=True, exist_ok=True, mode=DIRECTORY_MODE)
    except OSError as exc:
        raise StoreUnavailable(
            "the application store directory could not be created."
        ) from exc

    if not os.access(directory, os.W_OK | os.X_OK):
        raise StoreUnavailable(
            "the application store directory is not writable by this process."
        )

    paths.enforce_permissions()

    return paths


def open_connection(paths: StorePaths, *, busy_timeout_ms: int) -> sqlite3.Connection:
    """Open the database and apply the pragmas, refusing an unusable file.

    ``quick_check`` runs before anything else so corruption is reported at startup with a
    clear message instead of surfacing later as a failed write. The file is never
    removed and never recreated.
    """
    try:
        connection = sqlite3.connect(
            str(paths.database),
            isolation_level=None,
            check_same_thread=False,
            timeout=busy_timeout_ms / 1000,
        )
    except sqlite3.Error as exc:
        raise StoreUnavailable("the application database could not be opened.") from exc

    try:
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")

        for pragma in _PRAGMAS:
            connection.execute(f"PRAGMA {pragma}")

        result = connection.execute("PRAGMA quick_check").fetchone()

        if result is None or result[0] != "ok":
            raise StoreUnavailable(
                "the application database failed its integrity check and will not be "
                "used. Restore it from a WAL-aware backup; it has not been modified."
            )
    except sqlite3.DatabaseError as exc:
        connection.close()

        message = str(exc).lower()

        if any(marker in message for marker in _CORRUPTION_MESSAGES):
            raise StoreUnavailable(
                "the application database is not a usable SQLite database."
            ) from exc

        raise StoreUnavailable("the application database could not be prepared.") from exc
    except StoreUnavailable:
        connection.close()
        raise

    paths.enforce_permissions()

    return connection


class SqliteAppStore:
    """One locked connection, with explicit and re-entrant transactions.

    The handle is shared by every SQLite-backed repository in the process, which is what
    makes it possible to commit a session mutation and its accounting event together.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        paths: StorePaths,
        busy_timeout_ms: int,
    ) -> None:
        self._connection = connection
        self._paths = paths
        self._busy_timeout_ms = busy_timeout_ms
        self._lock = threading.RLock()
        self._depth = 0
        self._closed = False

    # -- lifecycle ----------------------------------------------------------

    @classmethod
    def open(cls, config: StoreConfig) -> "SqliteAppStore":
        """Open (creating if needed) the durable store for one configuration."""
        paths = prepare_paths(config)
        connection = open_connection(paths, busy_timeout_ms=config.busy_timeout_ms)

        return cls(
            connection,
            paths=paths,
            busy_timeout_ms=config.busy_timeout_ms,
        )

    def close(self) -> None:
        """Close the connection.

        Safe to call twice. After closing, every operation fails closed with
        :class:`StoreUnavailable` rather than raising an unrelated SQLite error.
        """
        with self._lock:
            if self._closed:
                return

            try:
                # A checkpoint keeps the main database file complete for a copy taken
                # after shutdown. Failure here is not fatal: WAL recovery will replay it.
                self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                logger.warning("Application store checkpoint at shutdown did not complete.")

            self._connection.close()
            self._closed = True

    def migrate(self) -> int:
        """Bring the schema up to date and return the resulting version.

        Migrations manage their own transactions, so this must not be called from inside
        one. The lock is still held, so a concurrent initialiser in this process waits.
        """
        from pentaia.appstore.migrations import apply_migrations

        with self._lock:
            self._raise_if_closed()
            version = apply_migrations(self._connection)

            # The first write creates the -wal and -shm sidecars, so owner-only
            # permissions are applied now that they exist rather than only at open time.
            self._paths.enforce_permissions()

            return version

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def paths(self) -> StorePaths:
        return self._paths

    # -- transactions -------------------------------------------------------

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run a block inside one transaction, joining an outer one if present.

        The outermost use issues ``BEGIN IMMEDIATE`` so two writers cannot interleave
        their read-then-write decisions, and commits once at the end. Any exception rolls
        the whole unit back, including anything a nested block wrote.
        """
        with self._lock:
            self._raise_if_closed()
            outermost = self._depth == 0

            if outermost:
                try:
                    self._connection.execute("BEGIN IMMEDIATE")
                except sqlite3.Error as exc:
                    raise StoreUnavailable(
                        "the application store is busy or unavailable; the operation was "
                        "not started."
                    ) from exc

            self._depth += 1

            try:
                yield self._connection
            except sqlite3.Error as exc:
                # A statement failed. The whole unit is rolled back and the caller is
                # given a store error: the driver's message can carry SQL, a table name
                # or a path, and none of that may reach a caller or a response body.
                self._depth -= 1

                if outermost:
                    self._rollback_quietly()

                raise StoreUnavailable(
                    "the application store could not complete the operation; it was "
                    "rolled back and nothing was written."
                ) from exc
            except BaseException:
                self._depth -= 1

                if outermost:
                    self._rollback_quietly()

                raise
            else:
                self._depth -= 1

                if outermost:
                    try:
                        self._connection.execute("COMMIT")
                    except sqlite3.Error as exc:
                        self._rollback_quietly()

                        raise StoreUnavailable(
                            "the application store could not commit; nothing was written."
                        ) from exc

    @contextmanager
    def reading(self) -> Iterator[sqlite3.Connection]:
        """Run a read under the same lock, without opening a write transaction."""
        with self._lock:
            self._raise_if_closed()

            try:
                yield self._connection
            except sqlite3.Error as exc:
                raise StoreUnavailable(
                    "the application store could not be read."
                ) from exc

    @contextmanager
    def snapshot(self) -> Iterator[sqlite3.Connection]:
        """Hold one consistent read view for the duration of a block.

        Used where several reads have to agree with each other — verifying the chain and
        its anchor, for instance. Without a read transaction the rows and the anchor could
        be read either side of a concurrent append, and verification would report a
        failure that never happened. In WAL mode a read transaction does not block
        writers.
        """
        with self._lock:
            self._raise_if_closed()

            try:
                self._connection.execute("BEGIN")
            except sqlite3.Error as exc:
                raise StoreUnavailable(
                    "the application store could not be read."
                ) from exc

            try:
                yield self._connection
            except BaseException:
                try:
                    self._connection.execute("ROLLBACK")
                except sqlite3.Error:
                    logger.warning("Closing a read snapshot did not complete.")

                raise
            else:
                try:
                    self._connection.execute("COMMIT")
                except sqlite3.Error:
                    logger.warning("Closing a read snapshot did not complete.")

    def secure_paths(self) -> None:
        """Re-apply owner-only permissions, e.g. once the WAL files exist."""
        with self._lock:
            self._raise_if_closed()
            self._paths.enforce_permissions()

    # -- internals ----------------------------------------------------------

    def _raise_if_closed(self) -> None:
        if self._closed:
            raise StoreUnavailable("the application store is closed.")

    def _rollback_quietly(self) -> None:
        try:
            self._connection.execute("ROLLBACK")
        except sqlite3.Error:
            logger.warning("Rolling back an application store transaction did not complete.")
