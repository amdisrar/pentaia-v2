"""Migration safety, filesystem protections and SQLite lifecycle.

The properties that matter here are the ones a migration runner can get wrong quietly:
a half-applied migration, a database recreated behind the operator's back, a newer
schema silently downgraded, and permissions that depend on the process umask.
"""

import pathlib
import re
import sqlite3
import threading

import pytest

from pentaia.appstore import migrations
from pentaia.appstore.config import StoreConfig
from pentaia.appstore.connection import (
    SqliteAppStore,
    StorePaths,
    prepare_paths,
)
from pentaia.appstore.errors import (
    MigrationFailed,
    SchemaTooNew,
    StoreUnavailable,
)
from pentaia.appstore.migrations import (
    LATEST_VERSION,
    Migration,
    apply_migrations,
    current_version,
    pending_migrations,
)

EXPECTED_TABLES = {
    "accounting_chain_state",
    "accounting_events",
    "login_throttle",
    "schema_migrations",
    "web_sessions",
}


def config_for(directory: pathlib.Path) -> StoreConfig:
    return StoreConfig(mode="sqlite", data_dir=directory)


@pytest.fixture()
def store(tmp_path: pathlib.Path):
    opened = SqliteAppStore.open(config_for(tmp_path))

    yield opened

    opened.close()


def table_names(connection: sqlite3.Connection) -> set[str]:
    return {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }


# --- applying migrations ----------------------------------------------------


def test_a_fresh_database_is_migrated_to_the_current_version(store: SqliteAppStore) -> None:
    assert store.migrate() == LATEST_VERSION

    with store.reading() as connection:
        assert EXPECTED_TABLES <= table_names(connection)
        assert current_version(connection) == LATEST_VERSION
        rows = connection.execute("SELECT version FROM schema_migrations").fetchall()
        assert [row[0] for row in rows] == [1]


def test_migrations_are_idempotent(store: SqliteAppStore) -> None:
    assert store.migrate() == LATEST_VERSION
    assert store.migrate() == LATEST_VERSION

    with store.reading() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM schema_migrations"
        ).fetchone()[0] == 1


def test_pending_migrations_reports_nothing_once_applied(store: SqliteAppStore) -> None:
    store.migrate()

    with store.reading() as connection:
        assert pending_migrations(connection) == ()


def test_a_newer_schema_is_refused(store: SqliteAppStore) -> None:
    """Downgrading in place risks corrupting recorded state, so it is refused."""
    store.migrate()

    with store.transaction() as connection:
        connection.execute(
            "INSERT INTO schema_migrations (version, description) VALUES (?, ?)",
            (LATEST_VERSION + 1, "from the future"),
        )

    with pytest.raises(SchemaTooNew):
        store.migrate()


def test_a_failed_migration_rolls_back_completely(
    store: SqliteAppStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The statements of one migration are one unit, including the DDL.

    ``executescript`` cannot give this guarantee: it commits before running, so the
    ``CREATE TABLE`` below would survive the failure. The migration runner therefore
    executes statements individually inside an explicit transaction.
    """
    broken = Migration(
        version=1,
        description="deliberately broken",
        statements=(
            "CREATE TABLE half_created (id INTEGER PRIMARY KEY)",
            "THIS IS NOT VALID SQL",
        ),
    )
    monkeypatch.setattr(migrations, "MIGRATIONS", (broken,))

    with pytest.raises(MigrationFailed) as caught:
        store.migrate()

    assert "still at version 0" in str(caught.value)

    with store.reading() as connection:
        assert current_version(connection) == 0
        assert "half_created" not in table_names(connection)


def test_the_migration_runner_never_uses_executescript() -> None:
    """A source-level guard for the property the rollback test proves behaviourally.

    The module's docstring names ``executescript`` to explain why it is not used, so this
    checks for a call rather than for the word.
    """
    source = pathlib.Path(migrations.__file__).read_text(encoding="utf-8")

    assert not re.search(r"\.executescript\s*\(", source)


def test_migrations_are_refused_inside_another_transaction(store: SqliteAppStore) -> None:
    """A clear refusal beats a confusing 'transaction within a transaction' error."""
    with (
        pytest.raises(StoreUnavailable) as caught,
        store.transaction() as connection,
    ):
        apply_migrations(connection)

    assert "must not run inside another transaction" in str(caught.value)


def test_two_initialisers_can_migrate_concurrently(tmp_path: pathlib.Path) -> None:
    """Whichever process loses the race finds the work already done and skips it.

    A generous busy timeout is used so the test measures the locking protocol rather than
    how loaded the machine happens to be when it runs.
    """
    config = StoreConfig(
        mode="sqlite", data_dir=tmp_path, busy_timeout_ms=30_000
    )
    failures: list[BaseException] = []
    start = threading.Barrier(2)

    def initialise() -> None:
        try:
            opened = SqliteAppStore.open(config)
            start.wait(timeout=10)
            opened.migrate()
            opened.close()
        except BaseException as exc:  # noqa: BLE001 - reported by the assertion below
            failures.append(exc)

    threads = [threading.Thread(target=initialise) for _ in range(2)]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join(timeout=15)

    assert failures == []

    opened = SqliteAppStore.open(config)

    try:
        with opened.reading() as connection:
            assert current_version(connection) == LATEST_VERSION
            assert connection.execute(
                "SELECT COUNT(*) FROM schema_migrations"
            ).fetchone()[0] == 1
    finally:
        opened.close()


# --- the database file is never recreated ----------------------------------


def test_a_corrupt_database_is_reported_and_left_alone(tmp_path: pathlib.Path) -> None:
    """Repair-by-recreation would destroy the evidence the audit trail exists to keep."""
    database = tmp_path / "pentaia.db"
    garbage = b"this is not a sqlite database" * 64
    database.write_bytes(garbage)

    with pytest.raises(StoreUnavailable):
        SqliteAppStore.open(config_for(tmp_path))

    assert database.exists()
    assert database.read_bytes() == garbage


def test_an_empty_file_is_treated_as_a_new_database(tmp_path: pathlib.Path) -> None:
    """A zero-byte file has no schema to lose, so initialising it is not destructive."""
    (tmp_path / "pentaia.db").write_bytes(b"")

    store = SqliteAppStore.open(config_for(tmp_path))

    try:
        assert store.migrate() == LATEST_VERSION
    finally:
        store.close()


# --- filesystem protections -------------------------------------------------


def test_the_directory_and_database_are_owner_only(tmp_path: pathlib.Path) -> None:
    store = SqliteAppStore.open(config_for(tmp_path))

    try:
        store.migrate()

        assert (tmp_path.stat().st_mode & 0o777) == 0o700
        assert ((tmp_path / "pentaia.db").stat().st_mode & 0o777) == 0o600
    finally:
        store.close()


def test_write_ahead_logging_sidecars_are_owner_only(tmp_path: pathlib.Path) -> None:
    """The sidecars appear only once SQLite writes, so permissions are re-applied then."""
    store = SqliteAppStore.open(config_for(tmp_path))

    try:
        store.migrate()
        store.secure_paths()

        for name in ("pentaia.db-wal", "pentaia.db-shm"):
            sidecar = tmp_path / name

            if sidecar.exists():
                assert (sidecar.stat().st_mode & 0o777) == 0o600, name
    finally:
        store.close()


def test_a_symlinked_data_directory_is_refused(tmp_path: pathlib.Path) -> None:
    """A link could be swapped to redirect the store, so it is refused outright."""
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(StoreUnavailable) as caught:
        prepare_paths(config_for(link))

    assert "symbolic link" in str(caught.value)


def test_a_file_where_the_directory_belongs_is_refused(tmp_path: pathlib.Path) -> None:
    occupied = tmp_path / "store"
    occupied.write_text("not a directory")

    with pytest.raises(StoreUnavailable):
        prepare_paths(config_for(occupied))


def test_an_unwritable_directory_is_refused(tmp_path: pathlib.Path) -> None:
    readonly = tmp_path / "readonly"
    readonly.mkdir(mode=0o500)

    try:
        with pytest.raises(StoreUnavailable):
            prepare_paths(config_for(readonly))
    finally:
        readonly.chmod(0o700)


def test_store_paths_are_derived_from_configuration(tmp_path: pathlib.Path) -> None:
    paths = StorePaths.for_config(config_for(tmp_path))

    assert paths.directory == tmp_path
    assert paths.database == tmp_path / "pentaia.db"
    assert paths.wal.name == "pentaia.db-wal"
    assert paths.shm.name == "pentaia.db-shm"


# --- connection settings and lifecycle --------------------------------------


def test_the_connection_uses_the_durability_pragmas(store: SqliteAppStore) -> None:
    with store.reading() as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        # 2 == FULL: durable accounting must survive a power loss, not just a crash.
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 5000


def test_a_closed_store_fails_closed(store: SqliteAppStore) -> None:
    store.migrate()
    store.close()

    with pytest.raises(StoreUnavailable):
        store.migrate()

    with pytest.raises(StoreUnavailable), store.reading():
        pass

    with pytest.raises(StoreUnavailable), store.transaction():
        pass


def test_closing_twice_is_harmless(store: SqliteAppStore) -> None:
    store.close()
    store.close()

    assert store.closed is True


def test_a_shutdown_checkpoint_leaves_the_main_file_complete(tmp_path: pathlib.Path) -> None:
    """Documents the WAL-aware backup requirement: copy after shutdown, not while live."""
    store = SqliteAppStore.open(config_for(tmp_path))
    store.migrate()

    with store.transaction() as connection:
        connection.execute(
            "INSERT INTO schema_migrations (version, description) VALUES (?, ?)",
            (99, "simulated later work"),
        )

    store.close()

    copy = tmp_path / "copy.db"
    copy.write_bytes((tmp_path / "pentaia.db").read_bytes())

    connection = sqlite3.connect(str(copy))

    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM schema_migrations"
        ).fetchone()[0] == 2
    finally:
        connection.close()


# --- transactions -----------------------------------------------------------


def test_a_nested_transaction_joins_the_outer_one(store: SqliteAppStore) -> None:
    store.migrate()

    with (
        pytest.raises(RuntimeError),
        store.transaction() as connection,
    ):
        connection.execute(
            "INSERT INTO schema_migrations (version, description) VALUES (?, ?)",
            (50, "rolled back with its outer block"),
        )

        with store.transaction() as nested:
            assert nested is connection

        raise RuntimeError("the outer block failed")

    with store.reading() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 50"
        ).fetchone()[0] == 0


def test_a_committed_transaction_is_visible_afterwards(store: SqliteAppStore) -> None:
    store.migrate()

    with store.transaction() as connection:
        connection.execute(
            "INSERT INTO schema_migrations (version, description) VALUES (?, ?)",
            (60, "committed"),
        )

    with store.reading() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 60"
        ).fetchone()[0] == 1
