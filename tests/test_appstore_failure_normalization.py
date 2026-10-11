"""Database failures at the statement-execution boundary.

The distinction these tests draw: closing a store tests what happens when an operation
cannot *start*, while a trigger that aborts a statement tests what happens when one fails
*inside* an open transaction — the case where a partial mutation, a leaked driver message
or an unhandled 500 would appear. Each failure is injected deterministically with a SQLite
trigger or by removing a table, so nothing depends on timing.
"""

import pathlib

import pytest
from fastapi.testclient import TestClient

from pentaia.appstore.config import StoreConfig
from pentaia.appstore.connection import SqliteAppStore
from pentaia.appstore.errors import (
    AccountingUnavailable,
    StoreConfigurationError,
    StoreUnavailable,
)
from pentaia.appstore.recorder import RepositoryAccountingRecorder
from pentaia.appstore.repository import SqliteAccountingRepository
from pentaia.webapp import WebAppConfig, create_app
from pentaia.webapp.auth.base import AuthOutcome, AuthResult
from pentaia.webapp.auth.csrf import CSRF_HEADER_NAME
from pentaia.webapp.identity import AuthenticatedIdentity
from pentaia.webapp.persistence import SqliteLoginThrottle, SqliteSessionStore

USERNAME = "admin@example.test"
PASSWORD = "not-a-real-password"
PEER = "203.0.113.7"


class Provider:
    name = "ad"

    def __init__(self) -> None:
        self.calls = 0

    def authenticate(self, username: object, password: object) -> AuthResult:
        self.calls += 1

        if username == USERNAME and password == PASSWORD:
            return AuthResult(
                AuthOutcome.SUCCESS,
                AuthenticatedIdentity.from_provider(
                    auth_source="ad", username=USERNAME, display_name="Admin User"
                ),
            )

        return AuthResult(AuthOutcome.REJECTED)


def store_for(tmp_path: pathlib.Path) -> SqliteAppStore:
    store = SqliteAppStore.open(StoreConfig(mode="sqlite", data_dir=tmp_path))
    store.migrate()

    return store


def sessions_for(store: SqliteAppStore) -> SqliteSessionStore:
    return SqliteSessionStore(
        store, recorder=RepositoryAccountingRecorder(SqliteAccountingRepository(store))
    )


def inject_statement_failure(
    store: SqliteAppStore, *, table: str, when: str = "INSERT"
) -> None:
    """Make the next write to ``table`` fail inside whatever transaction is open."""
    with store.transaction() as connection:
        connection.execute(
            f"CREATE TRIGGER injected_failure BEFORE {when} ON {table} "
            f"BEGIN SELECT RAISE(ABORT, 'injected statement failure'); END"
        )


def identity(username: str = USERNAME) -> AuthenticatedIdentity:
    return AuthenticatedIdentity.from_provider(auth_source="ad", username=username)


# --- statements failing inside a transaction --------------------------------


def test_a_failing_statement_becomes_a_store_error_not_a_driver_error(
    tmp_path: pathlib.Path,
) -> None:
    """The driver's message can carry SQL, a table name or a path; the caller sees none."""
    store = store_for(tmp_path)
    sessions = sessions_for(store)
    inject_statement_failure(store, table="web_sessions")

    try:
        with pytest.raises(StoreUnavailable) as caught:
            sessions.create(identity())

        message = str(caught.value)

        assert "injected statement failure" not in message
        assert "INSERT" not in message
        assert str(tmp_path) not in message
        assert "web_sessions" not in message
    finally:
        store.close()


def test_a_failed_session_insert_leaves_nothing_behind(
    tmp_path: pathlib.Path,
) -> None:
    """No partial mutation: the session row and its event are the same unit."""
    store = store_for(tmp_path)
    sessions = sessions_for(store)
    repository = SqliteAccountingRepository(store)
    inject_statement_failure(store, table="web_sessions")

    try:
        with pytest.raises(StoreUnavailable):
            sessions.create(identity())

        assert sessions.active_count == 0
        assert repository.count() == 0
    finally:
        store.close()


def test_a_failed_accounting_insert_rolls_back_the_session(
    tmp_path: pathlib.Path,
) -> None:
    """The lifecycle event is inside the mutation's transaction, so the session goes too."""
    store = store_for(tmp_path)
    sessions = sessions_for(store)
    inject_statement_failure(store, table="accounting_events")

    try:
        with pytest.raises(AccountingUnavailable):
            sessions.create(identity())

        assert sessions.active_count == 0
    finally:
        store.close()


def test_a_failed_throttle_statement_consumes_nothing(
    tmp_path: pathlib.Path,
) -> None:
    """The three counters are one unit even when a statement fails mid-way."""
    store = store_for(tmp_path)
    throttle = SqliteLoginThrottle(
        store, max_attempts=3, window_seconds=900, max_keys=10
    )
    inject_statement_failure(store, table="login_throttle")

    try:
        with pytest.raises(StoreUnavailable):
            throttle.admit(username_key="k", client_ip=PEER)

        assert throttle.counts(username_key="k", client_ip=PEER) == (0, 0, 0)
    finally:
        store.close()


def test_a_read_statement_failure_is_a_store_error(tmp_path: pathlib.Path) -> None:
    store = store_for(tmp_path)
    sessions = sessions_for(store)

    with store.transaction() as connection:
        connection.execute("DROP TABLE web_sessions")

    try:
        with pytest.raises(StoreUnavailable):
            sessions.resolve("anything")

        with pytest.raises(StoreUnavailable):
            _ = sessions.active_count
    finally:
        store.close()


# --- the same failures through the HTTP surface -----------------------------


def durable_app(tmp_path: pathlib.Path, provider: Provider) -> object:
    return create_app(
        WebAppConfig(
            auth_provider="ad",
            store=StoreConfig(mode="sqlite", data_dir=tmp_path),
        ),
        auth_provider=provider,
    )


def client_for(app) -> TestClient:
    return TestClient(app, base_url="https://testserver", client=(PEER, 4321))


def sign_in(client: TestClient):
    token = client.get("/api/auth/csrf").json()["csrf_token"]

    return client.post(
        "/api/auth/login",
        json={"username": USERNAME, "password": PASSWORD},
        headers={CSRF_HEADER_NAME: token},
    )


def app_store_of(app) -> SqliteAppStore:
    return app.state.app_store


def test_a_session_write_failure_is_a_503_not_a_500(tmp_path: pathlib.Path) -> None:
    provider = Provider()
    app = durable_app(tmp_path, provider)

    with client_for(app) as client:
        inject_statement_failure(app_store_of(app), table="web_sessions")
        response = sign_in(client)

    assert response.status_code == 503
    assert set(response.json()) == {"detail"}
    assert str(tmp_path) not in response.text
    assert "injected" not in response.text


def test_a_session_read_failure_is_a_503_for_an_authenticated_caller(
    tmp_path: pathlib.Path,
) -> None:
    """Not a 401: a storage failure is not an authentication decision."""
    provider = Provider()
    app = durable_app(tmp_path, provider)

    with client_for(app) as client:
        assert sign_in(client).status_code == 200

        with app_store_of(app).transaction() as connection:
            connection.execute("DROP TABLE web_sessions")

        response = client.get("/api/me")

    assert response.status_code == 503
    assert response.json()["detail"] == "The service is temporarily unavailable."
    assert "no such table" not in response.text


def test_a_throttle_store_failure_cannot_bypass_admission(
    tmp_path: pathlib.Path,
) -> None:
    """The important one: no admission decision means no authentication."""
    provider = Provider()
    app = durable_app(tmp_path, provider)

    with client_for(app) as client:
        with app_store_of(app).transaction() as connection:
            connection.execute("DROP TABLE login_throttle")

        response = sign_in(client)

    assert response.status_code == 503
    assert provider.calls == 0, "the provider must not be reached when throttling cannot run"


def test_a_corrupt_store_file_is_never_recreated(tmp_path: pathlib.Path) -> None:
    database = tmp_path / "pentaia.db"
    garbage = b"not a database at all" * 32
    database.write_bytes(garbage)

    with pytest.raises(StoreUnavailable):
        SqliteAppStore.open(StoreConfig(mode="sqlite", data_dir=tmp_path))

    assert database.read_bytes() == garbage


# --- construction and path safety -------------------------------------------


def test_a_durable_session_store_requires_a_recorder(tmp_path: pathlib.Path) -> None:
    """Finding 4: no silent unaccounted mode."""
    store = store_for(tmp_path)

    try:
        with pytest.raises(StoreConfigurationError) as caught:
            SqliteSessionStore(store, recorder=None)  # type: ignore[arg-type]

        assert "accounting recorder" in str(caught.value)
    finally:
        store.close()


def test_a_symlinked_database_file_is_refused(tmp_path: pathlib.Path) -> None:
    """A link could be swapped to redirect the store to another file."""
    elsewhere = tmp_path / "elsewhere.db"
    elsewhere.write_bytes(b"")
    directory = tmp_path / "store"
    directory.mkdir()
    (directory / "pentaia.db").symlink_to(elsewhere)

    with pytest.raises(StoreUnavailable) as caught:
        SqliteAppStore.open(StoreConfig(mode="sqlite", data_dir=directory))

    assert "symbolic link" in str(caught.value)


def test_wal_sidecar_permissions_are_applied_without_being_asked(
    tmp_path: pathlib.Path,
) -> None:
    """Migration is the first write; the sidecars it creates are secured as part of it."""
    store = store_for(tmp_path)

    try:
        assert (tmp_path.stat().st_mode & 0o777) == 0o700
        assert ((tmp_path / "pentaia.db").stat().st_mode & 0o777) == 0o600

        for name in ("pentaia.db-wal", "pentaia.db-shm"):
            sidecar = tmp_path / name

            if sidecar.exists():
                assert (sidecar.stat().st_mode & 0o777) == 0o600, name
    finally:
        store.close()
