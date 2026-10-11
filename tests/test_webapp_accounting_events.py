"""End-to-end accounting through the web application.

These are the tests that connect the pieces: a real application built by ``create_app``,
a real SQLite store, and the events that authentication and session lifecycle actually
produce. They also carry the property the adversarial model tests cannot: whatever the
emitters pass, no credential reaches a stored record.
"""

import logging
import pathlib
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from pentaia.appstore.accounting import (
    ALLOWED_AUTH_SOURCES,
    AccountingErrorType,
    AccountingOutcome,
)
from pentaia.appstore.config import StoreConfig
from pentaia.appstore.connection import SqliteAppStore
from pentaia.appstore.recorder import AccountingState
from pentaia.appstore.repository import SqliteAccountingRepository
from pentaia.webapp import WebAppConfig, create_app
from pentaia.webapp.auth.base import AuthOutcome, AuthResult
from pentaia.webapp.auth.csrf import CSRF_HEADER_NAME
from pentaia.webapp.config import SUPPORTED_AUTH_PROVIDERS
from pentaia.webapp.identity import AuthenticatedIdentity
from pentaia.webapp.sessions import SESSION_COOKIE_NAME

USERNAME = "admin@example.test"
PASSWORD = "not-a-real-password"
PEER = "203.0.113.7"


class Provider:
    """A provider that proves one credential, so no directory is needed."""

    name = "ad"

    def __init__(self, *, outcome: AuthOutcome | None = None) -> None:
        self._outcome = outcome

    def authenticate(self, username: object, password: object) -> AuthResult:
        if self._outcome is not None:
            return AuthResult(self._outcome)

        if username == USERNAME and password == PASSWORD:
            return AuthResult(
                AuthOutcome.SUCCESS,
                AuthenticatedIdentity.from_provider(
                    auth_source="ad", username=USERNAME, display_name="Admin User"
                ),
            )

        return AuthResult(AuthOutcome.REJECTED)


def durable_config(tmp_path: pathlib.Path, **overrides) -> WebAppConfig:
    return WebAppConfig(
        auth_provider="ad",
        store=StoreConfig(mode="sqlite", data_dir=tmp_path),
        **overrides,
    )


def reader(tmp_path: pathlib.Path) -> SqliteAccountingRepository:
    """Read the events through a separate handle, as the admin utility would."""
    store = SqliteAppStore.open(StoreConfig(mode="sqlite", data_dir=tmp_path))

    return SqliteAccountingRepository(store)


def client_for(app, address: str = PEER) -> TestClient:
    return TestClient(app, base_url="https://testserver", client=(address, 4321))


def sign_in(client: TestClient, *, password: str = PASSWORD):
    token = client.get("/api/auth/csrf").json()["csrf_token"]

    return client.post(
        "/api/auth/login",
        json={"username": USERNAME, "password": password},
        headers={CSRF_HEADER_NAME: token},
    )


def event_types(repository: SqliteAccountingRepository) -> list[str]:
    return [str(r.as_mapping()["event_type"]) for r in repository.iter_records()]


def records_by_type(repository: SqliteAccountingRepository) -> dict[str, dict]:
    """Every recorded event keyed by type, so an assertion can name the one it means."""
    return {
        str(record.as_mapping()["event_type"]): dict(record.as_mapping())
        for record in repository.iter_records()
    }


# --- the store is opened, migrated and reported ----------------------------


def test_the_durable_store_is_created_and_migrated(tmp_path: pathlib.Path) -> None:
    app = create_app(durable_config(tmp_path), auth_provider=Provider())

    with client_for(app) as client:
        assert client.get("/healthz").status_code == 200
        sign_in(client)
        assert client.get("/api/status").status_code == 200

    assert (tmp_path / "pentaia.db").exists()
    assert (tmp_path.stat().st_mode & 0o777) == 0o700


def test_the_status_surface_reports_the_accounting_state(
    tmp_path: pathlib.Path,
) -> None:
    """Memory mode reports disabled; the durable mode reports active."""
    memory_app = create_app(WebAppConfig(auth_provider="ad"), auth_provider=Provider())

    with client_for(memory_app) as client:
        sign_in(client)
        memory_state = client.get("/api/status").json()["accounting"]

    durable_app = create_app(durable_config(tmp_path), auth_provider=Provider())

    with client_for(durable_app) as client:
        sign_in(client)
        durable_state = client.get("/api/status").json()["accounting"]

    assert memory_state == "disabled"
    assert durable_state == "active"


def test_an_unusable_data_directory_stops_the_application(
    tmp_path: pathlib.Path,
) -> None:
    """Fail closed at startup, not on the first login."""
    occupied = tmp_path / "store"
    occupied.write_text("not a directory")

    with pytest.raises(Exception) as caught:
        create_app(
            WebAppConfig(
                auth_provider="ad",
                store=StoreConfig(mode="sqlite", data_dir=occupied),
            ),
            auth_provider=Provider(),
        )

    assert "not a directory" in str(caught.value)


def test_the_startup_log_records_the_store_mode(
    tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    app = create_app(durable_config(tmp_path), auth_provider=Provider())

    with caplog.at_level("INFO", logger="pentaia.webapp.app"), client_for(app):
        pass

    logged = "\n".join(record.getMessage() for record in caplog.records)

    assert "store=sqlite" in logged
    assert "accounting=active" in logged


# --- what authentication records -------------------------------------------


def test_a_successful_login_records_the_authentication_and_the_session(
    tmp_path: pathlib.Path,
) -> None:
    app = create_app(durable_config(tmp_path), auth_provider=Provider())

    with client_for(app) as client:
        assert sign_in(client).status_code == 200

    repository = reader(tmp_path)

    try:
        assert event_types(repository) == ["web_session_created", "login_success"]

        events = records_by_type(repository)

        # Both events are inspected by name. Asserting on "the first record" is how a
        # successful login could be recorded as an error and still pass: the first record
        # is the session creation, whose outcome is legitimately success.
        login = events["login_success"]
        assert login["outcome"] == "success"
        assert login["error_type"] is None
        assert login["user_id"] == f"ad:{USERNAME}"
        assert login["auth_source"] == "ad"
        assert login["session_label"].startswith("sess-")

        created = events["web_session_created"]
        assert created["outcome"] == "success"
        assert created["error_type"] is None
        assert created["user_id"] == f"ad:{USERNAME}"
        # The two records describe the same session.
        assert created["session_label"] == login["session_label"]

        assert repository.verify().ok is True
    finally:
        repository._store.close()


def test_a_refused_login_records_a_denied_outcome(tmp_path: pathlib.Path) -> None:
    app = create_app(durable_config(tmp_path), auth_provider=Provider())

    with client_for(app) as client:
        assert sign_in(client, password="wrong").status_code == 401

    repository = reader(tmp_path)

    try:
        assert event_types(repository) == ["login_failure"]
        assert next(iter(repository.iter_records())).as_mapping()["outcome"] == "denied"
    finally:
        repository._store.close()


def test_an_unreachable_provider_records_an_error(tmp_path: pathlib.Path) -> None:
    app = create_app(
        durable_config(tmp_path),
        auth_provider=Provider(outcome=AuthOutcome.UNAVAILABLE),
    )

    with client_for(app) as client:
        assert sign_in(client).status_code == 503

    repository = reader(tmp_path)

    try:
        record = next(iter(repository.iter_records())).as_mapping()
        assert record["outcome"] == "error"
        assert record["error_type"] == "unavailable"
    finally:
        repository._store.close()


def test_a_throttled_attempt_records_a_blocked_error(tmp_path: pathlib.Path) -> None:
    app = create_app(
        durable_config(tmp_path, login_max_attempts=1), auth_provider=Provider()
    )

    with client_for(app) as client:
        assert sign_in(client, password="wrong").status_code == 401
        assert sign_in(client, password="wrong").status_code == 429

    repository = reader(tmp_path)

    try:
        outcomes = [
            (str(r.as_mapping()["outcome"]), r.as_mapping()["error_type"])
            for r in repository.iter_records()
        ]
        assert outcomes == [("denied", None), ("denied", "blocked")]
    finally:
        repository._store.close()


def test_logout_records_the_action_and_the_revocation(tmp_path: pathlib.Path) -> None:
    app = create_app(durable_config(tmp_path), auth_provider=Provider())

    with client_for(app) as client:
        assert sign_in(client).status_code == 200
        token = client.get("/api/auth/csrf").json()["csrf_token"]
        assert (
            client.post(
                "/api/auth/logout", headers={CSRF_HEADER_NAME: token}
            ).status_code
            == 204
        )

    repository = reader(tmp_path)

    try:
        # The store records the destruction; the route records the user action after it.
        assert event_types(repository) == [
            "web_session_created",
            "login_success",
            "web_session_revoked",
            "logout",
        ]
    finally:
        repository._store.close()


def test_an_expired_session_is_recorded_as_expired(
    tmp_path: pathlib.Path,
) -> None:
    """The deadline is created by the clock, so expiry is exercised without waiting."""
    class Clock:
        def __init__(self) -> None:
            self.now = datetime(2026, 10, 10, 22, 11, 41, tzinfo=UTC)

        def __call__(self) -> datetime:
            return self.now

        def advance(self, seconds: float):
            from datetime import timedelta

            self.now += timedelta(seconds=seconds)

    clock = Clock()
    app = create_app(
        durable_config(tmp_path, session_idle_timeout=60, session_absolute_lifetime=600),
        auth_provider=Provider(),
        clock=clock,
    )

    with client_for(app) as client:
        assert sign_in(client).status_code == 200
        clock.advance(61)
        assert client.get("/api/me").status_code == 401

    repository = reader(tmp_path)

    try:
        assert event_types(repository) == [
            "web_session_created",
            "login_success",
            "web_session_expired",
        ]
    finally:
        repository._store.close()


# --- a session outlives the process -----------------------------------------


def test_a_session_survives_an_application_restart(tmp_path: pathlib.Path) -> None:
    """The headline durability behaviour, through the real application."""
    config = durable_config(tmp_path)

    first = create_app(config, auth_provider=Provider())

    with client_for(first) as client:
        assert sign_in(client).status_code == 200
        cookie = client.cookies.get(SESSION_COOKIE_NAME)

    # The first application's lifespan closed its store; a second process opens it again.
    second = create_app(config, auth_provider=Provider())

    with client_for(second) as client:
        client.cookies.set(SESSION_COOKIE_NAME, cookie)

        assert client.get("/api/me").status_code == 200
        assert client.get("/api/me").json()["user_id"] == f"ad:{USERNAME}"


def test_throttling_survives_an_application_restart(tmp_path: pathlib.Path) -> None:
    config = durable_config(tmp_path, login_max_attempts=1)

    first = create_app(config, auth_provider=Provider())

    with client_for(first) as client:
        assert sign_in(client, password="wrong").status_code == 401

    second = create_app(config, auth_provider=Provider())

    with client_for(second) as client:
        assert sign_in(client, password="wrong").status_code == 429


# --- no credential ever reaches a record ------------------------------------


def test_no_credential_reaches_a_stored_record(
    tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The property the emitter tests exist for, asserted over real traffic."""
    app = create_app(durable_config(tmp_path), auth_provider=Provider())

    with caplog.at_level(logging.DEBUG), client_for(app) as client:
        assert sign_in(client).status_code == 200
        session_id = client.cookies.get(SESSION_COOKIE_NAME)
        token = client.get("/api/auth/csrf").json()["csrf_token"]
        assert sign_in(client, password="wrong").status_code == 401

    store = SqliteAppStore.open(StoreConfig(mode="sqlite", data_dir=tmp_path))
    repository = SqliteAccountingRepository(store)

    try:
        serialized = "\n".join(r.canonical_event for r in repository.iter_records())

        for secret in (PASSWORD, "wrong", session_id, token):
            assert secret not in serialized

        logged = "\n".join(record.getMessage() for record in caplog.records)

        assert PASSWORD not in logged
        assert session_id not in logged
        assert token not in logged
    finally:
        store.close()


def test_the_event_rows_themselves_carry_no_credential(
    tmp_path: pathlib.Path,
) -> None:
    app = create_app(durable_config(tmp_path), auth_provider=Provider())

    with client_for(app) as client:
        assert sign_in(client).status_code == 200
        session_id = client.cookies.get(SESSION_COOKIE_NAME)

    store = SqliteAppStore.open(StoreConfig(mode="sqlite", data_dir=tmp_path))

    try:
        with store.reading() as connection:
            rows = connection.execute("SELECT * FROM accounting_events").fetchall()

        dumped = "\n".join(str(tuple(row)) for row in rows)

        assert session_id not in dumped
        assert PASSWORD not in dumped
    finally:
        store.close()


def test_the_accounting_provider_set_agrees_with_configuration() -> None:
    """Two lists for the same contract, pinned together so they cannot drift."""
    assert tuple(ALLOWED_AUTH_SOURCES) == tuple(SUPPORTED_AUTH_PROVIDERS)
    assert AccountingState.ACTIVE.value == "active"


def test_every_login_outcome_has_a_recorded_mapping() -> None:
    """A new login outcome must not fall through to the error default unnoticed.

    The lookup has a default so an unmapped value degrades to "error/internal" rather than
    raising mid-request, which means a missing entry is silent. This test makes it loud.
    """
    from pentaia.webapp.auth.login import _RECORDED_OUTCOMES, LoginOutcome

    assert set(_RECORDED_OUTCOMES) == set(LoginOutcome)

    # A success is recorded as a success, with no error category.
    assert _RECORDED_OUTCOMES[LoginOutcome.SUCCESS] == (AccountingOutcome.SUCCESS, None)

    assert all(
        isinstance(outcome, AccountingOutcome)
        and (error is None or isinstance(error, AccountingErrorType))
        for outcome, error in _RECORDED_OUTCOMES.values()
    )


def test_a_refused_login_is_never_recorded_as_a_success(tmp_path: pathlib.Path) -> None:
    """The complement of the success mapping, so the two cannot be swapped."""
    app = create_app(durable_config(tmp_path), auth_provider=Provider())

    with client_for(app) as client:
        assert sign_in(client, password="wrong").status_code == 401

    repository = reader(tmp_path)

    try:
        record = records_by_type(repository)["login_failure"]

        assert record["outcome"] == "denied"
        assert record["error_type"] is None
    finally:
        repository._store.close()
