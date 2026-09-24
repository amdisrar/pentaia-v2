"""P4-04 server-side session model and lifecycle."""

import base64
import dataclasses
import logging
from datetime import UTC, datetime, timedelta

import pytest

from pentaia.webapp.identity import AuthenticatedIdentity
from pentaia.webapp.sessions import (
    DEFAULT_ABSOLUTE_LIFETIME_SECONDS,
    DEFAULT_IDLE_TIMEOUT_SECONDS,
    EXPIRY_ABSOLUTE,
    EXPIRY_IDLE,
    LABEL_PREFIX,
    SESSION_COOKIE_NAME,
    SESSION_COOKIE_PATH,
    SESSION_ID_BYTES,
    InMemorySessionStore,
    IssuedSession,
    WebSession,
    generate_session_id,
    session_cookie_settings,
)

START = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


def identity(username: str = "user@example.com", auth_source: str = "ad") -> AuthenticatedIdentity:
    return AuthenticatedIdentity.from_provider(
        auth_source=auth_source,
        username=username,
        display_name="Example User",
        authenticated_at=START,
    )


@pytest.fixture()
def store() -> InMemorySessionStore:
    return InMemorySessionStore()


# --- identifier ------------------------------------------------------------


def test_a_session_identifier_carries_256_bits_of_entropy() -> None:
    session_id = generate_session_id()

    raw = base64.urlsafe_b64decode(session_id + "=" * (-len(session_id) % 4))

    assert len(raw) == SESSION_ID_BYTES == 32
    assert len(raw) * 8 == 256


def test_identifiers_are_unique_and_url_safe() -> None:
    identifiers = {generate_session_id() for _ in range(500)}

    assert len(identifiers) == 500

    for value in identifiers:
        assert set(value) <= set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        )


# --- creation --------------------------------------------------------------


def test_create_returns_an_issued_session_with_timestamps(store: InMemorySessionStore) -> None:
    issued = store.create(identity(), now=START)

    assert isinstance(issued, IssuedSession)
    assert issued.session.label.startswith(LABEL_PREFIX)
    assert issued.session.identity.user_id == "ad:user@example.com"
    assert issued.session.auth_source == "ad"
    assert issued.session.created_at == START
    assert issued.session.last_activity_at == START
    assert issued.session.absolute_expires_at == START + timedelta(
        seconds=DEFAULT_ABSOLUTE_LIFETIME_SECONDS
    )
    assert issued.session.idle_timeout_seconds == DEFAULT_IDLE_TIMEOUT_SECONDS


def test_create_rejects_anything_that_is_not_an_identity(store: InMemorySessionStore) -> None:
    with pytest.raises(TypeError):
        store.create("not-an-identity")  # type: ignore[arg-type]


def test_sessions_for_the_same_user_are_independent(store: InMemorySessionStore) -> None:
    first = store.create(identity(), now=START)
    second = store.create(identity(), now=START)

    assert first.session_id != second.session_id
    assert first.session.label != second.session.label
    assert store.active_count == 2


def test_multiple_concurrent_sessions_are_all_resolvable(store: InMemorySessionStore) -> None:
    issued = [store.create(identity(), now=START) for _ in range(3)]

    for session in issued:
        resolved = store.resolve(session.session_id, now=START)
        assert resolved is not None
        assert resolved.label == session.session.label

    assert store.active_count == 3


def test_invalidating_one_session_leaves_the_others(store: InMemorySessionStore) -> None:
    first = store.create(identity(), now=START)
    second = store.create(identity(), now=START)

    assert store.invalidate(first.session_id) is True

    assert store.resolve(first.session_id, now=START) is None
    assert store.resolve(second.session_id, now=START) is not None
    assert store.active_count == 1


# --- the raw identifier is never stored or printed ------------------------


def test_the_store_never_holds_the_raw_identifier(store: InMemorySessionStore) -> None:
    issued = store.create(identity(), now=START)

    assert store.holds_raw_identifier(issued.session_id) is False
    assert issued.session_id not in repr(store.__dict__)


def test_representations_of_session_records_redact_the_identifier(
    store: InMemorySessionStore,
) -> None:
    issued = store.create(identity(), now=START)

    assert issued.session_id not in repr(issued)
    assert issued.session_id not in str(issued)
    assert issued.session_id not in repr(issued.session)
    assert "<redacted>" in repr(issued)
    assert issued.session.label in repr(issued)


def test_creating_and_resolving_a_session_never_logs_the_identifier(
    store: InMemorySessionStore,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="pentaia.webapp.sessions"):
        issued = store.create(identity(), now=START)
        store.resolve(issued.session_id, now=START)
        store.invalidate(issued.session_id)

    logged = "\n".join(record.getMessage() for record in caplog.records)

    assert issued.session_id not in logged
    assert issued.session.label in logged
    assert "user_id=ad:user@example.com" in logged


# --- lookup ----------------------------------------------------------------


def test_resolve_returns_the_identity_of_the_session(store: InMemorySessionStore) -> None:
    issued = store.create(identity("other@example.com", "radius"), now=START)

    resolved = store.resolve(issued.session_id, now=START)

    assert resolved is not None
    assert resolved.identity.user_id == "radius:other@example.com"
    assert resolved.identity.display_name == "Example User"


@pytest.mark.parametrize("value", ["", "unknown", "not-a-real-session", "a" * 200])
def test_an_unknown_identifier_fails_closed(store: InMemorySessionStore, value: str) -> None:
    assert store.resolve(value, now=START) is None


@pytest.mark.parametrize("value", [None, 5, b"bytes"])
def test_a_non_string_identifier_fails_closed(store: InMemorySessionStore, value: object) -> None:
    assert store.resolve(value, now=START) is None  # type: ignore[arg-type]


def test_an_invalidated_identifier_fails_closed(store: InMemorySessionStore) -> None:
    issued = store.create(identity(), now=START)

    store.invalidate(issued.session_id)

    assert store.resolve(issued.session_id, now=START) is None


# --- expiry ----------------------------------------------------------------


def test_the_idle_timer_refreshes_on_activity_but_the_absolute_lifetime_does_not(
    store: InMemorySessionStore,
) -> None:
    issued = store.create(identity(), now=START)
    idle = timedelta(seconds=DEFAULT_IDLE_TIMEOUT_SECONDS)

    later = START + idle - timedelta(minutes=1)
    resolved = store.resolve(issued.session_id, now=later)

    assert resolved is not None
    # Activity moved the idle deadline forward...
    assert resolved.idle_expires_at() > START + idle
    # ...but the absolute deadline never moves.
    assert resolved.absolute_expires_at == issued.session.absolute_expires_at


def test_a_session_expires_when_idle(store: InMemorySessionStore) -> None:
    issued = store.create(identity(), now=START)
    after_idle = START + timedelta(seconds=DEFAULT_IDLE_TIMEOUT_SECONDS)

    assert issued.session.expiry_reason(after_idle) == EXPIRY_IDLE
    assert store.resolve(issued.session_id, now=after_idle) is None
    assert store.active_count == 0


def test_a_session_expires_at_its_absolute_lifetime_even_if_recently_active(
    store: InMemorySessionStore,
) -> None:
    issued = store.create(identity(), now=START)
    absolute = START + timedelta(seconds=DEFAULT_ABSOLUTE_LIFETIME_SECONDS)

    assert issued.session.expiry_reason(absolute) == EXPIRY_ABSOLUTE


def test_the_absolute_lifetime_wins_over_the_idle_timer(
    store: InMemorySessionStore,
) -> None:
    store = InMemorySessionStore(idle_timeout_seconds=10_000, absolute_lifetime_seconds=60)
    issued = store.create(identity(), now=START)

    assert issued.session.expiry_reason(START + timedelta(seconds=60)) == EXPIRY_ABSOLUTE


def test_a_session_is_valid_just_before_its_idle_deadline(store: InMemorySessionStore) -> None:
    issued = store.create(identity(), now=START)
    just_before = START + timedelta(seconds=DEFAULT_IDLE_TIMEOUT_SECONDS) - timedelta(seconds=1)

    assert issued.session.expiry_reason(just_before) is None
    assert store.resolve(issued.session_id, now=just_before) is not None


def test_purge_expired_removes_only_expired_sessions(store: InMemorySessionStore) -> None:
    fresh = store.create(identity("fresh@example.com"), now=START)
    stale = store.create(identity("stale@example.com"), now=START)
    # Expire one of them by resolving long after its idle deadline while touching the
    # other first.
    store.resolve(fresh.session_id, now=START + timedelta(minutes=10))

    removed = store.purge_expired(now=START + timedelta(seconds=DEFAULT_IDLE_TIMEOUT_SECONDS))

    assert removed == 1
    assert store.resolve(stale.session_id, now=START) is None
    assert store.active_count == 1


def test_the_timeouts_are_validated() -> None:
    with pytest.raises(ValueError):
        InMemorySessionStore(idle_timeout_seconds=0)

    with pytest.raises(ValueError):
        InMemorySessionStore(absolute_lifetime_seconds=-1)

    with pytest.raises(ValueError):
        InMemorySessionStore(idle_timeout_seconds=True)


def test_a_wrong_timestamp_type_is_a_programming_error(store: InMemorySessionStore) -> None:
    """Wrong type raises TypeError; a naive timestamp is bad input and raises ValueError."""
    with pytest.raises(TypeError):
        store.create(identity(), now="2026-09-24")  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        store.create(identity(), now=datetime(2026, 9, 24, 12, 0))  # noqa: DTZ001


# --- invalidation ----------------------------------------------------------


def test_invalidation_by_label_destroys_only_that_session(store: InMemorySessionStore) -> None:
    first = store.create(identity(), now=START)
    second = store.create(identity(), now=START)

    assert store.invalidate_label(first.session.label) is True

    assert store.resolve(first.session_id, now=START) is None
    assert store.resolve(second.session_id, now=START) is not None
    assert store.invalidate_label("sess-unknown") is False


def test_invalidation_by_user_destroys_every_session_for_that_user(
    store: InMemorySessionStore,
) -> None:
    store.create(identity("first@example.com"), now=START)
    store.create(identity("second@example.com"), now=START)
    store.create(identity("first@example.com"), now=START)

    removed = store.invalidate_user("ad:first@example.com")

    assert removed == 2
    assert store.active_count == 1


def test_invalidating_an_unknown_session_reports_false(store: InMemorySessionStore) -> None:
    assert store.invalidate("unknown") is False
    assert store.invalidate("") is False
    assert store.invalidate_user("ad:nobody") == 0
    assert store.invalidate_label("another") is False


# --- record shape and cookie foundation ------------------------------------


def test_the_session_record_holds_no_identifier_or_credential() -> None:
    fields = {field.name for field in dataclasses.fields(WebSession)}

    assert fields == {
        "label",
        "identity",
        "created_at",
        "last_activity_at",
        "absolute_expires_at",
        "idle_timeout_seconds",
    }

    for forbidden in ("password", "token", "secret", "session_id", "cookie"):
        assert not [name for name in fields if forbidden in name]


def test_the_session_record_is_frozen(store: InMemorySessionStore) -> None:
    session = store.create(identity(), now=START).session

    with pytest.raises(dataclasses.FrozenInstanceError):
        session.label = "sess-other"  # type: ignore[misc]


def test_the_cookie_contract_matches_the_architecture() -> None:
    settings = session_cookie_settings()

    assert settings["key"] == SESSION_COOKIE_NAME == "pentaia_session"
    assert settings["httponly"] is True
    assert settings["secure"] is True
    assert settings["samesite"] == "lax"
    assert settings["path"] == SESSION_COOKIE_PATH == "/"
    # No broad Domain attribute, and the cookie carries nothing but the identifier.
    assert "domain" not in settings
    assert set(settings) == {"key", "httponly", "secure", "samesite", "path"}
