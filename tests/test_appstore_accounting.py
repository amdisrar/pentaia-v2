"""The accounting event model: typing, whitelisting and adversarial input.

The adversarial half of this file is the point. It pushes credential-shaped values at
every entry point of the model and asserts they are refused or cannot be serialized, and
it pins the serialized key set so a field cannot appear in a record without review.
"""

import dataclasses
import json
from datetime import UTC, datetime, timedelta, timezone

import pytest

from pentaia.appstore.accounting import (
    MAX_DURATION_MS,
    MAX_TEXT_LENGTH,
    NOT_PERSISTED_FIELDS,
    PERSISTED_FIELDS,
    AccountingErrorType,
    AccountingEvent,
    AccountingEventCategory,
    AccountingEventType,
    AccountingOutcome,
)

START = datetime(2026, 10, 10, 22, 11, 41, 123456, tzinfo=UTC)

#: Credential-shaped values that are also invalid for *every* field grammar, because they
#: carry a character no field accepts (``=``, a space) or exceed the length bound.
REFUSED_BY_EVERY_FIELD = (
    "pentaia_session=abc123def456",
    "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBgkq",
    "AIzaSyD-EXAMPLE KEY",  # a space: an API key copied with its label
    "Basic YWRtaW46c2VjcmV0",
    "password=hunter2\r\ninjected: true",
    "x" * (MAX_TEXT_LENGTH + 1),
)

TEXT_FIELDS = (
    "user_id",
    "auth_source",
    "session_label",
    "conversation_id",
    "langgraph_thread_id",
    "request_id",
    "action_id",
    "target",
    "proposal_signature",
    "requester_user_id",
    "approver_user_id",
)


def event(**overrides) -> AccountingEvent:
    fields = {
        "event_type": AccountingEventType.LOGIN_SUCCESS,
        "outcome": AccountingOutcome.SUCCESS,
        "user_id": "ad:user@example.test",
        "auth_source": "ad",
        "session_label": "sess-0123456789abcdef",
        "timestamp": START,
    }
    fields.update(overrides)

    return AccountingEvent(**fields)


# --- the whitelist is structural -------------------------------------------


def test_every_declared_field_is_either_persisted_or_explicitly_excluded() -> None:
    """Adding a field to the model fails here until it is handled deliberately."""
    declared = {field.name for field in dataclasses.fields(AccountingEvent)}

    assert declared == PERSISTED_FIELDS | NOT_PERSISTED_FIELDS
    assert PERSISTED_FIELDS == set(event().to_record())


def test_the_serialized_record_has_exactly_the_pinned_keys() -> None:
    record = event().to_record()

    assert set(record) == PERSISTED_FIELDS
    assert len(record) == 17


def test_absent_values_are_serialized_as_none_not_omitted() -> None:
    """A stable shape is what makes a record's hash reproducible."""
    record = event().to_record()

    assert record["conversation_id"] is None
    assert record["duration_ms"] is None
    assert record["error_type"] is None


def test_the_enum_values_are_stored_not_the_objects() -> None:
    record = event(
        event_type=AccountingEventType.LOGIN_FAILURE,
        outcome=AccountingOutcome.DENIED,
        error_type=AccountingErrorType.BLOCKED,
    ).to_record()

    assert record["event_type"] == "login_failure"
    assert record["outcome"] == "denied"
    assert record["error_type"] == "blocked"
    assert json.dumps(record)  # serializable without a custom encoder


# --- each field has a grammar ----------------------------------------------


def test_the_application_shaped_values_are_accepted() -> None:
    """The grammars accept what the application actually produces."""
    record = event(
        conversation_id="3f2a1b0c-4d5e-6f70-8192-a3b4c5d6e7f8",
        langgraph_thread_id="thread-01",
        request_id="req-01",
        action_id="nmap_service_scan",
        target="192.0.2.64",
        proposal_signature="a" * 64,
        requester_user_id="ad:requester@example.test",
        approver_user_id="ad:approver@example.test",
    ).to_record()

    assert record["proposal_signature"] == "a" * 64
    assert record["requester_user_id"] != record["approver_user_id"]


@pytest.mark.parametrize("field_name", ["target", "action_id", "request_id"])
def test_an_address_or_identifier_shaped_value_is_accepted(field_name: str) -> None:
    assert event(**{field_name: "host-01.example.test"}).to_record()[field_name] == (
        "host-01.example.test"
    )


@pytest.mark.parametrize("hostile", REFUSED_BY_EVERY_FIELD)
@pytest.mark.parametrize("field_name", TEXT_FIELDS)
def test_credential_shaped_text_is_refused_by_every_field(
    field_name: str, hostile: str
) -> None:
    with pytest.raises(ValueError):
        event(**{field_name: hostile})


@pytest.mark.parametrize(
    "field_name",
    [
        "user_id",
        "requester_user_id",
        "approver_user_id",
        "auth_source",
        "session_label",
        "proposal_signature",
    ],
)
def test_a_plain_password_is_refused_by_the_identity_and_token_grammars(
    field_name: str,
) -> None:
    """A password has no colon, no ``sess-`` prefix and is not 64 hex characters."""
    with pytest.raises(ValueError):
        event(**{field_name: "correct-horse-battery-staple"})


def test_a_grammatically_valid_value_is_stored_and_that_is_the_stated_limit() -> None:
    """The honest limit: a password that looks exactly like a host name is not detectable.

    Nothing in the value can distinguish it, which is precisely why the control that
    matters is the emitter and not value inspection. ``test_webapp_accounting_events``
    asserts that the events the application really emits carry no credential.
    """
    assert event(target="correct-horse-battery-staple").target == (
        "correct-horse-battery-staple"
    )


@pytest.mark.parametrize(
    "value",
    ["line\nbreak", "carriage\rreturn", "nul\x00byte", "bell\x07", "delete\x7f"],
)
def test_control_characters_are_refused(value: str) -> None:
    with pytest.raises(ValueError) as caught:
        event(user_id=value)

    assert "control characters" in str(caught.value)


def test_a_value_at_the_field_grammar_bound_is_accepted() -> None:
    assert event(request_id="r" * 128).request_id == "r" * 128


@pytest.mark.parametrize("field_name", ["user_id", "target", "action_id"])
def test_a_non_string_text_field_is_refused(field_name: str) -> None:
    with pytest.raises(ValueError):
        event(**{field_name: 42})


def test_blank_text_becomes_absent_rather_than_empty() -> None:
    assert event(user_id="   ").user_id is None


# --- typing is enforced -----------------------------------------------------


@pytest.mark.parametrize("value", ["login_success", 1, None])
def test_an_untyped_event_type_is_refused(value: object) -> None:
    with pytest.raises(ValueError):
        event(event_type=value)


@pytest.mark.parametrize("value", ["success", 1, None])
def test_an_untyped_outcome_is_refused(value: object) -> None:
    with pytest.raises(ValueError):
        event(outcome=value)


def test_an_untyped_error_type_is_refused() -> None:
    """An exception string can never reach the record through this field."""
    with pytest.raises(ValueError):
        event(error_type="ValueError: could not bind to 192.0.2.15")


def test_an_arbitrary_exception_object_cannot_be_passed_as_an_error() -> None:
    with pytest.raises(ValueError):
        event(error_type=ValueError("bind failed"))


def test_no_arbitrary_mapping_can_be_attached() -> None:
    with pytest.raises(TypeError):
        AccountingEvent(  # type: ignore[call-arg]
            event_type=AccountingEventType.LOGIN_SUCCESS,
            outcome=AccountingOutcome.SUCCESS,
            safe_detail={"password": "hunter2"},
        )


@pytest.mark.parametrize("value", [-1, MAX_DURATION_MS + 1, True, "10", 1.5])
def test_an_invalid_duration_is_refused(value: object) -> None:
    with pytest.raises(ValueError):
        event(duration_ms=value)


def test_a_valid_duration_is_stored() -> None:
    assert event(duration_ms=1234).to_record()["duration_ms"] == 1234


def test_the_event_identifier_must_be_a_32_character_token() -> None:
    with pytest.raises(ValueError):
        event(event_id="short")

    assert len(event().event_id) == 32


def test_identifiers_are_unique_by_default() -> None:
    assert event().event_id != event().event_id


# --- timestamps -------------------------------------------------------------


def test_a_naive_timestamp_is_refused() -> None:
    with pytest.raises(ValueError):
        event(timestamp=datetime(2026, 10, 10, 22, 0))  # noqa: DTZ001 - the naive value is the point


def test_a_timestamp_is_normalized_to_utc() -> None:
    elsewhere = START.astimezone(timezone(timedelta(hours=5)))

    assert event(timestamp=elsewhere).timestamp == START
    assert event(timestamp=elsewhere).to_record()["timestamp"].endswith("+00:00")


def test_the_stored_timestamp_keeps_microsecond_precision() -> None:
    assert event().to_record()["timestamp"] == "2026-10-10T22:11:41.123456+00:00"


def test_the_default_timestamp_is_aware_and_current() -> None:
    fresh = AccountingEvent(
        event_type=AccountingEventType.LOGOUT, outcome=AccountingOutcome.SUCCESS
    )

    assert fresh.timestamp.tzinfo is not None
    assert abs((datetime.now(UTC) - fresh.timestamp).total_seconds()) < 5


# --- categories -------------------------------------------------------------


def test_every_event_type_belongs_to_exactly_one_category() -> None:
    for member in AccountingEventType:
        assert isinstance(member.category, AccountingEventCategory)

    assert event().category is AccountingEventCategory.AUTHENTICATION
    assert (
        AccountingEvent(
            event_type=AccountingEventType.APPROVAL_APPROVED,
            outcome=AccountingOutcome.SUCCESS,
        ).category
        is AccountingEventCategory.SECURITY_WORKFLOW
    )
    assert (
        AccountingEvent(
            event_type=AccountingEventType.BREAK_GLASS_USED,
            outcome=AccountingOutcome.SUCCESS,
        ).category
        is AccountingEventCategory.ADMINISTRATION
    )


def test_the_phase_4_event_set_is_complete() -> None:
    """The architecture's four areas are all represented, and P4-09 emits one of them."""
    expected = {
        "login_success",
        "login_failure",
        "logout",
        "web_session_created",
        "web_session_expired",
        "web_session_revoked",
        "conversation_created",
        "conversation_opened",
        "prompt_submitted",
        "conversation_closed",
        "tool_requested",
        "tool_completed",
        "proposal_created",
        "approval_approved",
        "approval_rejected",
        "approval_stale",
        "validation_started",
        "validation_completed",
        "session_held",
        "session_handoff",
        "session_closed",
        "auth_provider_status_check",
        "break_glass_used",
        "recovery_action",
        "operational_setting_changed",
    }

    assert {member.value for member in AccountingEventType} == expected


def test_requester_and_approver_are_separate_fields() -> None:
    """Kept apart even when they are the same person, for a future two-person rule."""
    record = event(
        event_type=AccountingEventType.APPROVAL_APPROVED,
        outcome=AccountingOutcome.SUCCESS,
        requester_user_id="ad:requester@example.test",
        approver_user_id="ad:approver@example.test",
    ).to_record()

    assert record["requester_user_id"] == "ad:requester@example.test"
    assert record["approver_user_id"] == "ad:approver@example.test"
