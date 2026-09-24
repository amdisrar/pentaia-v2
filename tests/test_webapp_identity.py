"""P4-04 authenticated identity model."""

import dataclasses
from datetime import UTC, datetime, timedelta, timezone

import pytest

from pentaia.webapp.identity import (
    AUTH_SOURCE_AD,
    AUTH_SOURCE_RADIUS,
    MAX_AUTH_SOURCE_LENGTH,
    MAX_DISPLAY_NAME_LENGTH,
    MAX_USERNAME_LENGTH,
    AuthenticatedIdentity,
    build_user_id,
    normalize_username,
    validate_auth_source,
)

# --- normalization ---------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("User@Example.com", "user@example.com"),
        ("  USER@EXAMPLE.COM  ", "user@example.com"),
        ("John.Doe", "john.doe"),
        ("svc-pentaia", "svc-pentaia"),
        ("user+tag@example.com", "user+tag@example.com"),
    ],
)
def test_username_normalization_lower_cases_and_trims(raw: str, expected: str) -> None:
    assert normalize_username(raw) == expected


@pytest.mark.parametrize("value", ["", "   ", None, 5, ["user"]])
def test_an_empty_or_non_string_username_is_rejected(value: object) -> None:
    with pytest.raises(ValueError):
        normalize_username(value)


@pytest.mark.parametrize(
    "value",
    [
        "user:name",  # would make the user_id key ambiguous
        "user name",  # whitespace would forge log lines
        "user\nname",
        "user\tname",
        "user\x00name",
        "user\x7fname",
    ],
)
def test_a_username_that_could_forge_a_key_or_a_log_line_is_rejected(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_username(value)


def test_an_over_long_username_is_rejected() -> None:
    with pytest.raises(ValueError):
        normalize_username("u" * (MAX_USERNAME_LENGTH + 1))

    assert normalize_username("u" * MAX_USERNAME_LENGTH)


# --- auth source -----------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ad", AUTH_SOURCE_AD),
        ("AD", AUTH_SOURCE_AD),
        ("  Ad  ", AUTH_SOURCE_AD),
        ("radius", AUTH_SOURCE_RADIUS),
        ("RADIUS", AUTH_SOURCE_RADIUS),
        ("custom-provider", "custom-provider"),
    ],
)
def test_auth_source_is_normalized(raw: str, expected: str) -> None:
    assert validate_auth_source(raw) == expected


@pytest.mark.parametrize(
    "value",
    ["", "   ", None, 7, "1ad", "ad source", "ad:radius", "a" * (MAX_AUTH_SOURCE_LENGTH + 1), "-ad"],
)
def test_an_invalid_auth_source_is_rejected(value: object) -> None:
    with pytest.raises(ValueError):
        validate_auth_source(value)


def test_the_provider_key_is_validated_by_shape_not_membership() -> None:
    """A new provider must not require editing this model (P4-05/P4-06 own naming)."""
    assert validate_auth_source("ldap") == "ldap"


# --- user id ---------------------------------------------------------------


def test_user_id_is_provider_scoped_and_normalized() -> None:
    assert build_user_id(auth_source="AD", username="User@Example.com") == "ad:user@example.com"


def test_the_same_username_under_different_providers_is_a_different_identity() -> None:
    ad = build_user_id(auth_source="ad", username="user@example.com")
    radius = build_user_id(auth_source="radius", username="user@example.com")

    assert ad != radius
    assert ad == "ad:user@example.com"
    assert radius == "radius:user@example.com"


def test_build_user_id_validates_both_halves() -> None:
    with pytest.raises(ValueError):
        build_user_id(auth_source="ad", username="bad:name")

    with pytest.raises(ValueError):
        build_user_id(auth_source="AD SOURCE", username="user")


# --- identity construction -------------------------------------------------


def test_from_provider_normalizes_and_defaults_the_display_name() -> None:
    identity = AuthenticatedIdentity.from_provider(
        auth_source="AD", username="User@Example.com"
    )

    assert identity.user_id == "ad:user@example.com"
    assert identity.username == "user@example.com"
    assert identity.display_name == "user@example.com"
    assert identity.auth_source == "ad"


def test_a_provided_display_name_is_used_and_trimmed() -> None:
    identity = AuthenticatedIdentity.from_provider(
        auth_source="radius",
        username="user@example.com",
        display_name="  Example User  ",
    )

    assert identity.display_name == "Example User"


@pytest.mark.parametrize("blank", ["", "   ", None])
def test_a_blank_display_name_falls_back_to_the_username(blank: object) -> None:
    identity = AuthenticatedIdentity.from_provider(
        auth_source="ad", username="user@example.com", display_name=blank
    )

    assert identity.display_name == "user@example.com"


def test_authenticated_at_defaults_to_now_in_utc() -> None:
    before = datetime.now(UTC)
    identity = AuthenticatedIdentity.from_provider(auth_source="ad", username="user")
    after = datetime.now(UTC)

    assert identity.authenticated_at.tzinfo is not None
    assert before <= identity.authenticated_at <= after


def test_a_non_utc_timestamp_is_converted_and_a_naive_one_is_rejected() -> None:
    moment = datetime(2026, 9, 24, 12, 0, tzinfo=timezone(timedelta(hours=4)))
    identity = AuthenticatedIdentity.from_provider(
        auth_source="ad", username="user", authenticated_at=moment
    )

    assert identity.authenticated_at == datetime(2026, 9, 24, 8, 0, tzinfo=UTC)

    with pytest.raises(ValueError, match="timezone-aware"):
        # A naive timestamp is the subject of this test, not an accident.
        naive = datetime(2026, 9, 24, 12, 0)  # noqa: DTZ001
        AuthenticatedIdentity.from_provider(
            auth_source="ad",
            username="user",
            authenticated_at=naive,
        )


def test_an_inconsistent_user_id_cannot_be_constructed_directly() -> None:
    """The key must always match the provider-scoped username."""
    with pytest.raises(ValueError, match="user_id must be"):
        AuthenticatedIdentity(
            user_id="ad:someone-else",
            username="user@example.com",
            display_name="User",
            auth_source="ad",
            authenticated_at=datetime.now(UTC),
        )


def test_direct_construction_rejects_unnormalized_halves() -> None:
    with pytest.raises(ValueError, match="normalized"):
        AuthenticatedIdentity(
            user_id="ad:user",
            username="user",
            display_name="User",
            auth_source="AD",
            authenticated_at=datetime.now(UTC),
        )


def test_an_over_long_display_name_is_rejected() -> None:
    with pytest.raises(ValueError):
        AuthenticatedIdentity.from_provider(
            auth_source="ad", username="user", display_name="d" * (MAX_DISPLAY_NAME_LENGTH + 1)
        )

    assert AuthenticatedIdentity.from_provider(
        auth_source="ad", username="user", display_name="d" * MAX_DISPLAY_NAME_LENGTH
    ).display_name


def test_the_identity_is_frozen() -> None:
    identity = AuthenticatedIdentity.from_provider(auth_source="ad", username="user")

    with pytest.raises(dataclasses.FrozenInstanceError):
        identity.user_id = "ad:other"  # type: ignore[misc]


def test_the_identity_carries_no_credential_field() -> None:
    """Pinning the field set is the point: a secret cannot be added unnoticed."""
    fields = {field.name for field in dataclasses.fields(AuthenticatedIdentity)}

    assert fields == {"user_id", "username", "display_name", "auth_source", "authenticated_at"}

    for forbidden in ("password", "token", "secret", "credential", "assertion", "session"):
        assert not [name for name in fields if forbidden in name]
