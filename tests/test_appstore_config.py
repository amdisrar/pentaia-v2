"""Application store configuration and its explicit durable-operation policy.

The policy under test: memory storage remains the default so development and the
existing suite are unaffected, and the durable mode cannot be entered by accident —
asking for it without a data directory is a configuration error, and an unrecognised
mode is refused rather than silently downgraded to memory.
"""

from pathlib import Path

import pytest

from pentaia.appstore.config import (
    BUSY_TIMEOUT_ENV,
    DATA_DIR_ENV,
    DEFAULT_BUSY_TIMEOUT_MS,
    DEFAULT_STORE_MODE,
    STORE_MODE_ENV,
    StoreConfig,
    load_store_config,
    validate_busy_timeout,
    validate_data_dir,
    validate_store_mode,
)
from pentaia.appstore.errors import StoreConfigurationError

# --- defaults and the explicit mode ----------------------------------------


def test_memory_is_the_default_mode() -> None:
    config = load_store_config({})

    assert config.mode == DEFAULT_STORE_MODE == "memory"
    assert config.data_dir is None
    assert config.busy_timeout_ms == DEFAULT_BUSY_TIMEOUT_MS
    assert config.durable is False
    assert config.database_path is None


@pytest.mark.parametrize("value", ["memory", "MEMORY", "  Memory  ", ""])
def test_the_memory_mode_is_accepted_in_any_spelling(value: str) -> None:
    assert load_store_config({STORE_MODE_ENV: value}).mode == "memory"


def test_the_durable_mode_requires_a_data_directory() -> None:
    """The operational mode has no implicit location: without one it is refused."""
    with pytest.raises(StoreConfigurationError) as caught:
        load_store_config({STORE_MODE_ENV: "sqlite"})

    message = str(caught.value)
    assert DATA_DIR_ENV in message
    assert STORE_MODE_ENV in message


def test_the_durable_mode_resolves_the_database_path() -> None:
    config = load_store_config({STORE_MODE_ENV: "sqlite", DATA_DIR_ENV: "/tmp/pentaia-store"})

    assert config.durable is True
    assert config.data_dir == Path("/tmp/pentaia-store")
    assert config.database_path == Path("/tmp/pentaia-store/pentaia.db")


@pytest.mark.parametrize("value", ["postgres", "SQLITE3", "file", "true", 1, None, ["sqlite"]])
def test_an_unrecognised_mode_is_refused(value: object) -> None:
    """Falling back to memory would lose sessions and audit records without saying so."""
    with pytest.raises(StoreConfigurationError) as caught:
        validate_store_mode(value)

    assert STORE_MODE_ENV in str(caught.value)


def test_a_blank_mode_falls_back_to_the_documented_default() -> None:
    """Blank means unset, and unset means the documented default rather than an error."""
    assert validate_store_mode("   ") == "memory"


# --- the data directory -----------------------------------------------------


@pytest.mark.parametrize("value", [None, "", "   "])
def test_a_blank_data_directory_means_unset(value: object) -> None:
    assert validate_data_dir(value) is None


def test_a_data_directory_is_expanded_and_kept_as_a_path() -> None:
    resolved = validate_data_dir("~/pentaia-data")

    assert isinstance(resolved, Path)
    assert resolved == Path("~/pentaia-data").expanduser()
    assert validate_data_dir(Path("/tmp/direct")) == Path("/tmp/direct")


@pytest.mark.parametrize("value", [42, ["/tmp/x"], {"dir": "/tmp/x"}])
def test_a_non_path_data_directory_is_refused(value: object) -> None:
    with pytest.raises(StoreConfigurationError):
        validate_data_dir(value)


def test_a_data_directory_containing_a_nul_is_refused() -> None:
    with pytest.raises(StoreConfigurationError):
        validate_data_dir("/tmp/evil\x00name")


# --- the busy timeout -------------------------------------------------------


@pytest.mark.parametrize(("value", "expected"), [(5000, 5000), ("2500", 2500), (750, 750)])
def test_a_busy_timeout_is_accepted(value: object, expected: int) -> None:
    assert validate_busy_timeout(value) == expected


@pytest.mark.parametrize("value", [0, 99, 60_001, -1, True, "soon", 1.5, None])
def test_an_invalid_busy_timeout_is_refused(value: object) -> None:
    with pytest.raises(StoreConfigurationError) as caught:
        validate_busy_timeout(value)

    assert BUSY_TIMEOUT_ENV in str(caught.value)


def test_the_configured_timeouts_are_read_from_the_environment() -> None:
    config = load_store_config(
        {STORE_MODE_ENV: "sqlite", DATA_DIR_ENV: "/tmp/store", BUSY_TIMEOUT_ENV: "1234"}
    )

    assert config.busy_timeout_ms == 1234


def test_a_configuration_built_directly_is_validated_too() -> None:
    """Embedding code and tests construct this object directly, so it validates itself."""
    with pytest.raises(StoreConfigurationError):
        StoreConfig(mode="sqlite")

    with pytest.raises(StoreConfigurationError):
        StoreConfig(mode="unknown")
