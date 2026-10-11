"""Application store configuration.

Framework-independent on purpose. The store is used by the web application and, from
P4-14, by the local ``pentaia-admin`` utility, so this module imports nothing from
``pentaia.webapp`` and nothing from FastAPI.

The operational policy is deliberately explicit rather than implicit:

* ``PENTAIA_STORE_MODE=memory`` (the default) keeps the pre-P4-09 behaviour: sessions,
  throttling and accounting live in the process and are lost on restart. It is the
  development and test mode, and it is logged loudly at startup.
* ``PENTAIA_STORE_MODE=sqlite`` is the operational mode. It **requires**
  ``PENTAIA_DATA_DIR``; without it the configuration is refused at load time, so an
  operational deployment cannot accidentally run without its durable store.

Choosing the durable mode is a decision an operator makes, not something a default
grants. Accounting events that a security-critical operation marks as *required* fail
closed in either mode when they cannot be committed, so the memory mode cannot be used
to skip accounting on a path that demands it.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from pentaia.appstore.errors import StoreConfigurationError

STORE_MODE_ENV = "PENTAIA_STORE_MODE"
DATA_DIR_ENV = "PENTAIA_DATA_DIR"
BUSY_TIMEOUT_ENV = "PENTAIA_DB_BUSY_TIMEOUT_MS"

STORE_MODE_MEMORY = "memory"
STORE_MODE_SQLITE = "sqlite"
SUPPORTED_STORE_MODES = (STORE_MODE_MEMORY, STORE_MODE_SQLITE)
DEFAULT_STORE_MODE = STORE_MODE_MEMORY

DEFAULT_BUSY_TIMEOUT_MS = 5_000
MIN_BUSY_TIMEOUT_MS = 100
MAX_BUSY_TIMEOUT_MS = 60_000

#: Single fixed filename. The operator chooses the directory, never the file, so a
#: configuration value can never point the store at an arbitrary path.
DATABASE_FILENAME = "pentaia.db"

#: Directory mode and file mode applied to everything the store creates. SQLite honours
#: the process umask, so permissions are set explicitly rather than assumed.
DIRECTORY_MODE = 0o700
FILE_MODE = 0o600


@dataclass(frozen=True)
class StoreConfig:
    """Resolved application-store configuration."""

    mode: str = DEFAULT_STORE_MODE
    #: Directory holding the database, or ``None`` in memory mode.
    data_dir: Path | None = None
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS

    def __post_init__(self) -> None:
        mode = validate_store_mode(self.mode)
        object.__setattr__(self, "mode", mode)

        configured = validate_data_dir(self.data_dir)

        if mode == STORE_MODE_SQLITE and configured is None:
            raise StoreConfigurationError(
                f"{DATA_DIR_ENV} is required when {STORE_MODE_ENV}={STORE_MODE_SQLITE}: "
                "the durable store has no default location."
            )

        object.__setattr__(self, "data_dir", configured)
        object.__setattr__(
            self,
            "busy_timeout_ms",
            validate_busy_timeout(self.busy_timeout_ms),
        )

    @property
    def durable(self) -> bool:
        """True when the deployment asked for the durable SQLite store."""
        return self.mode == STORE_MODE_SQLITE

    @property
    def database_path(self) -> Path | None:
        """Full path of the database file, or ``None`` in memory mode."""
        if self.data_dir is None:
            return None

        return self.data_dir / DATABASE_FILENAME


def _read(environ: Mapping[str, str], name: str, default: str) -> str:
    """Read one setting, defaulting only when it is genuinely absent."""
    value = environ.get(name)

    return default if value is None else value


def validate_store_mode(value: object) -> str:
    """Validate the store mode.

    An unrecognised value is refused rather than defaulted: silently running in memory
    mode when a deployment asked for durability would lose sessions and audit records
    without saying so.
    """
    if not isinstance(value, str):
        raise StoreConfigurationError(
            f"{STORE_MODE_ENV} must be one of: {', '.join(SUPPORTED_STORE_MODES)}."
        )

    candidate = value.strip().lower()

    if not candidate:
        return DEFAULT_STORE_MODE

    if candidate not in SUPPORTED_STORE_MODES:
        raise StoreConfigurationError(
            f"{STORE_MODE_ENV} must be one of: {', '.join(SUPPORTED_STORE_MODES)} "
            f"(got {candidate!r})."
        )

    return candidate


def validate_data_dir(value: object) -> Path | None:
    """Validate the data-directory setting, returning ``None`` when unset.

    Only the shape is validated here. Creating the directory, applying permissions and
    checking writability happen in :mod:`pentaia.appstore.connection`, so configuration
    validation stays free of side effects.
    """
    if value is None:
        return None

    if isinstance(value, Path):
        candidate = value
    elif isinstance(value, str):
        if not value.strip():
            return None

        candidate = Path(value.strip())
    else:
        raise StoreConfigurationError(
            f"{DATA_DIR_ENV} must be a filesystem directory path."
        )

    if "\x00" in str(candidate):
        raise StoreConfigurationError(
            f"{DATA_DIR_ENV} must be a filesystem directory path."
        )

    return candidate.expanduser()


def validate_busy_timeout(value: object) -> int:
    """Validate the SQLite busy timeout, in milliseconds."""
    candidate = value

    if isinstance(candidate, str):
        stripped = candidate.strip()

        if not stripped.isdigit():
            raise StoreConfigurationError(
                f"{BUSY_TIMEOUT_ENV} must be a whole number of milliseconds."
            )

        candidate = int(stripped)

    if not isinstance(candidate, int) or isinstance(candidate, bool):
        raise StoreConfigurationError(
            f"{BUSY_TIMEOUT_ENV} must be a whole number of milliseconds."
        )

    if not MIN_BUSY_TIMEOUT_MS <= candidate <= MAX_BUSY_TIMEOUT_MS:
        raise StoreConfigurationError(
            f"{BUSY_TIMEOUT_ENV} must be between {MIN_BUSY_TIMEOUT_MS} and "
            f"{MAX_BUSY_TIMEOUT_MS} milliseconds."
        )

    return candidate


def load_store_config(environ: Mapping[str, str] | None = None) -> StoreConfig:
    """Load the store configuration from the environment.

    Passing ``environ`` reads only that mapping, which keeps tests hermetic.
    """
    source: Mapping[str, str] = os.environ if environ is None else environ

    return StoreConfig(
        mode=validate_store_mode(_read(source, STORE_MODE_ENV, DEFAULT_STORE_MODE)),
        data_dir=validate_data_dir(_read(source, DATA_DIR_ENV, "")),
        busy_timeout_ms=validate_busy_timeout(
            _read(source, BUSY_TIMEOUT_ENV, str(DEFAULT_BUSY_TIMEOUT_MS))
        ),
    )
