"""Phase 4 application store: durable sessions, login throttling and accounting.

A framework-independent package. The web application uses it, and from P4-14 the local
``pentaia-admin`` utility will too, so nothing here imports ``pentaia.webapp`` or
FastAPI. That independence is not stylistic: the architecture requires a state-changing
Phase 3 approval to fail closed when its accountable record cannot be committed, and
Phase 3 code is forbidden from importing the web layer, so the accounting contract has
to live outside it.

Layout:

* ``config`` — ``PENTAIA_STORE_MODE``/``PENTAIA_DATA_DIR``/busy timeout, validated.
* ``connection`` — one locked connection, explicit and re-entrant transactions,
  owner-only permissions, integrity checking, clean shutdown.
* ``migrations`` — genuinely transactional, versioned schema migrations.
* ``accounting`` — the typed event model and its whitelist serialization.
* ``integrity`` — canonical bytes and the SHA-256 hash chain.
* ``repository`` — the accounting repository contract and its SQLite implementation.
* ``recorder`` — the interface security-critical callers use, with required/optional
  semantics.
"""

from pentaia.appstore.config import (
    StoreConfig,
    load_store_config,
    validate_busy_timeout,
    validate_data_dir,
    validate_store_mode,
)
from pentaia.appstore.errors import (
    AccountingUnavailable,
    MigrationFailed,
    SchemaTooNew,
    StoreConfigurationError,
    StoreError,
    StoreUnavailable,
)

__all__ = [
    "AccountingUnavailable",
    "MigrationFailed",
    "SchemaTooNew",
    "StoreConfig",
    "StoreConfigurationError",
    "StoreError",
    "StoreUnavailable",
    "load_store_config",
    "validate_busy_timeout",
    "validate_data_dir",
    "validate_store_mode",
]
