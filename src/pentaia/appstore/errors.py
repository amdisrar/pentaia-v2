"""Application store exceptions.

Separate from any framework and from the web layer: the store is used by the web
application today and by the local ``pentaia-admin`` utility later, so its failures must
be expressible without importing FastAPI.

Every one of these is deliberately a *fail-closed* signal. None of them is ever handled
by silently recreating, deleting or ignoring the database.
"""


class StoreError(RuntimeError):
    """Base class for application-store failures."""


class StoreUnavailable(StoreError):
    """The store could not be opened, read or written.

    Raised for a missing or unwritable data directory, a database that fails its
    integrity check, a closed handle, and lock or disk failures that outlast the
    configured busy timeout.
    """


class StoreConfigurationError(StoreError):
    """The store configuration is unusable and the application must not start."""


class SchemaTooNew(StoreError):
    """The database was written by a newer schema than this code understands.

    Refusing is the only safe answer: an older build cannot know what the extra
    migrations changed, and downgrading in place risks corrupting recorded state.
    """


class MigrationFailed(StoreError):
    """A migration did not complete. The database is left at its previous version."""


class AccountingUnavailable(StoreError):
    """A required accounting event could not be committed.

    Callers that are about to perform a security-significant state change must treat this
    as a refusal, not as a warning: the architecture requires that a state-changing
    approval or execution must not proceed when its accountable record cannot be stored.
    """
