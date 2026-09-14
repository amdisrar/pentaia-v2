"""Typed, allowlisted discovery parameters shared by the discovery wrappers.

PentAiA exposes semantic, typed parameters to the model and translates them into
code-owned native options. The model never supplies command-line syntax: there is
no ``extra_args``, ``raw_options``, ``command`` or ``native_flags`` field anywhere.

Every parameter a tool exposes is classified by who owns it:

- ``model``   -- the model may select it from an explicit allowlist or a bounded range.
- ``runtime`` -- PentAiA resolves it from deployment configuration.
- ``code``    -- fixed by the wrapper and never selectable.

A test asserts that the parameters a tool actually exposes match the ``model``
entries registered here, so an unclassified parameter cannot ship unnoticed.
"""

from dataclasses import dataclass
from typing import Literal

ParameterOwnership = Literal["model", "runtime", "code"]

# An upper bound on how many ports the model may name in one request, so a
# "bounded port selection" cannot become an unbounded scan specification.
MAX_SELECTABLE_PORTS = 64


@dataclass(frozen=True)
class DiscoveryParameter:
    """One parameter of a discovery tool, with its ownership classification."""

    name: str
    ownership: ParameterOwnership
    description: str


@dataclass(frozen=True)
class NmapProfile:
    """A code-owned mapping from a semantic profile to native options."""

    name: str
    description: str
    options: tuple[str, ...]
    allows_ports: bool = False


# The only Nmap options PentAiA will ever emit. A profile name that does not
# appear here is rejected, so no model-supplied option text can reach the command.
NMAP_PROFILES: dict[str, NmapProfile] = {
    "service": NmapProfile(
        name="service",
        description="Service and version identification of the most common TCP ports.",
        options=("-sV",),
        allows_ports=True,
    ),
    "quick": NmapProfile(
        name="quick",
        description="Faster scan limited to the most common TCP ports.",
        options=("-T4", "-F"),
        allows_ports=True,
    ),
    "full_tcp": NmapProfile(
        name="full_tcp",
        description="Every TCP port of the target.",
        options=("-p-",),
        allows_ports=False,
    ),
    "os": NmapProfile(
        name="os",
        description=(
            "Operating-system identification. Requires raw-socket privileges on "
            "the Kali host, so it fails cleanly when the execution account lacks them."
        ),
        options=("-O",),
        allows_ports=False,
    ),
}

NMAP_DEFAULT_PROFILE = "service"

NmapProfileName = Literal["service", "quick", "full_tcp", "os"]

NMAP_TIMEOUT_SECONDS = 120


def validate_nmap_profile(value: object) -> NmapProfile:
    """Return the code-owned profile for a model-selected name, or fail closed."""
    if not isinstance(value, str) or value not in NMAP_PROFILES:
        allowed = ", ".join(sorted(NMAP_PROFILES))
        raise ValueError(
            f"Unsupported Nmap profile: {value!r}. Allowed profiles: {allowed}."
        )

    return NMAP_PROFILES[value]


def _is_port_number(value: object) -> bool:
    """True only for a genuine integer port, never a bool."""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_list(value: object) -> bool:
    """True only for a list, so a port selection is never silently coerced."""
    return isinstance(value, list)


def validate_nmap_ports(value: object) -> list[int]:
    """Validate a bounded, de-duplicated, sorted port selection."""
    if value is None:
        return []

    if not _is_list(value):
        raise ValueError("Nmap ports must be a list of TCP port numbers.")

    if not value:
        return []

    if len(value) > MAX_SELECTABLE_PORTS:
        raise ValueError(
            f"At most {MAX_SELECTABLE_PORTS} ports may be selected in one scan."
        )

    ports: list[int] = []

    for item in value:
        if not _is_port_number(item):
            raise ValueError("Every Nmap port must be an integer.")

        if not 1 <= item <= 65535:
            raise ValueError("Every Nmap port must be between 1 and 65535.")

        if item not in ports:
            ports.append(item)

    return sorted(ports)


def build_nmap_options(profile: NmapProfile, ports: list[int]) -> list[str]:
    """Translate a validated profile and port selection into native options."""
    if ports and not profile.allows_ports:
        raise ValueError(
            f"Nmap profile {profile.name!r} does not accept a port selection."
        )

    options = list(profile.options)

    if ports:
        options += ["-p", ",".join(str(port) for port in ports)]

    return options


# ---------------------------------------------------------------------------
# Parameter ownership registries
# ---------------------------------------------------------------------------
#
# These describe the full parameter surface of each discovery tool, including the
# values PentAiA owns itself. Only the ``model`` entries may appear in a tool
# schema, and a test enforces exactly that.

NMAP_PARAMETERS: tuple[DiscoveryParameter, ...] = (
    DiscoveryParameter(
        "target",
        "model",
        "One IPv4 lab target, validated against the target policy before use.",
    ),
    DiscoveryParameter(
        "profile",
        "model",
        "One allowlisted scan profile, mapped to code-owned native options.",
    ),
    DiscoveryParameter(
        "ports",
        "model",
        "Bounded TCP port selection, accepted only by profiles that allow it.",
    ),
    DiscoveryParameter("timeout", "runtime", "Execution timeout owned by the wrapper."),
    DiscoveryParameter("binary", "code", "The nmap executable and its fixed options."),
)

NUCLEI_PARAMETERS: tuple[DiscoveryParameter, ...] = (
    DiscoveryParameter(
        "target",
        "model",
        "One IPv4 address or validated http/https URL.",
    ),
    DiscoveryParameter(
        "severities",
        "model",
        "Allowlisted Nuclei severity filter.",
    ),
    DiscoveryParameter("timeout", "runtime", "Execution timeout owned by the wrapper."),
    DiscoveryParameter(
        "binary",
        "code",
        "The nuclei executable and its fixed options.",
    ),
)


def model_parameter_names(
    registry: tuple[DiscoveryParameter, ...],
) -> set[str]:
    """Return the parameters of a registry that the model is allowed to supply."""
    return {
        parameter.name for parameter in registry if parameter.ownership == "model"
    }
