import logging
import os

from pentaia.validation import validate_ipv4

logger = logging.getLogger(__name__)

DEFAULT_PHASE3_PROTECTED_TARGETS = {"172.16.0.1"}


def _parse_ipv4_set(raw_value: str, *, variable_name: str) -> set[str]:
    values: set[str] = set()

    for item in raw_value.split(","):
        candidate = item.strip()
        if not candidate:
            continue

        try:
            values.add(validate_ipv4(candidate))
        except ValueError as exc:
            raise ValueError(
                f"Invalid IPv4 address in {variable_name}: {candidate}"
            ) from exc

    return values


def get_phase3_allowlist() -> set[str]:
    return _parse_ipv4_set(
        os.getenv("PENTAIA_PHASE3_ALLOWLIST", ""),
        variable_name="PENTAIA_PHASE3_ALLOWLIST",
    )


def get_phase3_protected_targets() -> set[str]:
    configured = _parse_ipv4_set(
        os.getenv("PENTAIA_PHASE3_DENYLIST", ""),
        variable_name="PENTAIA_PHASE3_DENYLIST",
    )

    return DEFAULT_PHASE3_PROTECTED_TARGETS | configured


def authorize_phase3_target(target: str) -> str:
    """Validate and authorize one IPv4 target for a Phase 3 action.

    Phase 3 is fail-closed: a target must be explicitly present in
    PENTAIA_PHASE3_ALLOWLIST and must not be protected or denylisted.
    """
    validated_target = validate_ipv4(target.strip())
    protected_targets = get_phase3_protected_targets()

    if validated_target in protected_targets:
        logger.warning(
            "Phase 3 authorization denied target=%s reason=protected_target",
            validated_target,
        )
        raise ValueError(
            f"Phase 3 actions are blocked for protected target: {validated_target}"
        )

    allowlist = get_phase3_allowlist()

    if validated_target not in allowlist:
        logger.warning(
            "Phase 3 authorization denied target=%s reason=not_allowlisted",
            validated_target,
        )
        raise ValueError(
            f"Phase 3 target is not explicitly authorized: {validated_target}"
        )

    logger.info(
        "Phase 3 authorization approved target=%s",
        validated_target,
    )

    return validated_target
