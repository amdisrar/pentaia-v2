"""Deterministic post-discovery lookup of supported Phase 3 validation candidates.

Phase 2 discovery returns normalized findings to the model as a tool result. This
module turns those findings back into structured objects and asks the code-owned
Test Framework whether any of them maps to a supported validation action.

The decision is deterministic and code-owned: the model never decides whether a
supported validation exists. The result is context for the model to explain and
recommend from, never an execution path. An unsupported finding yields no
candidate, and therefore no proposed action.

Nothing here executes anything, and nothing here is exposed to Gemini as a tool.
"""

import logging

from langchain_core.messages import BaseMessage, ToolMessage

from pentaia.findings import VulnerabilityFinding, findings_from_json
from pentaia.validation_mapping import (
    ValidationCandidate,
    finding_reference,
    map_findings_to_validations,
)

logger = logging.getLogger(__name__)

DISCOVERY_TOOL_NAME = "nuclei_vulnerability_scan"

_NO_FINDINGS_MARKER = "returned no vulnerability findings"


def _unusable_reason(content: object) -> str:
    """Classify why a discovery result could not be used, without logging its text.

    The raw result is never logged: dedicated audit events deliberately exclude
    scanner output. A short classification is enough to tell an empty scan apart
    from an execution failure.
    """
    if not isinstance(content, str) or not content.strip():
        return "empty"

    if _NO_FINDINGS_MARKER in content:
        return "no-findings"

    if content.lstrip().startswith(("[", "{")):
        return "unparseable-json"

    return "error-output"


def findings_from_tool_messages(
    messages: list[BaseMessage],
) -> list[VulnerabilityFinding]:
    """Recover normalized findings from the most recent discovery tool result.

    Only the latest discovery result is used, because a later scan supersedes an
    earlier one. An unusable result -- an execution error, no findings, or
    unparseable output -- yields no findings: a discovery problem must never
    escalate into a proposed validation action.
    """
    for message in reversed(messages):
        if not isinstance(message, ToolMessage):
            continue

        if message.name != DISCOVERY_TOOL_NAME:
            continue

        try:
            return findings_from_json(message.content)
        except ValueError:
            logger.info(
                "Phase 3 candidate lookup skipped an unusable discovery result tool=%s reason=%s",
                DISCOVERY_TOOL_NAME,
                _unusable_reason(message.content),
            )
            return []

    return []


def candidates_from_messages(
    messages: list[BaseMessage],
) -> list[ValidationCandidate]:
    """Return the code-owned validation candidates supported by this discovery run."""
    return map_findings_to_validations(findings_from_tool_messages(messages))


def candidate_context(candidates: list[ValidationCandidate]) -> str | None:
    """Render the code-owned candidate context shown to the model, if any."""
    if not candidates:
        return None

    lines = ["Code-owned Test Framework lookup for the latest discovery run:", ""]

    for index, candidate in enumerate(candidates, start=1):
        proposal = candidate.proposal

        lines.append(f"Candidate {index}")
        lines.append(f"  action_id: {proposal.action_id}")
        lines.append(f"  target: {proposal.target}")

        for key in sorted(proposal.parameters):
            lines.append(f"  parameter {key} = {proposal.parameters[key]}")

        lines.append(
            "  matched_cve: "
            + (", ".join(candidate.source_finding.cve) or "not-provided")
        )
        lines.append(f"  evidence: {finding_reference(candidate.source_finding)}")
        lines.append("")

    lines.extend(
        [
            "These are the only validation actions PentAiA supports for these findings.",
            "To validate, call phase3_controlled_validation with exactly these details.",
            "PentAiA pauses for explicit human approval before anything state-changing runs.",
            "Never invent another action, module, or payload.",
            "If no candidate is listed, report the findings only and propose no validation.",
        ]
    )

    return "\n".join(lines)
