from dataclasses import dataclass
from typing import Any

from pentaia.approval import Phase3ActionProposal
from pentaia.findings import VulnerabilityFinding


@dataclass(frozen=True)
class ValidationRule:
    action_id: str
    cve: str
    parameters: dict[str, Any]
    expected_effect: str


@dataclass(frozen=True)
class ValidationCandidate:
    proposal: Phase3ActionProposal
    source_finding: VulnerabilityFinding

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal": self.proposal.to_dict(),
            "source_finding": self.source_finding.to_dict(),
        }


SUPPORTED_VALIDATION_RULES: tuple[ValidationRule, ...] = (
    ValidationRule(
        action_id="validate_vsftpd_234_backdoor",
        cve="CVE-2011-2523",
        parameters={"rport": 21},
        expected_effect="Run the predefined validation action for this supported finding on the explicitly authorized lab target.",
    ),
)


def _finding_reference(finding: VulnerabilityFinding) -> str:
    parts = [
        f"scanner={finding.source_tool}",
        f"template={finding.template_id or 'not-provided'}",
        f"title={finding.title}",
        f"severity={finding.severity}",
        f"target={finding.target}",
        f"port={finding.port if finding.port is not None else 'not-provided'}",
        f"service={finding.service or 'not-provided'}",
    ]

    if finding.cve:
        parts.append(f"cve={','.join(finding.cve)}")
    if finding.cvss is not None:
        parts.append(f"cvss={finding.cvss}")
    if finding.matched_at:
        parts.append(f"matched_at={finding.matched_at}")

    return "; ".join(parts)


def map_finding_to_validation(finding: VulnerabilityFinding) -> ValidationCandidate | None:
    """Map a normalized finding to a supported Phase 3 proposal without executing it."""
    finding_cves = {cve.upper() for cve in finding.cve}

    for rule in SUPPORTED_VALIDATION_RULES:
        if rule.cve not in finding_cves:
            continue

        proposal = Phase3ActionProposal(
            action_id=rule.action_id,
            target=finding.target,
            rationale=(
                f"Confirmed Phase 2 finding matched supported validation rule {rule.cve}. "
                f"Original evidence: {_finding_reference(finding)}. "
                f"Evidence detail: {finding.evidence}"
            ),
            expected_effect=rule.expected_effect,
            parameters=dict(rule.parameters),
        )

        return ValidationCandidate(proposal=proposal, source_finding=finding)

    return None


def map_findings_to_validations(findings: list[VulnerabilityFinding]) -> list[ValidationCandidate]:
    candidates: list[ValidationCandidate] = []
    for finding in findings:
        candidate = map_finding_to_validation(finding)
        if candidate is not None:
            candidates.append(candidate)
    return candidates
