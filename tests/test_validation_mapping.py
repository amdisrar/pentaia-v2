from pentaia.findings import VulnerabilityFinding
from pentaia.validation_mapping import (
    map_finding_to_validation,
    map_findings_to_validations,
)


def make_finding(**overrides):
    values = {
        "target": "172.16.0.64",
        "port": 6200,
        "protocol": "tcp",
        "service": None,
        "template_id": "vsftpd-backdoor",
        "title": "VSFTPD 2.3.4 Backdoor Command Execution",
        "severity": "critical",
        "cve": ["CVE-2011-2523"],
        "cvss": 9.8,
        "matched_at": "172.16.0.64:6200",
        "evidence": "Matched at 172.16.0.64:6200.",
        "source_tool": "nuclei",
    }
    values.update(overrides)
    return VulnerabilityFinding(**values)


def test_supported_finding_maps_to_predefined_action() -> None:
    candidate = map_finding_to_validation(make_finding())

    assert candidate is not None
    assert candidate.proposal.action_id == "validate_vsftpd_234_backdoor"
    assert candidate.proposal.target == "172.16.0.64"
    assert candidate.proposal.parameters == {"rport": 21}


def test_candidate_preserves_original_finding_context() -> None:
    finding = make_finding()
    candidate = map_finding_to_validation(finding)

    assert candidate is not None
    assert candidate.source_finding == finding
    payload = candidate.to_dict()
    assert payload["source_finding"]["cve"] == ["CVE-2011-2523"]
    assert payload["source_finding"]["port"] == 6200
    assert payload["source_finding"]["matched_at"] == "172.16.0.64:6200"
    assert payload["source_finding"]["evidence"] == finding.evidence


def test_mapping_rationale_is_traceable_to_scanner_evidence() -> None:
    candidate = map_finding_to_validation(make_finding())

    assert candidate is not None
    assert "scanner=nuclei" in candidate.proposal.rationale
    assert "template=vsftpd-backdoor" in candidate.proposal.rationale
    assert "CVE-2011-2523" in candidate.proposal.rationale
    assert "172.16.0.64:6200" in candidate.proposal.rationale


def test_unsupported_cve_returns_none_without_guessing() -> None:
    finding = make_finding(
        template_id="ghostcat",
        title="Apache Tomcat AJP Ghostcat",
        cve=["CVE-2020-1938"],
        port=8009,
        service="ajp",
        matched_at="172.16.0.64:8009",
    )

    assert map_finding_to_validation(finding) is None


def test_title_similarity_without_supported_cve_does_not_map() -> None:
    finding = make_finding(cve=[], title="VSFTPD-like possible issue")

    assert map_finding_to_validation(finding) is None


def test_batch_mapping_returns_only_supported_candidates() -> None:
    supported = make_finding()
    unsupported = make_finding(
        title="PostgreSQL Empty Password Detect",
        template_id="postgres-empty-password",
        cve=[],
        port=5432,
        service="postgresql",
        cvss=None,
        matched_at="172.16.0.64:5432",
    )

    candidates = map_findings_to_validations([unsupported, supported])

    assert len(candidates) == 1
    assert candidates[0].source_finding == supported


def test_mapping_does_not_require_or_create_approval_state() -> None:
    candidate = map_finding_to_validation(make_finding())

    assert candidate is not None
    assert not hasattr(candidate, "approval")
