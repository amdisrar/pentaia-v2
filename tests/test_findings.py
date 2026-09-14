import json

import pytest

from pentaia.findings import (
    VulnerabilityFinding,
    finding_from_dict,
    findings_from_json,
    findings_to_json,
)


def _finding() -> VulnerabilityFinding:
    return VulnerabilityFinding(
        target="172.16.0.64",
        port=6200,
        protocol="tcp",
        service=None,
        template_id="CVE-2011-2523",
        title="VSFTPD 2.3.4 - Backdoor Command Execution",
        severity="critical",
        cve=["CVE-2011-2523"],
        cvss=9.8,
        matched_at="172.16.0.64:6200",
        evidence="Matched at 172.16.0.64:6200. Response: :x:3:3:sys:/dev:/bin/sh",
    )


def test_finding_round_trips_through_dict() -> None:
    original = _finding()

    assert finding_from_dict(original.to_dict()) == original


def test_findings_round_trip_through_json() -> None:
    original = [_finding()]

    assert findings_from_json(findings_to_json(original)) == original


def test_finding_from_dict_normalizes_case() -> None:
    record = _finding().to_dict()
    record["cve"] = ["cve-2011-2523"]
    record["severity"] = "CRITICAL"

    restored = finding_from_dict(record)

    assert restored.cve == ["CVE-2011-2523"]
    assert restored.severity == "critical"


def test_finding_from_dict_accepts_a_single_cve_string() -> None:
    record = _finding().to_dict()
    record["cve"] = "CVE-2011-2523"

    assert finding_from_dict(record).cve == ["CVE-2011-2523"]


def test_finding_from_dict_accepts_null_optional_fields() -> None:
    restored = finding_from_dict(
        {
            "target": "172.16.0.64",
            "port": None,
            "protocol": None,
            "service": None,
            "template_id": "t",
            "title": "n",
            "severity": "info",
            "cve": [],
            "cvss": None,
            "matched_at": None,
            "evidence": "",
        }
    )

    assert restored.port is None
    assert restored.cvss is None
    assert restored.service is None
    assert restored.source_tool == "nuclei"


@pytest.mark.parametrize(
    "record",
    [
        None,
        "not-an-object",
        [],
        {},
        {"target": ""},
        {"target": "172.16.0.64", "cve": {"unexpected": "object"}},
        {"target": "172.16.0.64", "cve": [1, 2]},
        {"target": "172.16.0.64", "port": "21"},
        {"target": "172.16.0.64", "port": True},
        {"target": "172.16.0.64", "cvss": "high"},
        {"target": "172.16.0.64", "cvss": True},
    ],
)
def test_finding_from_dict_rejects_unusable_records(record) -> None:
    with pytest.raises(ValueError):
        finding_from_dict(record)


@pytest.mark.parametrize("payload", ["", "   ", None, 7, "{not json", '{"a": 1}', '"text"'])
def test_findings_from_json_rejects_unusable_payloads(payload) -> None:
    with pytest.raises(ValueError):
        findings_from_json(payload)


def test_findings_from_json_accepts_an_empty_array() -> None:
    assert findings_from_json(json.dumps([])) == []
