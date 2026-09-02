import json
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class VulnerabilityFinding:
    target: str
    port: int | None
    protocol: str | None
    service: str | None
    template_id: str
    title: str
    severity: str
    cve: list[str]
    cvss: float | None
    matched_at: str | None
    evidence: str
    source_tool: str = "nuclei"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalize_cves(classification: dict[str, Any]) -> list[str]:
    raw_cves = classification.get("cve-id") or []

    if isinstance(raw_cves, str):
        raw_cves = [raw_cves]

    return [str(cve).upper() for cve in raw_cves]


def _normalize_cvss(classification: dict[str, Any]) -> float | None:
    value = classification.get("cvss-score")

    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _build_evidence(record: dict[str, Any]) -> str:
    matched_at = record.get("matched-at")
    response = record.get("response") or ""

    if matched_at:
        evidence = f"Matched at {matched_at}."
    else:
        evidence = "Nuclei template matched the target."

    if response:
        first_line = response.splitlines()[0].strip()
        if first_line:
            evidence = f"{evidence} Response: {first_line}"

    return evidence


def parse_nuclei_record(record: dict[str, Any]) -> VulnerabilityFinding:
    info = record.get("info") or {}
    classification = info.get("classification") or {}

    port = record.get("port")
    try:
        normalized_port = int(port) if port is not None else None
    except (TypeError, ValueError):
        normalized_port = None

    protocol = record.get("type")

    return VulnerabilityFinding(
        target=str(record.get("host") or record.get("url") or ""),
        port=normalized_port,
        protocol=str(protocol) if protocol is not None else None,
        service=str(record.get("scheme")) if record.get("scheme") else None,
        template_id=str(record.get("template-id") or ""),
        title=str(info.get("name") or record.get("template-id") or "Unknown finding"),
        severity=str(info.get("severity") or "unknown").lower(),
        cve=_normalize_cves(classification),
        cvss=_normalize_cvss(classification),
        matched_at=str(record.get("matched-at")) if record.get("matched-at") else None,
        evidence=_build_evidence(record),
    )


def parse_nuclei_jsonl(output: str) -> list[VulnerabilityFinding]:
    findings: list[VulnerabilityFinding] = []

    for line_number, line in enumerate(output.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid Nuclei JSONL on line {line_number}: {exc.msg}"
            ) from exc

        if not isinstance(record, dict):
            raise ValueError(
                f"Invalid Nuclei JSONL on line {line_number}: expected an object."
            )

        findings.append(parse_nuclei_record(record))

    return findings


def findings_to_json(findings: list[VulnerabilityFinding]) -> str:
    return json.dumps(
        [finding.to_dict() for finding in findings],
        indent=2,
        sort_keys=True,
    )
