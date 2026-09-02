import ipaddress
from urllib.parse import urlsplit, urlunsplit


def validate_ipv4(target: str) -> str:
    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 address: {target}") from exc

    if address.version != 4:
        raise ValueError(f"IPv4 address required: {target}")

    return str(address)


def validate_nuclei_target(target: str) -> str:
    target = target.strip()

    if not target:
        raise ValueError("Nuclei target cannot be empty.")

    if any(char.isspace() for char in target):
        raise ValueError("Nuclei target must not contain whitespace.")

    if "://" not in target:
        return validate_ipv4(target)

    parsed = urlsplit(target)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https Nuclei targets are allowed.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials in Nuclei target URLs are not allowed.")

    if not parsed.hostname:
        raise ValueError("Nuclei target URL must include an IPv4 host.")

    host = validate_ipv4(parsed.hostname)

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid port in Nuclei target URL.") from exc

    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Nuclei target port must be between 1 and 65535.")

    if parsed.query or parsed.fragment:
        raise ValueError("Query strings and URL fragments are not allowed in Nuclei targets.")

    netloc = host if port is None else f"{host}:{port}"
    path = parsed.path or "/"

    return urlunsplit((parsed.scheme, netloc, path, "", ""))
