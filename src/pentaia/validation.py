import ipaddress


def validate_ipv4(target: str) -> str:
    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 address: {target}") from exc

    if address.version != 4:
        raise ValueError(f"IPv4 address required: {target}")

    return str(address)
