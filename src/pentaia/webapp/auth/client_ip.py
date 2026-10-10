"""Client IP resolution for throttling, behind the trusted reverse proxy.

The architecture places a reverse proxy on the same host and allows the application to
trust forwarded-protocol information **only from that proxy**. Login throttling keys on
the client address, so this module is where that trust decision is made and bounded.

The rules, all fail-closed:

* The address of the TCP peer is the only value the application observes directly.
* A peer that is not a configured trusted proxy has its ``X-Forwarded-For`` header
  **ignored entirely**. A client therefore cannot choose its own throttle identity by
  sending a header.
* Only for a trusted peer is ``X-Forwarded-For`` consulted, and then it is walked from
  the right: each proxy appends the address it saw, so the rightmost entry is the one
  our own proxy wrote, and the first entry that is not itself a trusted proxy is the
  real client. Client-supplied entries further left are never reached.
* Work is bounded: at most :data:`MAX_FORWARDED_FOR_LENGTH` characters and
  :data:`MAX_FORWARDED_HOPS` hops are examined.
* A value that is not a well-formed IPv4/IPv6 address (optionally with a port) is
  never turned into an identity, so a malformed header cannot mint unlimited throttle
  buckets. If nothing usable remains, the peer address is used.

Two consequences worth stating plainly. First, a proxy that forwards a client-supplied
``X-Forwarded-For`` without appending the address it observed defeats this module; the
deployment must sanitize or append, which is documented in the README and is the
operator's responsibility. Second, if a client sends a malformed header through a
correctly configured proxy, the whole deployment shares the proxy's address as a
throttle bucket; that is a deliberate fail-closed choice, and it is the misconfiguration
signal rather than a bypass.
"""

import ipaddress
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

#: Used when the peer address is missing or unparseable. Every such request shares one
#: throttle bucket, which is the conservative direction.
UNKNOWN_CLIENT_IP = "unknown"

#: Only this many trailing characters of ``X-Forwarded-For`` are examined.
MAX_FORWARDED_FOR_LENGTH = 1024

#: Only this many rightmost entries are examined.
MAX_FORWARDED_HOPS = 20

Address = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _normalize_address(value: object) -> str | None:
    """Return the canonical form of one address, or ``None`` if it is not one.

    Accepts a bare address, ``address:port`` and the bracketed ``[address]:port`` form.
    Anything else — including an empty string, a hostname, or a port that is not a
    number — is refused rather than guessed at.
    """
    if not isinstance(value, str):
        return None

    candidate = value.strip()

    if not candidate:
        return None

    if candidate.startswith("["):
        end = candidate.find("]")

        if end == -1:
            return None

        host = candidate[1:end]
        remainder = candidate[end + 1 :]

        if remainder and not remainder.startswith(":"):
            return None
    else:
        host = candidate

        # A single colon means "IPv4 address with a port"; IPv6 addresses contain more.
        if host.count(":") == 1:
            host, _, port = host.partition(":")

            if not port.isdigit():
                return None

    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        return None


@dataclass(frozen=True)
class TrustedProxySet:
    """The configured proxies whose forwarded headers are believed.

    Built once at startup from validated configuration. An empty set trusts nothing,
    which is the safe default: every request is then keyed by its TCP peer.
    """

    addresses: frozenset[Address] = field(default_factory=frozenset)
    networks: tuple[Network, ...] = ()

    @classmethod
    def parse(cls, entries: Iterable[str]) -> "TrustedProxySet":
        """Build a set from configuration values, ignoring blank entries.

        Configuration validation has already rejected anything unparseable; a value
        that still fails here is skipped rather than trusted.
        """
        addresses: set[Address] = set()
        networks: list[Network] = []

        for entry in entries:
            candidate = entry.strip()

            if not candidate:
                continue

            try:
                if "/" in candidate:
                    networks.append(ipaddress.ip_network(candidate, strict=False))
                else:
                    addresses.add(ipaddress.ip_address(candidate))
            except ValueError:
                logger.warning(
                    "Ignoring an unparseable trusted-proxy entry; it will not be trusted."
                )

        return cls(addresses=frozenset(addresses), networks=tuple(networks))

    def __contains__(self, address: object) -> bool:
        """True when ``address`` (canonical string or address object) is trusted."""
        try:
            candidate = (
                address
                if isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address))
                else ipaddress.ip_address(str(address))
            )
        except ValueError:
            return False

        if candidate in self.addresses:
            return True

        return any(candidate in network for network in self.networks)

    def __bool__(self) -> bool:
        return bool(self.addresses or self.networks)


def resolve_client_ip(
    *,
    peer_host: object,
    forwarded_for: object,
    trusted: TrustedProxySet | None = None,
) -> str:
    """Resolve the client address used for throttling and logging.

    Returns a canonical address string, or :data:`UNKNOWN_CLIENT_IP` when the peer
    cannot be identified at all.
    """
    proxies = trusted if trusted is not None else TrustedProxySet()
    peer = _normalize_address(peer_host)

    if peer is None:
        return UNKNOWN_CLIENT_IP

    # The header is meaningless unless the request actually came from our proxy.
    if peer not in proxies:
        return peer

    if not isinstance(forwarded_for, str) or not forwarded_for.strip():
        return peer

    # Bound both the characters examined and the number of hops considered.
    hops = forwarded_for[-MAX_FORWARDED_FOR_LENGTH :].split(",")[-MAX_FORWARDED_HOPS :]

    for hop in reversed(hops):
        address = _normalize_address(hop)

        if address is None:
            continue

        if address not in proxies:
            return address

    # Every hop was a trusted proxy, or none of them was usable.
    return peer
