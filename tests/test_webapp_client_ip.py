"""P4-08 client-IP resolution behind the trusted reverse proxy.

The trust boundary is asserted as behaviour: a peer that is not a configured proxy
cannot influence the resolved address at all, no matter what it puts in
``X-Forwarded-For``, and header handling is bounded so a hostile header cannot mint
unlimited throttle identities.
"""

import pytest

from pentaia.webapp.auth.client_ip import (
    MAX_FORWARDED_FOR_LENGTH,
    MAX_FORWARDED_HOPS,
    UNKNOWN_CLIENT_IP,
    TrustedProxySet,
    resolve_client_ip,
)

PROXY = TrustedProxySet.parse(["127.0.0.1"])
NONE_TRUSTED = TrustedProxySet.parse([])


def resolve(peer, forwarded_for=None, trusted=PROXY):
    return resolve_client_ip(
        peer_host=peer,
        forwarded_for=forwarded_for,
        trusted=trusted,
    )


# --- the peer decides when it is not a trusted proxy ------------------------


@pytest.mark.parametrize(
    "forwarded_for",
    [
        None,
        "",
        "   ",
        "203.0.113.9",
        "6.6.6.6, 203.0.113.9",
        "not-an-address",
        "1.2.3.4:9999",
    ],
)
def test_an_untrusted_peer_cannot_choose_its_own_address(forwarded_for) -> None:
    """A client that is not our proxy is keyed by its TCP peer, whatever it sends."""
    assert resolve("198.51.100.7", forwarded_for) == "198.51.100.7"


def test_an_empty_trusted_set_trusts_nobody() -> None:
    assert resolve("127.0.0.1", "203.0.113.9", trusted=NONE_TRUSTED) == "127.0.0.1"


def test_a_trusted_peer_without_the_header_is_keyed_by_its_peer() -> None:
    assert resolve("127.0.0.1", None) == "127.0.0.1"


# --- the rightmost untrusted hop is the client -----------------------------


def test_a_single_forwarded_address_is_the_client() -> None:
    assert resolve("127.0.0.1", "203.0.113.9") == "203.0.113.9"


def test_a_spoofed_prefix_is_ignored_when_the_proxy_appends() -> None:
    """The classic spoof: the client prepends, our proxy appends the real address."""
    assert resolve("127.0.0.1", "6.6.6.6, 203.0.113.9") == "203.0.113.9"


def test_multiple_proxy_hops_are_walked_from_the_right() -> None:
    trusted = TrustedProxySet.parse(["127.0.0.1", "10.0.0.0/8"])
    assert resolve("127.0.0.1", "6.6.6.6, 203.0.113.9, 10.0.0.5", trusted) == "203.0.113.9"


def test_every_hop_being_a_trusted_proxy_falls_back_to_the_peer() -> None:
    trusted = TrustedProxySet.parse(["127.0.0.1", "10.0.0.0/8"])
    assert resolve("127.0.0.1", "10.0.0.5, 10.0.0.6", trusted) == "127.0.0.1"


def test_a_cidr_network_can_be_trusted() -> None:
    trusted = TrustedProxySet.parse(["10.0.0.0/8"])
    assert resolve("10.1.2.3", "203.0.113.9", trusted) == "203.0.113.9"
    assert resolve("192.0.2.1", "203.0.113.9", trusted) == "192.0.2.1"


# --- forms, normalisation and junk ----------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("203.0.113.9", "203.0.113.9"),
        ("  203.0.113.9  ", "203.0.113.9"),
        ("203.0.113.9:44321", "203.0.113.9"),
        ("2001:0db8:0000:0000:0000:0000:0000:0009", "2001:db8::9"),
        ("[2001:db8::9]", "2001:db8::9"),
        ("[2001:db8::9]:443", "2001:db8::9"),
    ],
)
def test_address_forms_are_normalized(value: str, expected: str) -> None:
    """Two spellings of one address must not become two throttle identities."""
    assert resolve("127.0.0.1", value) == expected


@pytest.mark.parametrize(
    "value",
    ["", "   ", "hostname.example.test", "1.2.3.4:notaport", "1.2.3", "[2001:db8::9"],
)
def test_malformed_entries_never_become_identities(value: str) -> None:
    assert resolve("127.0.0.1", value) == "127.0.0.1"


def test_a_valid_entry_further_left_is_used_when_the_rightmost_is_junk() -> None:
    assert resolve("127.0.0.1", "6.6.6.6, garbage") == "6.6.6.6"


def test_a_missing_peer_is_unknown() -> None:
    assert resolve(None, "203.0.113.9") == UNKNOWN_CLIENT_IP
    assert resolve("", "203.0.113.9") == UNKNOWN_CLIENT_IP
    assert resolve(1234, "203.0.113.9") == UNKNOWN_CLIENT_IP


# --- bounds -----------------------------------------------------------------


def test_an_over_long_header_is_bounded_and_still_resolved() -> None:
    """Length is capped, but the proxy-appended address at the end is still read."""
    padding = ", ".join(["6.6.6.6"] * 500)
    header = f"{padding}, 203.0.113.9"

    assert len(header) > MAX_FORWARDED_FOR_LENGTH
    assert resolve("127.0.0.1", header) == "203.0.113.9"


def test_hop_count_is_bounded() -> None:
    """Entries beyond the examined window are not walked, so work stays bounded.

    The untrusted address is pushed out of the window by trusted hops, so a header that
    tries to make the resolver walk an unbounded list cannot reach it and the peer is
    used instead.
    """
    trusted = TrustedProxySet.parse(["127.0.0.1", "10.0.0.0/8"])
    header = ", ".join(["203.0.113.9"] + ["10.0.0.5"] * (MAX_FORWARDED_HOPS * 3))

    assert resolve("127.0.0.1", header, trusted) == "127.0.0.1"


def test_unparseable_trusted_proxy_entries_are_ignored() -> None:
    """A bad entry in configuration must not become a trusted host."""
    parsed = TrustedProxySet.parse(["", "   ", "not-an-address"])

    assert not parsed
    assert resolve("198.51.100.7", "203.0.113.9", parsed) == "198.51.100.7"
