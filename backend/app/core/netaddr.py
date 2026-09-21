"""Address classification shared by detection and correlation, so both agree on what "external" means."""

from __future__ import annotations

import ipaddress

# Not reachable from outside an organisation: RFC 1918, CGNAT, loopback, link-local, unique-local,
# unspecified and multicast. Documentation ranges (RFC 5737) deliberately count as external.
INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "0.0.0.0/8",
        "224.0.0.0/4",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "::/128",
        "ff00::/8",
    )
)


def is_external_ip(value: str) -> bool:
    """True for a parseable address outside every internal range; False for internal or unparseable."""
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return not any(address.version == net.version and address in net for net in INTERNAL_NETWORKS)
