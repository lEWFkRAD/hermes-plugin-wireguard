"""wireguard — Hermes plugin entry point.

Adds two read-only tools for a WireGuard server running on the same
Windows machine as Hermes: vpn_status (full status) and vpn_peers
(peer list only).
"""

from .schemas import VPN_PEERS_SCHEMA, VPN_STATUS_SCHEMA
from .tools import vpn_peers_handler, vpn_status_handler


def register(ctx):
    ctx.register_tool(
        name="vpn_status",
        toolset="vpn_status",
        schema=VPN_STATUS_SCHEMA,
        handler=vpn_status_handler,
        emoji="🔐",
    )
    ctx.register_tool(
        name="vpn_peers",
        toolset="vpn_peers",
        schema=VPN_PEERS_SCHEMA,
        handler=vpn_peers_handler,
        emoji="🔐",
    )
