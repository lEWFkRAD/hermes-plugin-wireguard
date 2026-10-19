"""Tool schemas for the wireguard plugin (what the LLM sees)."""

VPN_STATUS_SCHEMA = {
    "name": "vpn_status",
    "description": (
        "Full status of the WireGuard server running on THIS machine "
        "(WireGuard for Windows). Read-only. Returns the Windows service "
        "state, the tunnel address and listen port, the server public "
        "key, and one entry per peer with allowed IPs, latest handshake "
        "(or 'never'), and transfer totals. Use this when asked whether "
        "the VPN is up or how it is configured. The tunnel is the one "
        "named by the wireguard.tunnel config setting; when none is set "
        "and exactly one tunnel exists on the machine, it is found "
        "automatically. This tool can only report state; it cannot "
        "start, stop, or change the tunnel, and it never exposes "
        "private key material."
    ),
    "parameters": {
        "type": "object",
        "properties": {},
    },
}

VPN_PEERS_SCHEMA = {
    "name": "vpn_peers",
    "description": (
        "Peer list only for the WireGuard server running on THIS "
        "machine (WireGuard for Windows). Read-only. One entry per "
        "peer: public key, allowed IPs, latest handshake (or 'never'), "
        "and transfer totals. Use this for a quick 'who is on the VPN / "
        "who has keys' answer. A peer with handshake 'never' has not "
        "connected since the tunnel started (or ever)."
    ),
    "parameters": {
        "type": "object",
        "properties": {},
    },
}
