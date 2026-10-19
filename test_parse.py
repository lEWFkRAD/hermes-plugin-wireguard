"""Parser and handler tests for the wireguard plugin.

Loads wireguard/tools.py by path, replaces its subprocess runner with
a fake that feeds captured `wg show` output, and asserts the parsed
values and the handler JSON contract. No WireGuard install needed.

Run: python3 test_parse.py
"""

import importlib.util
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS_PATH = os.path.join(HERE, "wireguard", "tools.py")

spec = importlib.util.spec_from_file_location("wireguard_tools", TOOLS_PATH)
tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tools)

# wg.exe lives at a Windows path that does not exist on the test
# machine; the handlers check for it before running anything.
_real_exists = os.path.exists
os.path.exists = (
    lambda p: True if str(p).lower().endswith("wg.exe") else _real_exists(p)
)

# --- Captured `wg show` output: one active peer ---------------------

SAMPLE_ACTIVE_NAME = "example-tunnel"
SAMPLE_ACTIVE = """interface: example-tunnel
  public key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  private key: (hidden)
  listening port: 51820

peer: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
  endpoint: 192.0.2.10:51820
  allowed ips: 10.99.99.2/32
  latest handshake: 1 minute, 25 seconds ago
  transfer: 852.70 MiB received, 3.76 GiB sent
"""

# --- Captured `wg show` output: one peer that has never connected ---

SAMPLE_NEVER = """interface: example-tunnel
  public key: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
  private key: (hidden)
  listening port: 51820

peer: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=
  allowed ips: 10.99.99.12/32
"""


def make_fake_run(interfaces, show_map):
    """A _run replacement dispatching on the command line."""

    def fake_run(cmd, timeout):
        if cmd[0] == "sc.exe":
            return 0, "        STATE              : 4  RUNNING\n", ""
        if cmd[0] == "powershell":
            return 0, "192.0.2.1/24\n", ""
        if len(cmd) >= 3 and cmd[1] == "show" and cmd[2] == "interfaces":
            return 0, (" ".join(interfaces) + "\n") if interfaces else "", ""
        if len(cmd) >= 3 and cmd[1] == "show":
            out = show_map.get(cmd[2])
            if out is None:
                return 1, "", "Unable to access interface: %s" % cmd[2]
            return 0, out, ""
        return 1, "", "unexpected command: %r" % (cmd,)

    return fake_run


def test_parse_active():
    interface, peers = tools._parse_wg(SAMPLE_ACTIVE)
    assert interface["name"] == SAMPLE_ACTIVE_NAME, interface
    assert interface["listen_port"] == 51820, interface
    assert interface["public_key"] == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    assert len(peers) == 1, peers
    peer = peers[0]
    assert peer["public_key"] == "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
    assert peer["endpoint"] == "192.0.2.10:51820", peer
    assert peer["allowed_ips"] == ["10.99.99.2/32"], peer
    assert peer["latest_handshake"] == "1 minute, 25 seconds ago", peer
    # 852.70 MiB and 3.76 GiB, converted to bytes by the parser.
    assert peer["transfer_rx_bytes"] == 894120755, peer
    assert peer["transfer_tx_bytes"] == 4037269258, peer
    print("ok: parser, active peer (handshake string, transfer to bytes)")


def test_parse_never_connected():
    interface, peers = tools._parse_wg(SAMPLE_NEVER)
    assert interface["listen_port"] == 51820, interface
    assert len(peers) == 1, peers
    peer = peers[0]
    assert peer["allowed_ips"] == ["10.99.99.12/32"], peer
    assert "endpoint" not in peer, peer
    assert peer["latest_handshake"] == "never", peer
    assert peer["transfer_rx_bytes"] is None, peer
    assert peer["transfer_tx_bytes"] is None, peer
    print("ok: parser, never-connected peer ('never' default, null transfer)")


def test_handlers_auto_discovery():
    tools._run = make_fake_run(
        [SAMPLE_ACTIVE_NAME], {SAMPLE_ACTIVE_NAME: SAMPLE_ACTIVE}
    )
    status = json.loads(tools.vpn_status_handler({}))
    assert status["ok"] is True, status
    assert status["service_state"] == "Running", status
    assert status["tunnel"]["name"] == SAMPLE_ACTIVE_NAME, status
    assert status["tunnel"]["listen_port"] == 51820, status
    assert status["tunnel"]["address"] == "192.0.2.1/24", status
    assert status["server_public_key"] == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    assert status["peers"][0]["transfer_rx_bytes"] == 894120755, status
    peers = json.loads(tools.vpn_peers_handler({}))
    assert peers["ok"] is True, peers
    assert peers["tunnel"] == SAMPLE_ACTIVE_NAME, peers
    assert peers["peer_count"] == 1, peers
    assert peers["peers"][0]["latest_handshake"] == "1 minute, 25 seconds ago"
    print("ok: handlers, single tunnel auto-discovered, full JSON contract")


def test_handlers_ambiguous_and_missing():
    tools._run = make_fake_run(["wg-a", "wg-b"], {})
    result = json.loads(tools.vpn_peers_handler({}))
    assert result["ok"] is False, result
    assert result["error"] == "tunnel_ambiguous", result
    assert result["interfaces"] == ["wg-a", "wg-b"], result

    tools._run = make_fake_run([], {})
    result = json.loads(tools.vpn_status_handler({}))
    assert result["ok"] is False, result
    assert result["error"] == "no_tunnel", result
    assert result["interfaces"] == [], result
    print("ok: handlers, tunnel_ambiguous and no_tunnel fail-soft results")


if __name__ == "__main__":
    test_parse_active()
    test_parse_never_connected()
    test_handlers_auto_discovery()
    test_handlers_ambiguous_and_missing()
    print("ALL TESTS PASSED")
