"""Handlers for the wireguard plugin.

v1 is read-only by construction: the only external commands are
`wg.exe show ...`, `sc.exe query <service>`, and one PowerShell adapter
lookup. The plugin never opens the tunnel configuration file and never
asks wg for private key material (`wg show` prints the interface
private key as "(hidden)" on its own).

Handlers return JSON strings and never raise, per the fail-soft pattern
used by Hermes tool plugins.
"""

import json
import os
import re
import subprocess

DEFAULTS = {
    "wg_path": r"C:\Program Files\WireGuard\wg.exe",
    # "" means: no tunnel configured. The tunnel is then auto-discovered
    # with `wg show interfaces` when exactly one interface exists.
    "tunnel": "",
    # "" means: derive from the tunnel as "WireGuardTunnel$<tunnel>",
    # which is the service name WireGuard for Windows creates.
    "service_name": "",
    "timeout_seconds": 15,
}

_UNITS = {"B": 1, "KiB": 1024, "MiB": 1024 ** 2, "GiB": 1024 ** 3, "TiB": 1024 ** 4}


def _cfg():
    cfg = dict(DEFAULTS)
    try:
        from hermes_cli.config import load_config_readonly

        section = (load_config_readonly() or {}).get("wireguard") or {}
        for key in DEFAULTS:
            if key in section:
                cfg[key] = section[key]
    except Exception:  # noqa: BLE001 - config is optional; defaults apply
        pass
    return cfg


def _run(cmd, timeout):
    """Run a local command; return (rc, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT after %ss" % timeout
    except FileNotFoundError:
        return 127, "", "NOT FOUND: %s" % cmd[0]
    except Exception as e:  # noqa: BLE001
        return 127, "", "EXEC ERROR: %s" % e


def _ok(payload):
    return json.dumps({"success": True, "ok": True, **payload})


def _fail(code, **extra):
    return json.dumps({"success": False, "ok": False, "error": code, **extra})


def _resolve_tunnel(cfg):
    """Pick the tunnel to report on.

    Returns (tunnel_name, None) on success, or (None, fail_json) when no
    tunnel is configured and auto-discovery cannot pick exactly one.
    Mutates cfg to fill in the derived service name.
    """
    tunnel = (cfg.get("tunnel") or "").strip()
    if not tunnel:
        if not os.path.exists(cfg["wg_path"]):
            return None, _fail("wg_exe_missing", path=cfg["wg_path"])
        rc, out, err = _run(
            [cfg["wg_path"], "show", "interfaces"], cfg["timeout_seconds"]
        )
        if rc == 124:
            return None, _fail("wg_timeout")
        if rc != 0:
            return None, _fail(
                "wg_error", detail=((out + err).strip()[:300] or "wg show failed")
            )
        names = out.split()
        if len(names) == 1:
            tunnel = names[0]
        elif not names:
            return None, _fail(
                "no_tunnel",
                interfaces=[],
                hint=(
                    "No WireGuard interfaces found. Create a tunnel in "
                    "WireGuard for Windows, or set wireguard.tunnel in "
                    "config to the tunnel name."
                ),
            )
        else:
            return None, _fail(
                "tunnel_ambiguous",
                interfaces=names,
                hint=(
                    "More than one WireGuard interface exists. Set "
                    "wireguard.tunnel in config to the tunnel name to "
                    "report on."
                ),
            )
    cfg["tunnel"] = tunnel
    if not (cfg.get("service_name") or "").strip():
        cfg["service_name"] = "WireGuardTunnel$" + tunnel
    return tunnel, None


def _service_state(cfg):
    """Running / Stopped / NotFound for the tunnel's Windows service."""
    rc, out, err = _run(["sc.exe", "query", cfg["service_name"]], cfg["timeout_seconds"])
    text = out + err
    if "1060" in text or "FAILED" in text:
        return "NotFound"
    m = re.search(r"STATE\s*:\s*\d+\s+(\w+)", text)
    if m:
        state = m.group(1).upper()
        if state == "RUNNING":
            return "Running"
        return "Stopped"
    return "Unknown"


def _tunnel_address(cfg):
    """IPv4 address/prefix of the tunnel adapter (for example
    '192.0.2.1/24'), or None when it cannot be read."""
    ps = (
        "(Get-NetIPAddress -InterfaceAlias '%s' -AddressFamily IPv4 "
        "| Select-Object -First 1 "
        "| ForEach-Object { $_.IPAddress + '/' + $_.PrefixLength })"
        % cfg["tunnel"]
    )
    rc, out, _ = _run(
        ["powershell", "-NoProfile", "-Command", ps], cfg["timeout_seconds"]
    )
    if rc == 0:
        value = out.strip().splitlines()
        if value and re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", value[0].strip()):
            return value[0].strip()
    return None


def _to_bytes(amount, unit):
    try:
        return int(round(float(amount) * _UNITS[unit]))
    except (ValueError, KeyError):
        return None


def _parse_wg(text):
    """Parse `wg show` text into (interface_dict, peers_list)."""
    interface = {}
    peers = []
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("interface:"):
            current = interface
            interface["name"] = line.split(":", 1)[1].strip()
        elif line.startswith("peer:"):
            current = {}
            peers.append(current)
            current["public_key"] = line.split(":", 1)[1].strip()
        elif current is not None and ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            if key == "public key":
                current["public_key"] = value
            elif key == "listening port":
                try:
                    current["listen_port"] = int(value)
                except ValueError:
                    current["listen_port"] = value
            elif key == "endpoint":
                current["endpoint"] = value
            elif key == "allowed ips":
                current["allowed_ips"] = [v.strip() for v in value.split(",")]
            elif key == "latest handshake":
                current["latest_handshake"] = value
            elif key == "transfer":
                m = re.match(
                    r"([\d.]+)\s*(\w+)\s+received,\s*([\d.]+)\s*(\w+)\s+sent", value
                )
                if m:
                    current["transfer_rx_bytes"] = _to_bytes(m.group(1), m.group(2))
                    current["transfer_tx_bytes"] = _to_bytes(m.group(3), m.group(4))
    for peer in peers:
        peer.setdefault("latest_handshake", "never")
        peer.setdefault("transfer_rx_bytes", None)
        peer.setdefault("transfer_tx_bytes", None)
    return interface, peers


def _collect(cfg):
    """Run wg show for cfg's tunnel and parse it.

    Returns ((interface, peers), None) on success, (None, (out, err))
    when wg ran but failed (tunnel down), or a _fail JSON string for
    errors that are reported as-is.
    """
    if not os.path.exists(cfg["wg_path"]):
        return _fail("wg_exe_missing", path=cfg["wg_path"])
    rc, out, err = _run(
        [cfg["wg_path"], "show", cfg["tunnel"]], cfg["timeout_seconds"]
    )
    if rc == 124:
        return _fail("wg_timeout")
    if rc != 0:
        return None, (out, err)
    try:
        return _parse_wg(out), None
    except Exception:  # noqa: BLE001
        return _fail("parse_error", raw=out[:500])


def vpn_status_handler(params=None, **kwargs):
    cfg = _cfg()
    tunnel, fail = _resolve_tunnel(cfg)
    if fail is not None:
        return fail
    service_state = _service_state(cfg)
    if service_state == "NotFound":
        return _ok(
            {
                "service_state": "NotFound",
                "tunnel": {"name": cfg["tunnel"]},
                "peers": [],
                "note": "The WireGuard tunnel service is not installed on this machine.",
            }
        )
    collected = _collect(cfg)
    if isinstance(collected, str):
        return collected
    (interface, peers), failure = collected
    if failure is not None:
        out, err = failure
        return _ok(
            {
                "service_state": service_state,
                "tunnel_down": True,
                "tunnel": {"name": cfg["tunnel"]},
                "peers": [],
                "detail": ((out + err).strip()[:300] or "wg show failed"),
            }
        )
    return _ok(
        {
            "service_state": service_state,
            "tunnel": {
                "name": interface.get("name", cfg["tunnel"]),
                "address": _tunnel_address(cfg),
                "listen_port": interface.get("listen_port"),
            },
            "server_public_key": interface.get("public_key"),
            "peers": peers,
        }
    )


def vpn_peers_handler(params=None, **kwargs):
    cfg = _cfg()
    tunnel, fail = _resolve_tunnel(cfg)
    if fail is not None:
        return fail
    collected = _collect(cfg)
    if isinstance(collected, str):
        return collected
    (interface, peers), failure = collected
    if failure is not None:
        out, err = failure
        return _fail(
            "tunnel_down",
            detail=((out + err).strip()[:300] or "wg show failed"),
        )
    return _ok({"tunnel": cfg["tunnel"], "peer_count": len(peers), "peers": peers})
