![banner](docs/banner.jpg)

# wireguard — a Hermes plugin for a local WireGuard server

Read-only status and peer list for a WireGuard server running on the
same Windows machine as Hermes. The plugin asks `wg.exe` what the
tunnel is doing and reports it. It never changes anything.

## What it does

Two tools, both read-only:

- **`vpn_status`** — the full picture: the tunnel service state
  (Running / Stopped / NotFound), the tunnel name, its IPv4
  address/prefix, its listen port, the server public key, and one
  entry per peer with allowed IPs, latest handshake (or `never`), and
  transfer totals in bytes.
- **`vpn_peers`** — just the peer list, for a quick "who is on the
  VPN / who has keys" answer.

A peer whose handshake reads `never` has not connected since the
tunnel started (or ever), and its transfer totals come back null.

## Requirements

- Windows, with **WireGuard for Windows** installed (the plugin shells
  out to `wg.exe`, `sc.exe`, and one PowerShell adapter lookup).
- Hermes 0.21.3 or later.
- The tunnel's Windows service is the one WireGuard creates for a
  tunnel, named `WireGuardTunnel$<tunnel>`.

## Install

1. Copy the `wireguard` folder into your Hermes plugins directory
   (for example `%LOCALAPPDATA%\hermes\plugins\wireguard`).
2. Add `wireguard` to the `plugins.enabled` list in your Hermes
   `config.yaml`:

   ```yaml
   plugins:
     enabled:
       - wireguard
   ```

3. Restart Hermes. The two tools appear alongside the built-in tools.

With no further configuration, the plugin finds the tunnel on its
own when the machine has exactly one WireGuard interface: it runs
`wg show interfaces` and uses the single result. If the machine has
zero interfaces, or more than one, the tools return a structured
error saying so instead of guessing.

## Configuration (optional)

Settings live in a top-level `wireguard:` section of `config.yaml`.
Every key is optional:

```yaml
wireguard:
  # Tunnel (interface) name. Set this when the machine has more than
  # one tunnel, or to pin the answer to one tunnel.
  tunnel: "example-tunnel"
  # Path to wg.exe. Default: "C:\Program Files\WireGuard\wg.exe"
  wg_path: "C:\\Program Files\\WireGuard\\wg.exe"
  # Windows service to query for state. Default: derived from the
  # tunnel as "WireGuardTunnel$<tunnel>".
  service_name: "WireGuardTunnel$example-tunnel"
  # Seconds before any single wg/sc/PowerShell call is given up on.
  # Default: 15
  timeout_seconds: 15
```

## Security

- The plugin never opens the tunnel configuration file and never asks
  `wg` for private key material. Plain `wg show` prints the interface
  private key as `(hidden)`, and that is the only form the plugin
  calls.
- Tool output carries public keys and IP addresses only. Both are
  identifiers the VPN itself exchanges in the clear during handshakes.
- There is no mutating surface at all: no service start or stop, no
  config writes, no peer changes. The worst a bug can do is produce a
  wrong status answer.
- Handlers return structured JSON results (including coded failures
  such as `wg_exe_missing`, `no_tunnel`, and `tunnel_ambiguous`) and
  never raise into the agent loop.

## Scope of v1

Reporting only. Adding or removing peers, generating client
configurations, and starting or stopping the tunnel are deliberately
out of scope: changing who can reach a network is a perimeter change
and belongs behind an explicit human decision, not a chat tool.
