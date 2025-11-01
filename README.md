# MktWireguardExporter

Generate per‑client Windows installer scripts from a MikroTik RouterOS WireGuard export.

This tool reads:
- `wg.rsc` — a RouterOS export containing `/interface wireguard peers` entries
- `wg.conf` — a known‑good client configuration used as a template for constants (e.g., server PublicKey, ListenPort, DNS, optional AllowedIPs template)

For every valid peer in `wg.rsc`, it writes a Windows `.que` script named after the client IP (e.g., `10.7.0.12.que`). Running that script on a Windows machine will:
1) generate a `<client-ip>.conf` file
2) move it into `C:\Program Files\WireGuard\`
3) install it as a WireGuard service via `wireguard.exe /installtunnelservice`


## Why `.que`?
The program currently outputs a `.que` file (a simple Windows CMD/batch script). You can double‑click it or run it from a command prompt with administrator privileges on the target client.
 - `.que` files are used in inpadi system - see https://gms.inpadi.dk for more info.
 - `.que` files can be renamed to .cmd and run from the command line with administrator privileges.

## How it builds each client config
- Interface section values come from a combination of the RouterOS peer and the `wg.conf` template:
  - `PrivateKey`, `Address`, and optional per‑peer `DNS` come from `wg.rsc`.
  - `ListenPort` and fallback `DNS` come from `wg.conf` if not present per‑peer.
- Peer section values:
  - `PublicKey` is the server's public key, read from the `[Peer]` section in `wg.conf`.
  - `AllowedIPs` is taken from RouterOS `allowed-address` if present, otherwise derived from `wg.conf`'s `[Peer] AllowedIPs`, replacing any `/32` entry with the client address (so the client's /32 goes last).
  - `PresharedKey` and `Endpoint` (address:port) come from `wg.rsc`.


## Quick start
1. Prepare inputs at the project root:
   - Export MikroTik WireGuard peers to `wg.rsc` (see example below).
   - Provide a base `wg.conf` containing the server's `[Peer] PublicKey` and any constants you want applied to all clients.
2. Build the tool (Go 1.20+ recommended):
   ```bash
   go build -o MktWireguardExporter.exe
   ```
3. Run it:
   ```bash
   ./MktWireguardExporter.exe
   ```
4. Find generated `*.que` files next to the executable. Copy the appropriate `.que` to the Windows client and run it as Administrator.


## Example files
- `wg.conf.example` — template showing the required fields and an optional `AllowedIPs` pattern.
- `wg.rsc.example` — RouterOS export snippet with multiple peers, including a line‑continuation example.

Rename/copy these to `wg.conf` and `wg.rsc` respectively and fill in real keys and values before running the exporter.


## Input file details
- `wg.conf`
  - The exporter looks for:
    - `[Interface]` → optional `ListenPort`, optional `DNS`
    - `[Peer]` → required `PublicKey` (server's public key), optional `AllowedIPs`
  - Other fields are ignored by the exporter.
- `wg.rsc`
  - Only the `/interface wireguard peers` section is parsed.
  - Each `add` line should include at least: `client-address`, `private-key`, `preshared-key`, `endpoint-address`, `endpoint-port`.
  - Optional: `client-dns`, `allowed-address`.


## Notes and limitations
- The exporter writes `.que` scripts that assume WireGuard for Windows is installed at `C:\Program Files\WireGuard\`.
- The script uses CRLF line endings and standard `cmd.exe` `echo` syntax.
- Invalid or incomplete peer entries are skipped.
- Security:
  - Handle `wg.rsc` and generated `.que` files with care; they contain sensitive keys.
  - Do not commit real keys to version control. Use the provided `*.example` files instead.


## License
No licenses attached - grap your copy and have fun.
