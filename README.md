# Opticable MikroTik WireGuard Hub

A small self-hosted hub for remotely managing RouterOS 7 MikroTik routers that sit behind NAT/CGNAT.

## What the stack installs

- WireGuard on the Ubuntu host (`wg0`, UDP 51820)
- Automatic per-router WireGuard enrollment
- One-time enrollment tokens
- FastAPI provisioning API
- PostgreSQL inventory/database
- Caddy reverse proxy with automatic HTTPS
- UFW firewall with router-to-router isolation by default
- Docker Engine + Docker Compose from Docker's official Ubuntu repository
- Daily PostgreSQL backup with 14-day local retention
- Helper scripts to create router installers and technician peers

### Addressing

- Hub: `10.250.0.1/16`
- Routers: `10.250.1.0/24` (254 addresses; more than enough for the initial <100-router target)
- Admin/technician devices: `10.250.254.0/24`

Normal customer Internet traffic is **not** routed through this VM.

## Before deployment

1. Create an Ubuntu 24.04 LTS VPS.
2. Give it a public IPv4.
3. Create a DNS A record such as `vpn.example.com` pointing to that IPv4.
4. Push this repository to a private or public GitHub repository.

A private repository needs Git authentication on the VPS. For the simplest bootstrap, use a public repo containing no secrets; `.env`, WireGuard private keys, and the database are generated only on the VM and are excluded from Git.

## One-command install

On a fresh VPS, change the values below and run:

```bash
curl -fsSL https://raw.githubusercontent.com/yboucher97/Tikcentral/main/bootstrap.sh | sudo bash -s -- \
  --repo https://github.com/yboucher97/Tikcentral.git \
  --domain vpn.example.com \
  --email you@example.com
```

If SSH uses a port other than 22, add:

```bash
--ssh-port 2222
```

The bootstrap can be run again later. It updates Ubuntu packages, pulls the latest Git branch, refreshes Docker packages/images, rebuilds the API, preserves `.env` secrets and the existing WireGuard configuration, and restarts the stack.

## Verify

```bash
cd /opt/opticable-mikrotik-hub
./scripts/status.sh
curl https://vpn.example.com/health
```

Expected API response:

```json
{"ok":true}
```

## Enroll a MikroTik

Generate a complete one-time RouterOS 7 script:

```bash
cd /opt/opticable-mikrotik-hub
./scripts/new-router.sh "Customer - Site"
```

Copy the output and paste it into the MikroTik terminal. The router generates its WireGuard key locally; its private key never leaves the router. The enrollment API receives only its public key, consumes the one-time token, assigns an unused management IP, adds the peer to the running WireGuard interface, and returns the hub parameters.

The RouterOS template uses a 25-second persistent keepalive, which is useful for peers behind stateful NAT/CGNAT.

List enrolled routers:

```bash
./scripts/list-routers.sh
```

## Add your laptop/technician device

Generate a WireGuard keypair **on the technician device**, then send only the public key to the server.

Linux/macOS with WireGuard tools:

```bash
umask 077
wg genkey | tee private.key | wg pubkey > public.key
cat public.key
```

Then on the VPS:

```bash
sudo ./scripts/add-admin-peer.sh "Yan-Erik Laptop" '<PUBLIC_KEY>' 10.250.254.2
```

The command prints the client configuration. Put your local private key into that configuration. Never copy the client private key into Git or onto the provisioning server.

Once connected, the intended management flow is:

```text
Technician 10.250.254.x -> Hub -> Router 10.250.1.x
```

Router-to-router forwarding is not allowed by the UFW rules installed by bootstrap.

## Useful commands

```bash
cd /opt/opticable-mikrotik-hub

# Status
./scripts/status.sh

# Generate a one-time token only
./scripts/new-token.sh "Customer - Site"

# Generate the complete copy/paste RouterOS installer
./scripts/new-router.sh "Customer - Site"

# Show inventory
./scripts/list-routers.sh

# Application logs
docker compose logs -f api

# Proxy logs
docker compose logs -f caddy

# WireGuard state
sudo wg show wg0
```

## Updating

Rerun the same original bootstrap command. Do not manually replace `.env` or `/etc/wireguard`.

For a production VM, also enable the VPS provider's snapshot/backup option. The included PostgreSQL backup is local to the VPS and does not protect against complete VM/disk loss.

## Security notes

- Keep the Git repo free of secrets. `.env` is generated on the VPS.
- Server and router private WireGuard keys are never stored in Git.
- Enrollment tokens are one-time tokens and are stored hashed in PostgreSQL.
- The administrative API requires a randomly generated API key.
- Only ports SSH, HTTP/HTTPS, and WireGuard are opened publicly.
- HTTP is needed by Caddy/ACME and redirects to HTTPS after certificate provisioning.
- The API listens only on `127.0.0.1:8080`; Caddy is the public entry point.
- Restrict your OVH account with MFA and keep an off-VM backup/snapshot.

## Current scope

This starter version manages the router itself through its dedicated WireGuard address. It intentionally does not advertise each customer's LAN, avoiding overlapping customer subnets such as `192.168.1.0/24`. LAN-device access can be added later using per-site translation or isolated routing.
