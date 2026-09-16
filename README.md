# Tikcentral

A deliberately small MikroTik remote-management hub for RouterOS 7 devices behind NAT/CGNAT.

This repo takes the useful operational ideas from `Tik-Central_Management` and `tikcentral-tenant-factory`, but removes the multi-tenant factory, OpenTofu, Ansible, worker queues, broad metrics/alerting, Docker, and PostgreSQL from v1.

## v1 design

```text
Internet
   |
   | UDP 51820
   v
Ubuntu 24.04 OVH VPS
   |- WireGuard wg0        10.250.0.1/16
   |- FastAPI API          127.0.0.1:8080
   |- SQLite/WAL           /var/lib/tikcentral/tikcentral.db
   |- Caddy HTTPS          80/443
   |- UFW
   |- systemd
   `- daily DB backup
        |
        +-- MikroTik routers  10.250.1.0/24
        `-- Admin devices     10.250.254.0/24
```

Customer Internet traffic does not traverse this VPS. The overlay is for management traffic.

## Why this version is smaller

For fewer than 100 routers, stability is improved by minimizing moving parts:

- WireGuard runs directly on the host.
- The API runs as a dedicated unprivileged `tikcentral` service account.
- SQLite runs in WAL mode; there is no database daemon to maintain.
- Only a small root-owned helper may modify WireGuard peers.
- Caddy handles public HTTPS.
- systemd handles startup/restart and the backup timer.
- configuration and data live outside the Git checkout.

Paths:

```text
/opt/tikcentral/current                 Git checkout
/opt/tikcentral/venv                    Python environment
/etc/tikcentral/tikcentral.env          secrets/config
/etc/wireguard/wg0.conf                 WireGuard configuration
/var/lib/tikcentral/tikcentral.db       inventory database
/var/backups/tikcentral/                local DB backups
/usr/local/sbin/tikcentral-wg-peer      restricted WireGuard helper
```

## One-command install

First create a DNS A record, for example:

```text
vpn.example.com -> YOUR_OVH_VPS_IPV4
```

Then on a fresh Ubuntu 24.04 VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/yboucher97/Tikcentral/main/bootstrap.sh | \
  sudo bash -s -- --domain vpn.example.com --email you@example.com
```

If SSH is not on port 22:

```bash
curl -fsSL https://raw.githubusercontent.com/yboucher97/Tikcentral/main/bootstrap.sh | \
  sudo bash -s -- --domain vpn.example.com --email you@example.com --ssh-port 2222
```

The bootstrap installs/upgrades required Ubuntu packages, clones this repo, creates the service account and persistent directories, generates the WireGuard server key if needed, creates `wg0`, generates the API key, configures Caddy/UFW/systemd, starts services, enables the backup timer, and runs a local health check.

Secrets and private keys are generated on the VM and are never committed to Git.

## Enroll a MikroTik

On the VPS:

```bash
cd /opt/tikcentral/current
sudo ./scripts/new-router.sh "Customer - Site"
```

That creates a 24-hour one-time enrollment token and prints a RouterOS 7 script. Paste the generated output into the remote MikroTik terminal.

The MikroTik generates its own WireGuard private key locally. Only its public key is sent to the server. The server then:

1. validates and consumes the one-time token;
2. allocates the next address from `10.250.1.0/24`;
3. adds the peer to the live `wg0` interface;
4. persists the peer in `wg0.conf`;
5. records the router in SQLite;
6. returns the hub public key, endpoint, and assigned address.

The generated MikroTik config uses `persistent-keepalive=25`, adds a route for the management overlay, and only permits WinBox/SSH/ICMP to the router from the technician subnet `10.250.254.0/24`.

## Add your laptop

Generate the private/public WireGuard pair on your laptop. Keep the private key there.

Pass only its public key to the VPS:

```bash
cd /opt/tikcentral/current
sudo ./scripts/add-admin-peer.sh "Yan-Erik Laptop" '<PUBLIC_KEY>' 10.250.254.2
```

The command prints the client config. Replace the private-key placeholder locally.

After connecting your laptop VPN, routers are reachable directly by management IP, for example:

```text
WinBox -> 10.250.1.1
WinBox -> 10.250.1.2
SSH    -> 10.250.1.3
```

The VM permits technician-to-router forwarding but denies router-to-router forwarding by default.

## Operations

```bash
cd /opt/tikcentral/current

# health/services/WireGuard
sudo ./scripts/manage.sh status

# update the repo, Python deps and installed service files
sudo ./scripts/manage.sh update

# restart core services
sudo ./scripts/manage.sh restart

# make an immediate SQLite backup
sudo ./scripts/manage.sh backup

# list router inventory
sudo ./scripts/list-routers.sh

# inspect WireGuard handshakes
sudo wg show wg0

# API logs
sudo journalctl -u tikcentral -f

# Caddy logs
sudo journalctl -u caddy -f
```

The scheduled local database backup runs daily and keeps 14 days. Enable OVH snapshots/backups as well because local backups do not protect against total VPS loss.

## Security model

- No private WireGuard keys or API secrets in Git.
- One-time enrollment tokens are stored only as SHA-256 hashes and expire after 24 hours.
- API is bound to `127.0.0.1`; only Caddy exposes it over HTTPS.
- API process is not root.
- The service account only has passwordless sudo access to one root-owned helper, which validates WireGuard keys and router IPs before changing `wg0`.
- UFW exposes only SSH, HTTP/HTTPS and WireGuard.
- Routers cannot route to one another through the hub by default.
- Router management rules only trust the technician overlay range.

## Intentionally not in v1

The older system contains useful features that can be added after the tunnel/enrollment foundation is proven:

- simple web dashboard
- online/offline handshake status
- RouterOS version/model inventory
- config/export backups
- temporary LAN-device access
- alerts
- bulk jobs
- multiple technicians/roles
- OVH API provisioning
- external/offsite backups

The principle is to add each feature without making WireGuard reachability depend on the dashboard or automation layer.
