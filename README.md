# Tikcentral

A small, stable MikroTik remote-management hub for RouterOS 7 devices behind NAT/CGNAT.

This repo keeps the strongest operational ideas from `Tik-Central_Management` and `tikcentral-tenant-factory`, but intentionally avoids the heavier multi-tenant factory, OpenTofu, Ansible, worker queues, Docker, and PostgreSQL in v1.

## v1 design

```text
Internet
   |
   | tikcentral.opticable.ca
   v
Ubuntu 24.04 OVH VPS
   |- WireGuard wg0        UDP 51820 / 10.250.0.1/16
   |- FastAPI              127.0.0.1:8080
   |- WinBox relay         random TCP 20000-49999
   |- SQLite/WAL           /var/lib/tikcentral/tikcentral.db
   |- Caddy HTTPS          80/443
   |- UFW
   |- systemd
   `- daily DB backup
        |
        +-- MikroTik routers  10.250.1.0/24
        `-- Admin devices     10.250.254.0/24
```

Customer Internet traffic does not traverse this VPS. The overlay is only for management traffic.

## Simple web dashboard

After installation, browse to:

```text
https://tikcentral.opticable.ca/
```

The bootstrap prints a generated dashboard password. Login username is `admin`.

The dashboard shows:

- online/offline status from the live WireGuard handshake;
- MikroTik identity;
- RouterBOARD serial number;
- current public/WAN egress IP observed by WireGuard;
- assigned VPN IP;
- a public Remote WinBox target such as `tikcentral.opticable.ca:23194`;
- a private VPN WinBox target such as `10.250.1.12:8291`;
- last WireGuard handshake time.

The public IP and online status come directly from WireGuard, so no heartbeat scheduler is required on the MikroTik.

## Remote WinBox access control

Every router gets a unique random public TCP port in the range `20000-49999`.

Example:

```text
tikcentral.opticable.ca:23194 -> 10.250.1.12:8291
tikcentral.opticable.ca:38422 -> 10.250.1.13:8291
```

The WinBox relay only forwards connections from IP addresses authorized in the Tikcentral database.

The dashboard includes:

- **Authorize my current IP for 5 days** — Tikcentral detects the public IPv4 used to access the dashboard and grants it access to all Remote WinBox ports for five days. Re-authorizing refreshes the five-day expiry.
- **Always Authorized IPs** — manually add stable office/home/technician public IPv4 addresses that never expire until removed.
- a list showing every authorized IP, label, authorization type, expiry, and a Remove button.

This allows travel/borrowed-computer access without requiring the technician WireGuard profile, while the private VPN method remains available as the preferred management path.

Unauthorized source IPs can establish a TCP connection to the VPS port range but the Tikcentral relay immediately rejects them before opening any connection to the MikroTik.

## Why this version is smaller

For fewer than 100 routers, fewer moving parts makes recovery and maintenance easier:

- WireGuard runs directly on the host.
- The API and WinBox relay run as the dedicated unprivileged `tikcentral` account.
- SQLite runs in WAL mode; there is no database daemon.
- A small root-owned helper is the only application component allowed to modify WireGuard peers.
- Caddy handles HTTPS and dashboard authentication.
- systemd handles startup/restart and database backup scheduling.
- configuration/data live outside the Git checkout.

Persistent paths:

```text
/opt/tikcentral/current                 Git checkout
/opt/tikcentral/venv                    Python environment
/etc/tikcentral/tikcentral.env          secrets/config
/etc/wireguard/wg0.conf                 WireGuard configuration
/var/lib/tikcentral/tikcentral.db       inventory/access database
/var/backups/tikcentral/                local DB backups
/usr/local/sbin/tikcentral-wg-peer      restricted WireGuard helper
```

## One-command install

`tikcentral.opticable.ca` should resolve to the public IPv4 of the OVH VPS.

On a fresh Ubuntu 24.04 VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/yboucher97/Tikcentral/main/bootstrap.sh | \
  sudo bash -s -- --domain tikcentral.opticable.ca --email YOUR_EMAIL
```

If SSH is not on port 22, add `--ssh-port 2222`.

The bootstrap installs/upgrades required Ubuntu packages, clones this repo, creates the service account and persistent directories, generates the WireGuard server key if required, creates `wg0`, generates the administrative API key and dashboard password, configures Caddy/UFW/systemd, starts the API and WinBox relay services, enables the backup timer, and runs a health check.

Secrets and private keys are generated on the VM and are never committed to Git.

## Enroll a MikroTik

On the VPS:

```bash
cd /opt/tikcentral/current
sudo ./scripts/new-router.sh "Customer - Site"
```

That creates a 24-hour one-time enrollment token and prints a RouterOS 7 script. Paste the generated output into the remote MikroTik terminal.

The MikroTik creates its own WireGuard private key locally. Only its public key, identity, and serial number are sent to Tikcentral.

The server then:

1. validates and consumes the one-time token;
2. allocates the next address from `10.250.1.0/24`;
3. allocates a unique random public WinBox relay port;
4. adds the peer to live `wg0`;
5. persists the peer in `wg0.conf`;
6. records identity/serial/VPN/public-port information in SQLite;
7. returns the hub public key, endpoint, assigned address, and Remote WinBox name.

The generated MikroTik configuration uses a 25-second persistent keepalive. It permits:

- technician VPN WinBox/SSH from `10.250.254.0/24`;
- WinBox on TCP 8291 from only the Tikcentral hub address `10.250.0.1`, which is needed for the public relay.

## Add your laptop VPN

Generate the WireGuard keypair on your laptop and keep its private key there.

Pass only the public key to the VPS:

```bash
cd /opt/tikcentral/current
sudo ./scripts/add-admin-peer.sh "Yan-Erik Laptop" '<PUBLIC_KEY>' 10.250.254.2
```

The command prints your client configuration. Once the laptop VPN is connected, use the private dashboard address, for example `10.250.1.12:8291`.

If you do not have the VPN profile available, authorize your current public IP in the dashboard and use the public Remote WinBox target instead, for example `tikcentral.opticable.ca:23194`.

## Operations

```bash
cd /opt/tikcentral/current

sudo ./scripts/manage.sh status
sudo ./scripts/manage.sh update
sudo ./scripts/manage.sh restart
sudo ./scripts/manage.sh backup
sudo ./scripts/list-routers.sh
sudo wg show wg0
sudo journalctl -u tikcentral -f
sudo journalctl -u tikcentral-winbox-proxy -f
sudo journalctl -u caddy -f
```

The scheduled local SQLite backup runs daily and keeps 14 days. OVH snapshots/backups should also be enabled because local backups do not protect against complete VPS loss.

## Security model

- No private WireGuard keys or API secrets in Git.
- One-time enrollment tokens are stored only as SHA-256 hashes and expire after 24 hours.
- FastAPI is bound to `127.0.0.1`; Caddy is the public HTTPS entry point.
- The dashboard is protected with generated HTTP Basic credentials.
- `/api/enroll` remains public so routers can enroll from behind NAT/CGNAT.
- The API and public WinBox relay processes are not root.
- The `tikcentral` account only has passwordless sudo access to a narrow, root-owned WireGuard helper.
- Remote WinBox connections are checked against the temporary/permanent source-IP allowlist before they are proxied to a router.
- Routers cannot route to one another through the hub by default.

## Later additions

Possible later features, without making WireGuard depend on the web application:

- add-router button directly in the dashboard;
- RouterOS/model/version inventory;
- config/export backups;
- temporary LAN-device access;
- alerts;
- bulk jobs;
- technician accounts/roles;
- OVH API provisioning;
- external/offsite backups.
