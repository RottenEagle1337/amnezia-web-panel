# Amnezia Web Panel

A lightweight web panel for a self-hosted [Amnezia VPN](https://github.com/amnezia-vpn/amnezia-client) server.
It runs on the same host as the Amnezia containers, inside your local network.

![Python](https://img.shields.io/badge/python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)
![Docker](https://img.shields.io/badge/docker-compose-2496ED)
![Tests](https://img.shields.io/badge/tests-102%20passed-34d399)
![License](https://img.shields.io/badge/license-GPL--3.0-orange)

## Features

- **Info** — all `amnezia-*` containers: status, image, ports, uptime, restart.
  A "server as seen from outside" card: public IP, country, ISP, AS, address type.
- **WireGuard / AmneziaWG 3.1 keys** — issue, revoke, list clients (IP, online, endpoint, traffic).
  The config is shown **once**: a `vpn://` key with an animated multi-frame QR
  (same as the official app) and a `.conf` for AmneziaWG/WireGuard. Xray and OpenVPN
  are placeholders for now.
- **Proxy & DNS** — MTProxy and Telemt: mode, masking domain, `tg://` / `t.me` links
  with QR codes. AmneziaDNS: resolver network and IP.
- **One-click deploy** — install and removal of WireGuard, AmneziaWG 3.1, AmneziaDNS,
  MTProxy and Telemt right on their pages (see [Deploying protocols](#deploying-protocols)).
- **Config editor** — edit server configs from the browser with validation,
  automatic backups and restore (see [Config editor](#config-editor)).
- **Minimalism** — dark theme in the spirit of 3x-ui, no JS frameworks, one container.

## Quick start: server (Linux + Docker)

On the host where Amnezia is already running:

```bash
git clone https://github.com/RottenEagle1337/amnezia-web-panel.git amnezia-web-panel
cd amnezia-web-panel
./install.sh
```

The script asks for the panel port (**empty input — 8080 if free**), the
availability mode (**all interfaces / localhost only**), a password
(**empty input — generates a strong one and shows it once**; it is never stored),
detects your public IP, writes only a PBKDF2 hash into `.env`, and starts the
container. At the end it prints how to reach the panel.

Panel: `http://<server-ip>:8080`

The container restarts automatically (`unless-stopped`): it survives crashes and
server reboots. Liveness is tracked by a healthcheck (`/healthz`, shown in
`docker ps` as `healthy`/`unhealthy`).

Lost the password → `rm .env && ./install.sh`.

### Changing the panel port

The port is asked during installation. To change it later, edit `.env`:

```bash
# .env
PANEL_PORT=9090
```

```bash
docker compose up -d
```

The panel moves to `http://<server-ip>:9090`.

### Uninstall

```bash
./uninstall.sh          # Linux / macOS
.\uninstall.ps1         # Windows (PowerShell)
```

The script stops and removes the container and image, and on request the `.env`
and the project directory. Amnezia containers and data are not affected: the
panel only reads their configs and stores no data of its own.

## Quick start: local (mock mode)

Mock mode brings up in-memory fake Amnezia containers — the whole workflow runs
without a real server. Login: `admin`.

### macOS

```bash
git clone https://github.com/RottenEagle1337/amnezia-web-panel.git amnezia-web-panel && cd amnezia-web-panel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
PANEL_BACKEND=mock uvicorn app.main:app --port 8080
```

### Linux

```bash
git clone https://github.com/RottenEagle1337/amnezia-web-panel.git amnezia-web-panel && cd amnezia-web-panel
sudo apt install python3-venv   # Debian/Ubuntu; Fedora already ships venv with python3
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
PANEL_BACKEND=mock uvicorn app.main:app --port 8080
```

### Windows

PowerShell (requires [Python 3.12+](https://www.python.org/downloads/) with "Add to PATH"):

```powershell
git clone https://github.com/RottenEagle1337/amnezia-web-panel.git amnezia-web-panel; cd amnezia-web-panel
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
$env:PANEL_BACKEND = "mock"
uvicorn app.main:app --port 8080
```

> If PowerShell blocks venv activation: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

Open `http://localhost:8080` — password `admin`.

## Tests

```bash
pytest tests/ -q
```

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `PANEL_PASSWORD_HASH` | prod | PBKDF2 password hash (created by install.sh) |
| `PANEL_PASSWORD` | no | plaintext password, development only |
| `AWG_ENDPOINT_HOST` | prod | public server IP/domain for client configs |
| `AWG_ENDPOINT_PORT` | no | AWG port, default `51820` |
| `PANEL_BACKEND` | no | `docker` (prod) or `mock` (development) |
| `PANEL_PORT` | no | panel port on the host, default `8080` |
| `PANEL_BIND` | no | bind address, default `0.0.0.0`; use `127.0.0.1` on a public VPS |

### Public VPS? Use an SSH tunnel

The panel is designed for LAN. On a public VPS, pick **"Localhost only"** when
the installer asks for the availability mode, then reach it through an SSH tunnel:

```bash
# on your machine
ssh -L 8080:localhost:8080 user@your-vps
# then open http://localhost:8080
```

For non-interactive installs you can preset the mode: `PANEL_BIND=127.0.0.1 ./install.sh`.

## Deploying protocols

Protocols and services are deployed and removed right on their own pages
(VPN → protocol, Proxy & DNS → service) via the Docker API with the same
container names, ports and file layout as the official client — protocols
installed from the panel are discovered by the Amnezia app (and vice versa).

| Service | Container | Default port | Notes |
|---|---|---|---|
| WireGuard | `amnezia-wireguard` | 51820/udp | `wg0.conf`, image built locally from the vendored Dockerfile (not pulled) |
| AmneziaWG 3.1 | `amnezia-awg2` | 51821/udp | `awg0.conf`, AWG 3.1 extra obfuscation params |
| AmneziaDNS | `amnezia-dns` | — | unbound on `amnezia-dns-net` (172.29.172.254) |
| MTProxy | `amnezia-mtproxy` | 8443/tcp | FakeTLS, requires a masking domain |
| Telemt | `amnezia-telemt` | 443/tcp | TLS mode, requires a masking domain |

Removal optionally wipes data volumes. Xray and OpenVPN stay manual for now —
install them from the official app.

## Config editor

The **Server config** button on a protocol page opens a structured editor for
the live config (`wg0.conf` / `awg0.conf`, Telemt `config.toml`).

- Only the fields the official client exposes are editable; the rest is read-only.
- Every change is validated before applying; invalid input is rejected with errors.
- The previous config is backed up automatically (`.bak-<timestamp>`); any backup
  can be restored from the same page.
- Client peers are never touched — only the `[Interface]` section.

## Security

- The panel is **for LAN only**. Never expose port 8080 to the internet.
- The panel mounts `/var/run/docker.sock` — via the Docker API that is effectively
  root access to the host. The password is the only barrier.
- The password is stored only as a PBKDF2-SHA256 hash (600k iterations) in `.env`
  (mode 600). A password generated by install.sh is stored nowhere.
- Anti-brute-force: 5 failed logins from one IP → 5-minute lockout.
- Actions are allowed on `amnezia-*` containers only; the panel cannot restart itself from the UI.
- Sessions: HMAC cookie (12 h, httponly, samesite=lax), reset on panel restart.
- Optional hardening: [tecnativa/docker-socket-proxy](https://github.com/tecnativa/docker-socket-proxy) with an API whitelist.

## Troubleshooting

**`readlink: Permission denied` / `Unable to modify interface: No such device`
when issuing a WireGuard key.** On Ubuntu 24.04+ the host ships an AppArmor
profile named `wg-quick` that also confines `wg-quick` *inside containers*,
breaking it ([Ubuntu bug #2123870](https://bugs.launchpad.net/bugs/2123870)).
The panel works around it (own `strip` for `syncconf`, direct `ip`/`wg`
fallback in the container's start.sh), but the cleanest fix is on the host —
it also unbreaks the official client:

```bash
sudo apt install -y apparmor-utils && sudo aa-complain /etc/apparmor.d/wg-quick
docker restart amnezia-wireguard
```

## Project layout

```
app/
  main.py              FastAPI: routes, security headers
  auth.py              PBKDF2 hash, sessions, brute-force guard
  passhash.py          password hash generator (called by install.sh)
  keys.py              AWG client issue/revoke/list
  configedit.py        server config editor (validation, backups, restore)
  deploy.py            one-click install/remove of protocols and services
  deploy_assets/       vendored images (AmneziaDNS unbound Dockerfile)
  extras.py            MTProxy / Telemt / AmneziaDNS
  amnezia_fmt.py       AmneziaVPN format export (vpn://)
  awg.py               wg0.conf / clientsTable / wg show dump parsing
  crypto.py            WireGuard keys (X25519, pure Python)
  hostinfo.py          server's external view (ipinfo.io over HTTPS, 5 min cache)
  backend/             docker socket (prod) / in-memory mock (development)
tests/                 pytest: 102 tests
docs/research.md       Amnezia formats research (step 1)
install.sh             one-command server setup
uninstall.sh/.ps1      full removal scripts
```

## Roadmap

- Xray and OpenVPN management
- One-click deploy of Xray / OpenVPN from the panel

## License

GPL-3.0 — same as [amnezia-client](https://github.com/amnezia-vpn/amnezia-client). See [LICENSE](LICENSE).
