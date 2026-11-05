# Step 1. Research: a web panel for Amnezia VPN

Date: 2026-11-05

## Requirements (from the task)

- The panel deploys on the LAN, on the same server where Amnezia runs.
- MVP scope: key management (issue, revoke, list), service information,
  running services overview. Config management comes later.
- The simplest possible way to run it on the server.

## Existing solutions (survey)

| Project | Stack | Approach | Verdict |
|---|---|---|---|
| PRVTPRO/Amnezia-Web-Panel | FastAPI + Jinja | SSH into servers, all protocols (AWG, WG, Xray, Telemt, WARP, AdGuard, exit nodes) | Full-featured but an overbuilt monster |
| kyoresuas/amnezia-api | Node Fastify | Installs on the server itself, auto-discovers amnezia-awg/awg2/xray containers; REST: clients, traffic, load, QR, backup | Good logic reference; API only, no UI |
| slowy19/amnezia-panel | Next.js + tRPC + Prisma | UI on top of amnezia-api | Heavy stack, needs a separate DB |
| mihsergeev/amnezia-control | FastAPI + React + PostgreSQL | SSH (agentless), cascades, alerts, 2FA | Built for server fleets, overkill |
| AlexisHW/amneziawg-web-ui | Flask + Vue | Runs its OWN AWG server in a container | Not suitable: can't see an existing Amnezia install |
| bivlked/amneziawg-installer + awgram | Bash / Rust TG bot | CLI/bot, JSON output | Not a web panel; useful as an `awg` command reference |

## Amnezia server internals (key to the implementation)

- The Amnezia app deploys everything as Docker containers: `amnezia-awg` (AWG 1.5/2.0),
  `amnezia-awg2` (AWG 3.1), `amnezia-xray`, `amnezia-openvpn`, etc.
- Inside the container, `/opt/amnezia/awg/`:
  - `wg0.conf` — server config, one `[Peer]` section per client
  - `clientsTable` — JSON array: `clientId`, `userData.clientName`, `userData.creationDate`
  - `wireguard_server_public_key.key`, `wireguard_server_private_key.key`, `wireguard_psk.key`
- Issuing a key = append `[Peer]` to `wg0.conf` + a record in `clientsTable` +
  `wg syncconf wg0 <(wg-quick strip /opt/amnezia/awg/wg0.conf)` (hot reload, no restart).
- Revoking = remove the `[Peer]` from `wg0.conf` + remove from `clientsTable` + `syncconf`.
- Stats/online status: `wg show all dump` (rx/tx, last handshake, endpoint).
- Handing the key to a client: a `vpn://` (base64) config that the Amnezia app reads,
  or a classic `.conf` + QR.

## Tooling choices

- Backend: **Python + FastAPI** (async, Swagger out of the box)
- Amnezia access: **Docker socket** (`/var/run/docker.sock`), the `docker` pip package.
  No SSH needed — the panel runs on the same host.
- Frontend: **Jinja2 templates + vanilla JS** — no Node build, no SPA, works offline.
- QR: the `qrcode` pip package.
- Run: a single `docker-compose.yml` → `docker compose up -d` → `http://<server-ip>:8080`.

## Architecture

```
Browser (LAN)
   │  HTTP :8080
   ▼
┌─ Panel container (FastAPI + Jinja) ────────┐
│  auth (single password, session cookie)    │
│  /services  — list, status, logs           │
│  /keys      — issue/revoke/list/QR         │
└──────┬─────────────────────────────────────┘
       │ Docker API
       ▼
 amnezia-awg / amnezia-awg2 / amnezia-xray …
   /opt/amnezia/awg/{wg0.conf, clientsTable}
   wg show / wg syncconf
```

## Step plan

1. [x] Research (this document)
2. [x] Skeleton: FastAPI + docker SDK; Services page: amnezia-* containers, status, uptime
3. [x] Keys read-only: clientsTable parsing + `wg show dump` (traffic, handshake)
4. [x] Keys write: issue (keys → peer → clientsTable → syncconf → .conf/QR), revoke
5. [x] Services: logs (tail), restart
6. [x] Auth (password + session cookie) + basic UI
7. [x] Parser unit tests and web scenarios on mocks (18 tests)
8. [x] Security audit
9. [ ] Integration run on a real Amnezia server
10. [ ] Later: config management (wg0.conf editor with validation and backup)

## Risks

1. The `clientsTable` and `vpn://` formats are undocumented and may change between
   Amnezia versions. Mitigation: cross-check with amnezia-api and PRVTPRO code
   (they track the changes).
2. `docker.sock` in the panel = root on the host. LAN only, password mandatory,
   never expose it to the internet.
3. Xray has a different data model (JSON config, not [Peer]). The MVP covers AWG/AWG2 only;
   Xray is a separate step on request.
