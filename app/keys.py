"""Key management operations on an AmneziaWG container."""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from . import awg, crypto
from .amnezia_fmt import build_vpn_link
from .backend.base import Backend

AWG_DIR = "/opt/amnezia/awg"
CONF = f"{AWG_DIR}/wg0.conf"
TABLE = f"{AWG_DIR}/clientsTable"
SERVER_PUB = f"{AWG_DIR}/wireguard_server_public_key.key"

# Containers that hold an AWG-style layout we can manage.
MANAGEABLE = ("amnezia-awg", "amnezia-awg2")


@dataclass
class ClientView:
    client_id: str          # == public key
    name: str
    created: str
    ip: str
    online: bool
    endpoint: str
    last_handshake: int
    rx: str
    tx: str
    orphaned: bool          # in clientsTable but missing from wg0.conf


class AWGError(Exception):
    pass


def _run(backend: Backend, container: str, cmd: list[str]) -> str:
    code, out = backend.exec(container, cmd)
    if code != 0:
        raise AWGError(f"{' '.join(cmd)} failed ({code}): {out.strip()}")
    return out


def _read(backend: Backend, container: str, path: str) -> str:
    code, out = backend.exec(container, ["cat", path])
    if code != 0:
        return ""
    return out


def _write(backend: Backend, container: str, path: str, content: str) -> None:
    b64 = base64.b64encode(content.encode()).decode()
    _run(backend, container, ["sh", "-c", f"echo {b64} | base64 -d > {path}"])


def _syncconf(backend: Backend, container: str) -> None:
    _run(backend, container, ["bash", "-c", f"wg syncconf wg0 <(wg-quick strip {CONF})"])


def _load(backend: Backend, container: str) -> tuple[awg.ServerConfig, list[dict]]:
    cfg = awg.parse_wg_conf(_read(backend, container, CONF))
    table = awg.parse_clients_table(_read(backend, container, TABLE))
    return cfg, table


def list_clients(backend: Backend, container: str) -> list[ClientView]:
    cfg, table = _load(backend, container)
    stats = awg.parse_wg_dump(_run(backend, container, ["wg", "show", "all", "dump"]))
    ips = {p.public_key: p.allowed_ips for p in cfg.peers}
    now = int(datetime.now(timezone.utc).timestamp())
    views = []
    for entry in table:
        cid = entry.get("clientId", "")
        ud = entry.get("userData", {})
        st = stats.get(cid)
        hs = st.latest_handshake if st else 0
        views.append(ClientView(
            client_id=cid,
            name=ud.get("clientName", "(unnamed)"),
            created=ud.get("creationDate", ""),
            ip=ips.get(cid, (st.allowed_ips if st else "")),
            online=bool(hs and now - hs < 180),
            endpoint=st.endpoint if st else "",
            last_handshake=hs,
            rx=awg.human_bytes(st.rx) if st else "0 B",
            tx=awg.human_bytes(st.tx) if st else "0 B",
            orphaned=cid not in ips,
        ))
    views.sort(key=lambda v: v.created)
    return views


def create_client(backend: Backend, container: str, name: str,
                  endpoint_host: str, endpoint_port: str) -> tuple[str, str, str]:
    """Create a peer. Returns (name, conf_text, vpn_link). Shown once, never stored."""
    name = name.strip()
    # The name lands in clientsTable and vpn:// — control characters are rejected.
    if not name or len(name) > 64 or any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        raise AWGError("bad client name")
    cfg, table = _load(backend, container)

    private_key = crypto.gen_private_key()
    public_key = crypto.public_key(private_key)
    preshared_key = crypto.gen_psk()
    address = awg.next_free_ip(cfg)

    cfg.peers.append(awg.Peer(public_key=public_key, preshared_key=preshared_key, allowed_ips=address))
    _write(backend, container, CONF, awg.render_wg_conf(cfg))

    table.append({"clientId": public_key, "userData": {
        "clientName": name,
        "creationDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    }})
    _write(backend, container, TABLE, json.dumps(table, indent=2))
    _syncconf(backend, container)

    server_pub = _read(backend, container, SERVER_PUB).strip()
    # Real listen port from the server config wins over the env default.
    endpoint_port = cfg.interface.get("ListenPort", endpoint_port)
    config_text = awg.render_client_conf(
        cfg, private_key=private_key, preshared_key=preshared_key, address=address,
        server_public_key=server_pub, endpoint_host=endpoint_host, endpoint_port=endpoint_port,
    )
    vpn_link = build_vpn_link(
        cfg, container=container, client_name=name,
        client_private_key=private_key, client_public_key=public_key,
        preshared_key=preshared_key, client_ip=address.split("/")[0],
        server_public_key=server_pub, endpoint_host=endpoint_host,
        endpoint_port=endpoint_port, config_text=config_text,
    )
    return name, config_text, vpn_link


def revoke_client(backend: Backend, container: str, client_id: str) -> None:
    cfg, table = _load(backend, container)
    peers = [p for p in cfg.peers if p.public_key != client_id]
    new_table = [e for e in table if e.get("clientId") != client_id]
    if len(peers) == len(cfg.peers) and len(new_table) == len(table):
        raise AWGError("client not found")
    cfg.peers = peers
    _write(backend, container, CONF, awg.render_wg_conf(cfg))
    _write(backend, container, TABLE, json.dumps(new_table, indent=2))
    _syncconf(backend, container)
