"""Parsing and rendering of AmneziaWG server state.

Amnezia server layout (inside container, /opt/amnezia/awg/):
- wg0.conf        [Interface] + [Peer] sections, AmneziaWG obfuscation params
- clientsTable    JSON array, clientId == peer public key
- wireguard_server_public_key.key, wireguard_psk.key
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field


@dataclass
class Peer:
    public_key: str
    preshared_key: str = ""
    allowed_ips: str = ""


@dataclass
class ServerConfig:
    interface: dict[str, str] = field(default_factory=dict)
    peers: list[Peer] = field(default_factory=list)


# Keys copied verbatim into client configs (AmneziaWG obfuscation).
OBFUSCATION_KEYS = (
    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
    "I1", "I2", "I3", "I4", "I5",
    "HeaderProtectionKey", "ContentPaddingAddition",
    "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
    "KeepaliveTimeout", "MaxHandshakeAttempts",
    "RandomTrailers", "DisableCookies",
)


def parse_wg_conf(text: str) -> ServerConfig:
    cfg = ServerConfig()
    section = None
    current: Peer | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            if section == "Peer":
                current = Peer(public_key="")
                cfg.peers.append(current)
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if section == "Interface":
            cfg.interface[key] = value
        elif section == "Peer" and current is not None:
            if key == "PublicKey":
                current.public_key = value
            elif key == "PresharedKey":
                current.preshared_key = value
            elif key == "AllowedIPs":
                current.allowed_ips = value
    return cfg


def render_wg_conf(cfg: ServerConfig) -> str:
    lines = ["[Interface]"]
    lines += [f"{k} = {v}" for k, v in cfg.interface.items()]
    for p in cfg.peers:
        lines.append("")
        lines.append("[Peer]")
        lines.append(f"PublicKey = {p.public_key}")
        if p.preshared_key:
            lines.append(f"PresharedKey = {p.preshared_key}")
        lines.append(f"AllowedIPs = {p.allowed_ips}")
    return "\n".join(lines) + "\n"


def parse_clients_table(text: str) -> list[dict]:
    try:
        data = json.loads(text or "[]")
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


@dataclass
class PeerStats:
    endpoint: str
    allowed_ips: str
    latest_handshake: int  # unix seconds, 0 = never
    rx: int
    tx: int


def parse_wg_dump(text: str) -> dict[str, PeerStats]:
    """`wg show all dump`: interface lines have 5 fields, peer lines 9."""
    out: dict[str, PeerStats] = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 9:
            continue
        _, pubkey, _psk, endpoint, allowed, handshake, rx, tx, _keepalive = parts
        out[pubkey] = PeerStats(
            endpoint=endpoint,
            allowed_ips=allowed,
            latest_handshake=int(handshake or 0),
            rx=int(rx or 0),
            tx=int(tx or 0),
        )
    return out


def next_free_ip(cfg: ServerConfig) -> str:
    """First free address in the interface subnet (e.g. 10.8.1.0/24 -> 10.8.1.4)."""
    address = cfg.interface.get("Address", "")
    network = ipaddress.ip_network(address, strict=False)
    used = {network.network_address, network.broadcast_address}
    for value in cfg.interface.get("Address", "").split(","):
        used.add(ipaddress.ip_address(value.strip().split("/")[0]))
    for p in cfg.peers:
        for item in p.allowed_ips.split(","):
            item = item.strip()
            if item:
                used.add(ipaddress.ip_address(item.split("/")[0]))
    for host in network.hosts():
        if host not in used:
            return f"{host}/32"
    raise RuntimeError(f"no free addresses in {network}")


def render_client_conf(
    cfg: ServerConfig,
    *,
    private_key: str,
    preshared_key: str,
    address: str,
    server_public_key: str,
    endpoint_host: str,
    endpoint_port: str,
    dns: str = "1.1.1.1, 1.0.0.1",
) -> str:
    """Client config in AmneziaWG format (works in AmneziaWG / AmneziaVPN apps)."""
    itf = cfg.interface
    lines = ["[Interface]"]
    lines.append(f"PrivateKey = {private_key}")
    lines.append(f"Address = {address.split('/')[0]}/32")
    lines.append(f"DNS = {dns}")
    for key in OBFUSCATION_KEYS:
        if key in itf:
            lines.append(f"{key} = {itf[key]}")
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {server_public_key}")
    if preshared_key:
        lines.append(f"PresharedKey = {preshared_key}")
    lines.append("AllowedIPs = 0.0.0.0/0, ::/0")
    lines.append(f"Endpoint = {endpoint_host}:{endpoint_port}")
    keepalive = "25-35" if "HeaderProtectionKey" in itf else "25"
    lines.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(lines) + "\n"


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n} B"


# Keys wg-quick strip drops — local-only, the kernel must never see them.
_STRIP_DROP = {"Address", "DNS", "DNSSearch", "MTU", "Table",
               "PreUp", "PostUp", "PreDown", "PostDown", "SaveConfig"}


def strip_for_syncconf(conf_text: str) -> str:
    """Own implementation of `wg-quick strip`: keeps crypto keys (incl. AWG
    obfuscation), drops local-only keys. Used instead of wg-quick because host
    AppArmor profiles (Ubuntu 24.04+) can break wg-quick inside containers."""
    out = []
    for line in conf_text.splitlines():
        # wg syncconf parses no comments — drop them too
        if line.strip().startswith(("#", ";")):
            continue
        key = line.split("=", 1)[0].strip()
        if key in _STRIP_DROP:
            continue
        out.append(line)
    return "\n".join(out).strip() + "\n"
