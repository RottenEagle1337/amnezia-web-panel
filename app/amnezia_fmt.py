"""Export of client configs in the AmneziaVPN `vpn://` format.

Format (matches amnezia-client importController + kyoresuas/amnezia-api):
    vpn://<base64url( uint32BE(len) + zlib.deflate(json) )>
"""
from __future__ import annotations

import base64
import json
import struct
import zlib

from .awg import ServerConfig

# Interface keys copied into the Amnezia JSON "awg" block.
AWG2_KEYS = ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4")
AWG3_KEYS = (
    "S3", "S4", "I1", "I2", "I3", "I4", "I5",
    "HeaderProtectionKey", "ContentPaddingAddition",
    "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
    "KeepaliveTimeout", "MaxHandshakeAttempts",
    "RandomTrailers", "DisableCookies",
)
SPECIAL_JUNK_KEYS = ("I1", "I2", "I3", "I4", "I5")

DNS1 = "1.1.1.1"
DNS2 = "1.0.0.1"
MTU = "1376"


def is_v3(cfg: ServerConfig) -> bool:
    return "HeaderProtectionKey" in cfg.interface


def encode_vpn_config(server_json: dict) -> str:
    raw = json.dumps(server_json, ensure_ascii=False).encode()
    payload = struct.pack(">I", len(raw)) + zlib.compress(raw, 8)
    return "vpn://" + base64.urlsafe_b64encode(payload).decode().rstrip("=")


# --- Multi-part QR (Amnezia app scans an animated series for long keys) ---

QR_MAGIC_CODE = 1984
QR_CHUNK_SIZE = 850


def vpn_qr_frames(vpn_link: str) -> list[str]:
    """Split a vpn:// payload into QDataStream frames (base64url), one per QR.

    Frame layout (big-endian): int16 magic, uint8 count, uint8 index,
    uint32 chunk length, chunk bytes. Matches amnezia-client QR reader.
    """
    payload = base64.urlsafe_b64decode(
        vpn_link.removeprefix("vpn://") + "=" * (-len(vpn_link.removeprefix("vpn://")) % 4))
    frames = []
    count = max(1, (len(payload) + QR_CHUNK_SIZE - 1) // QR_CHUNK_SIZE)
    for index in range(count):
        chunk = payload[index * QR_CHUNK_SIZE:(index + 1) * QR_CHUNK_SIZE]
        frame = struct.pack(">hBBI", QR_MAGIC_CODE, count, index, len(chunk)) + chunk
        frames.append(base64.urlsafe_b64encode(frame).decode().rstrip("="))
    return frames


def build_vpn_link(
    cfg: ServerConfig,
    *,
    container: str,
    client_name: str,
    client_private_key: str,
    client_public_key: str,
    preshared_key: str,
    client_ip: str,
    server_public_key: str,
    endpoint_host: str,
    endpoint_port: str,
    config_text: str,
    location: str = "",
) -> str:
    """Self-hosted guest key in the format the AmneziaVPN app imports."""
    v3 = is_v3(cfg)
    itf = cfg.interface

    params: dict[str, str] = {}
    for key in AWG2_KEYS + AWG3_KEYS:
        value = itf.get(key, "")
        # Amnezia stores I1-I5 even when empty, drops other empty params
        if value or key in SPECIAL_JUNK_KEYS:
            params[key] = value

    listen_port = itf.get("ListenPort", endpoint_port)
    keepalive = "25-35" if v3 else "25"

    last_config = {
        **params,
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "clientId": client_public_key,
        "client_ip": client_ip,
        "client_priv_key": client_private_key,
        "client_pub_key": client_public_key,
        "config": config_text,
        "hostName": endpoint_host,
        "mtu": MTU,
        "persistent_keep_alive": keepalive,
        "port": int(listen_port) if listen_port.isdigit() else None,
        "psk_key": preshared_key,
        "server_pub_key": server_public_key,
    }

    if container == "amnezia-wireguard":
        # Classic WireGuard: the app expects a "wireguard" block, no obfuscation.
        block_key = "wireguard"
        block = {
            "last_config": json.dumps(last_config, ensure_ascii=False, indent=2),
            "port": str(listen_port),
            "transport_proto": "udp",
        }
        description = f"{client_name} | {location or 'WireGuard'}"
    else:
        block_key = "awg"
        block = {
            **params,
            "protocol_version": "3.1" if v3 else "2.0",
            "last_config": json.dumps(last_config, ensure_ascii=False, indent=2),
            "port": str(listen_port),
            "transport_proto": "udp",
        }
        description = f"{client_name} | {location or ('AmneziaWG3' if v3 else 'AmneziaWG')}"

    server_json = {
        "containers": [{block_key: block, "container": container}],
        "defaultContainer": container,
        "description": description,
        "dns1": DNS1,
        "dns2": DNS2,
        "hostName": endpoint_host,
    }
    return encode_vpn_config(server_json)
