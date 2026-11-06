"""In-memory mock of an Amnezia server for local development and tests.

Imitates containers amnezia-awg / amnezia-awg2 (AWG layout) plus a couple of
other amnezia-* services. File writes go to an in-memory FS, so the full
create/revoke flow works end to end without a real server.
"""
from __future__ import annotations

import base64
import copy
import secrets
from datetime import datetime, timedelta, timezone

from .base import ContainerNotFound, ServiceInfo

WG0_CONF_AWG = """[Interface]
PrivateKey = aNk1f4EW1RfR0c9l0n6W3u0m0y6p9dYf8y3oF8xVq2E=
Address = 10.8.1.1/24
ListenPort = 51820
Jc = 3
Jmin = 50
Jmax = 1000
S1 = 96
S2 = 38
H1 = 1
H2 = 2
H3 = 3
H4 = 4
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = XkN3v7mQ2pL8sR4tY6uI9oP1aS5dF7gH0jK3lZ8cV0nE=
PresharedKey = mP9qW2eR5tY8uI1oP4aS7dF0gH3jK6lZ9cV2bN5mQ8wE=
AllowedIPs = 10.8.1.2/32

[Peer]
PublicKey = bN5mQ8wE1rT4yU7iO0pA3sD6fG9hJ2kL5zX8cV1bN4mE=
PresharedKey = qW2eR5tY8uI1oP4aS7dF0gH3jK6lZ9cV2bN5mQ8wE1rT4=
AllowedIPs = 10.8.1.3/32
"""

WG0_CONF_AWG2 = """[Interface]
PrivateKey = cV2bN5mQ8wE1rT4yU7iO0pA3sD6fG9hJ2kL5zX8cV1b4=
Address = 10.9.9.1/24
ListenPort = 51821
Jc = 4
Jmin = 40
Jmax = 70
S1 = 52
S2 = 43
S3 = 21
S4 = 15
H1 = 1234567890
H2 = 1234567891
H3 = 1234567892
H4 = 1234567893
I1 = <b 0x48656c6c6f>
HeaderProtectionKey = hdrProtKeyE1xAmPlE2yAmPlE3yAmPlE4yAmPlE5y=
ContentPaddingAddition = 12-36
RekeyAfterTime = 110-140
RekeyTimeout = 5-7
RejectAfterTime = 160-180
KeepaliveTimeout = 9-13
MaxHandshakeAttempts = 16-20
RandomTrailers = on
DisableCookies = on
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = zX8cV1bN4mQ7wE0rT3yU6iO9pA2sD5fG8hJ1kL4zX7cE=
PresharedKey = R5tY8uI1oP4aS7dF0gH3jK6lZ9cV2bN5mQ8wE1rT4yU7i=
AllowedIPs = 10.9.9.2/32
"""

CLIENTS_AWG = [
    {"clientId": "XkN3v7mQ2pL8sR4tY6uI9oP1aS5dF7gH0jK3lZ8cV0nE=",
     "userData": {"clientName": "phone-ivan", "creationDate": "2026-10-01T12:00:00.000Z"}},
    {"clientId": "bN5mQ8wE1rT4yU7iO0pA3sD6fG9hJ2kL5zX8cV1bN4mE=",
     "userData": {"clientName": "laptop-anna", "creationDate": "2026-10-20T09:30:00.000Z"}},
]

CLIENTS_AWG2 = [
    {"clientId": "zX8cV1bN4mQ7wE0rT3yU6iO9pA2sD5fG8hJ1kL4zX7cE=",
     "userData": {"clientName": "tablet-oleg", "creationDate": "2026-11-01T18:45:00.000Z"}},
]

_now = datetime.now(timezone.utc)


def _ts(dt: datetime) -> str:
    return str(int(dt.timestamp()))


WG_DUMP_AWG = (
    # interface line: private, public, port, fwmark
    "wg0\taNk1f4EW1RfR0c9l0n6W3u0m0y6p9dYf8y3oF8xVq2E=\tsrVpubkeyE1xAmPlE2yAmPlE3yAmPlE4yAmPlE5yA=\t51820\toff\n"
    # peer lines: pubkey, psk, endpoint, allowed, handshake, rx, tx, keepalive
    f"wg0\tXkN3v7mQ2pL8sR4tY6uI9oP1aS5dF7gH0jK3lZ8cV0nE=\tmP9qW2eR5tY8uI1oP4aS7dF0gH3jK6lZ9cV2bN5mQ8wE=\t203.0.113.50:41234\t10.8.1.2/32\t{_ts(_now - timedelta(minutes=2))}\t104857600\t52428800\toff\n"
    f"wg0\tbN5mQ8wE1rT4yU7iO0pA3sD6fG9hJ2kL5zX8cV1bN4mE=\tqW2eR5tY8uI1oP4aS7dF0gH3jK6lZ9cV2bN5mQ8wE1rT4=\t(none)\t10.8.1.3/32\t{_ts(_now - timedelta(days=4))}\t2097152\t1048576\toff\n"
)

WG_DUMP_AWG2 = (
    "wg0\tcV2bN5mQ8wE1rT4yU7iO0pA3sD6fG9hJ2kL5zX8cV1b4=\tsrVpubkeyAwg2xAmPlE2yAmPlE3yAmPlE4yAmPlE=\t51821\toff\n"
    f"wg0\tzX8cV1bN4mQ7wE0rT3yU6iO9pA2sD5fG8hJ1kL4zX7cE=\tR5tY8uI1oP4aS7dF0gH3jK6lZ9cV2bN5mQ8wE1rT4yU7i=\t198.51.100.7:51821\t10.9.9.2/32\t{_ts(_now - timedelta(seconds=40))}\t734003200\t188743680\toff\n"
)


TELEMT_CONFIG = """[general]
use_middle_proxy = true

[general.modes]
classic = false
secure = false
tls = true

[censorship]
tls_domain = "googletagmanager.com"
mask = true
tls_emulation = false

[access.users]
tg_main = "7a2f8b5c9d0e1f2a3b4c5d6e7f8a9b0c"
"""

MTPROXY_SECRET = "1a2b3c4d5e6f7890abcdef1234567890"


def _fake_key() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


class MockBackend:
    """Enough of the Backend contract for the whole UI flow."""

    def __init__(self) -> None:
        self._fs: dict[str, dict[str, str]] = {
            "amnezia-awg": {
                "/opt/amnezia/awg/wg0.conf": WG0_CONF_AWG,
                "/opt/amnezia/awg/clientsTable": __import__("json").dumps(CLIENTS_AWG, indent=2),
                "/opt/amnezia/awg/wireguard_server_public_key.key": "srVpubkeyE1xAmPlE2yAmPlE3yAmPlE4yAmPlE5yA=",
                "/opt/amnezia/awg/wireguard_psk.key": "pskMockKeyE1xAmPlE2yAmPlE3yAmPlE4yAmPlE5y=",
            },
            "amnezia-awg2": {
                "/opt/amnezia/awg/awg0.conf": WG0_CONF_AWG2,
                "/opt/amnezia/awg/clientsTable": __import__("json").dumps(CLIENTS_AWG2, indent=2),
                "/opt/amnezia/awg/wireguard_server_public_key.key": "srVpubkeyAwg2xAmPlE2yAmPlE3yAmPlE4yAmPlE=",
                "/opt/amnezia/awg/wireguard_psk.key": "pskMockKeyAwg2xAmPlE2yAmPlE3yAmPlE4yAmPl=",
            },
            "amnezia-mtproxy": {
                "/data/secret": MTPROXY_SECRET,
            },
            "amnezia-telemt": {
                "/data/config.toml": TELEMT_CONFIG,
            },
            "amnezia-dns": {},
        }
        self._inspect = {
            "amnezia-mtproxy": {
                "env": {"MTPROXY_TRANSPORT_MODE": "faketls", "MTPROXY_TLS_DOMAIN": "googletagmanager.com",
                        "MTPROXY_PORT": "8443"},
                "ports": {"8443/tcp": "8443"},
                "networks": {"bridge": {"ip": "172.17.0.5"}},
            },
            "amnezia-telemt": {
                "env": {},
                "ports": {"443/tcp": "443"},
                "networks": {"bridge": {"ip": "172.17.0.6"}},
            },
            "amnezia-dns": {
                "env": {},
                "ports": {},
                "networks": {"amnezia-dns-net": {"ip": "172.29.172.254"}},
            },
        }
        self._dumps = {"amnezia-awg": WG_DUMP_AWG, "amnezia-awg2": WG_DUMP_AWG2}
        self._services = [
            ServiceInfo("amnezia-awg", "running", "amneziavpn/amneziawg-go:latest",
                        (_now - timedelta(days=6)).isoformat(), "51820/udp->51820"),
            ServiceInfo("amnezia-awg2", "running", "amneziavpn/amneziawg-go:latest",
                        (_now - timedelta(days=3)).isoformat(), "51821/udp->51821"),
            ServiceInfo("amnezia-xray", "running", "amneziavpn/xray:latest",
                        (_now - timedelta(days=6)).isoformat(), "443/tcp->443"),
            ServiceInfo("amnezia-openvpn", "exited", "amneziavpn/openvpn-cloak:latest", "", "1194/udp->1194"),
            ServiceInfo("amnezia-mtproxy", "running", "amneziavpn/mtproxy:latest",
                        (_now - timedelta(days=6)).isoformat(), "8443/tcp->8443"),
            ServiceInfo("amnezia-telemt", "running", "telemt/telemt:latest",
                        (_now - timedelta(days=2)).isoformat(), "443/tcp->443"),
            ServiceInfo("amnezia-dns", "running", "amneziavpn/amnezia-dns:latest",
                        (_now - timedelta(days=6)).isoformat(), ""),
        ]
        self.restarted: list[str] = []
        self.synced: list[str] = []

    def list_services(self) -> list[ServiceInfo]:
        return copy.deepcopy(self._services)

    def exec(self, container: str, cmd: list[str]) -> tuple[int, str]:
        files = self._fs.get(container)
        if files is None:
            raise ContainerNotFound(container)
        joined = " ".join(cmd)

        if cmd[:1] == ["cat"] and len(cmd) == 2:
            path = cmd[1]
            if path in files:
                return 0, files[path]
            return 1, f"cat: {path}: No such file or directory"
        if cmd[:2] == ["wg", "genkey"] or cmd[:2] == ["awg", "genkey"]:
            return 0, _fake_key() + "\n"
        if cmd[:2] == ["wg", "genpsk"] or cmd[:2] == ["awg", "genpsk"]:
            return 0, _fake_key() + "\n"
        if cmd[:3] == ["wg", "show", "all"]:
            return 0, self._dumps[container]
        if "syncconf" in joined:
            self.synced.append(container)
            return 0, ""
        if cmd[:2] == ["sh", "-c"] and "| base64 -d >" in cmd[2]:
            b64, path = cmd[2].split("| base64 -d >", 1)
            b64 = b64.replace("echo", "").strip()
            files[path.strip()] = base64.b64decode(b64).decode()
            return 0, ""
        return 1, f"mock: unsupported command: {joined}"

    def restart(self, container: str) -> None:
        if container not in self._fs and container not in {s.name for s in self._services}:
            raise ContainerNotFound(container)
        self.restarted.append(container)

    def inspect(self, container: str) -> dict:
        if container not in self._inspect:
            raise ContainerNotFound(container)
        return copy.deepcopy(self._inspect[container])

    def logs(self, container: str, tail: int = 200) -> str:
        if container not in {s.name for s in self._services}:
            raise ContainerNotFound(container)
        return "\n".join(f"2026-11-05T20:0{i % 10}: mock log line {i} for {container}" for i in range(min(tail, 20)))
