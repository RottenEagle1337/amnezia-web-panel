"""One-click deployment of Amnezia protocols and services via the Docker API.

Container parameters mirror amnezia-client/server_scripts (dev branch).
Obfuscation values are randomized per install, as the official client does.
"""
from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import crypto
from .backend.base import Backend
from .keys import AWGError, _write

AWG_IMAGE = "amneziavpn/amneziawg-go:latest"


@dataclass
class DeploySpec:
    key: str
    container: str
    image: str
    kind: str            # "vpn" | "service"
    default_port: int
    proto: str = "udp"   # port mapping protocol ("" = no published port)
    needs_domain: bool = False
    version: str = ""    # AWG entries: "2.0" | "3.1"
    subnet: str = ""
    iface: str = ""
    conf_path: str = ""


DEPLOYABLE: dict[str, DeploySpec] = {}

DEPLOYABLE["awg"] = DeploySpec("awg", "amnezia-awg", AWG_IMAGE, "vpn", 51820,
                               version="2.0", subnet="10.8.1.0/24", iface="wg0",
                               conf_path="/opt/amnezia/awg/wg0.conf")
DEPLOYABLE["awg2"] = DeploySpec("awg2", "amnezia-awg2", AWG_IMAGE, "vpn", 51821,
                                version="3.1", subnet="10.9.9.0/24", iface="awg0",
                                conf_path="/opt/amnezia/awg/awg0.conf")


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def valid_domain(value: str) -> bool:
    """Strict hostname check — the value lands in TOML configs and container env."""
    return bool(_DOMAIN_RE.match(value.strip().lower()))


def _absent(backend: Backend, spec: DeploySpec, port: int) -> None:
    """Shared guard: container must not exist, host port must be free."""
    for s in backend.list_services():
        if s.name == spec.container:
            raise AWGError(f"{spec.container} already exists")
        if s.ports.endswith(f"->{port}"):
            raise AWGError(f"port {port} is already used by {s.name}")


def _rand_obfuscation(version: str) -> dict[str, str]:
    """Per-install randomized AWG obfuscation (official client behavior)."""
    rng = secrets.SystemRandom()
    s1 = rng.randint(12, 149)
    s2 = rng.randint(12, 149)
    while s1 + 56 == s2:
        s2 = rng.randint(12, 149)
    headers = set()
    while len(headers) < 4:
        headers.add(rng.randint(5, 2**31 - 1))
    h1, h2, h3, h4 = sorted(headers)  # sorted -> stable test expectations
    params = {
        "Jc": str(rng.randint(4, 6)), "Jmin": "10", "Jmax": "50",
        "S1": str(s1), "S2": str(s2),
        "H1": str(h1), "H2": str(h2), "H3": str(h3), "H4": str(h4),
    }
    if version == "3.1":
        params.update({
            "S3": str(rng.randint(12, 63)), "S4": "12",
            "HeaderProtectionKey": crypto.gen_psk(),
            "ContentPaddingAddition": "10-100",
            "RekeyAfterTime": "100-120", "RekeyTimeout": "3-7",
            "RejectAfterTime": "150-180", "KeepaliveTimeout": "5-15",
            "MaxHandshakeAttempts": "15-20",
            "RandomTrailers": "on", "DisableCookies": "on",
        })
    return params


def _awg_conf(version: str, port: int, subnet: str, iface: str) -> tuple[str, str]:
    priv = crypto.gen_private_key()
    params = _rand_obfuscation(version)
    lines = ["[Interface]", f"PrivateKey = {priv}",
             f"Address = {subnet.split('/')[0].rsplit('.', 1)[0]}.1/24",
             f"ListenPort = {port}"]
    lines += [f"{k} = {v}" for k, v in params.items()]
    lines += [
        f"PostUp = iptables -A FORWARD -i {iface} -j ACCEPT; "
        f"iptables -A FORWARD -o {iface} -j ACCEPT; "
        f"iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
        f"PostDown = iptables -D FORWARD -i {iface} -j ACCEPT; "
        f"iptables -D FORWARD -o {iface} -j ACCEPT; "
        f"iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
        "",
    ]
    return "\n".join(lines), crypto.public_key(priv)


def _ensure_dir(backend: Backend, container: str, path: str) -> None:
    """The image entrypoint creates /opt/amnezia/awg asynchronously — wait for it."""
    for _ in range(5):
        code, _ = backend.exec(container, ["mkdir", "-p", path])
        if code == 0:
            return
        time.sleep(1)
    raise AWGError(f"cannot create {path} in {container}")


def deploy_awg(backend: Backend, version: str, port: int) -> None:
    """Deploy amnezia-awg (2.0, wg0.conf) or amnezia-awg2 (3.1, awg0.conf)."""
    spec = DEPLOYABLE["awg" if version == "2.0" else "awg2"]
    _absent(backend, spec, port)
    backend.pull_image(spec.image)
    backend.run_container(
        spec.container, spec.image,
        ports={f"{port}/udp": port}, env={},
        volumes={"/lib/modules": {"bind": "/lib/modules", "mode": "rw"}},
        privileged=True, cap_add=["NET_ADMIN", "SYS_MODULE"],
        sysctls={"net.ipv4.conf.all.src_valid_mark": "1"})
    _ensure_dir(backend, spec.container, "/opt/amnezia/awg")
    conf, pub = _awg_conf(version, port, spec.subnet, spec.iface)
    _write(backend, spec.container, spec.conf_path, conf)
    _write(backend, spec.container, "/opt/amnezia/awg/wireguard_server_public_key.key", pub + "\n")
    _write(backend, spec.container, "/opt/amnezia/awg/wireguard_psk.key", crypto.gen_psk() + "\n")
    _write(backend, spec.container, "/opt/amnezia/awg/clientsTable", "[]\n")
    try:
        backend.connect_network("amnezia-dns-net", spec.container)
    except Exception:
        pass  # DNS network is optional
    backend.restart(spec.container)  # pick up the written config


DEPLOYABLE["dns"] = DeploySpec("dns", "amnezia-dns", "amnezia-dns", "service", 53, proto="")
DEPLOYABLE["mtproxy"] = DeploySpec("mtproxy", "amnezia-mtproxy", "amneziavpn/mtproxy:latest",
                                   "service", 8443, proto="tcp", needs_domain=True)
DEPLOYABLE["telemt"] = DeploySpec("telemt", "amnezia-telemt", "ghcr.io/telemt/telemt:latest",
                                  "service", 443, proto="tcp", needs_domain=True)

DNS_NETWORK = "amnezia-dns-net"
DNS_SUBNET = "172.29.172.0/24"
DNS_IP = "172.29.172.254"


def deploy_dns(backend: Backend) -> None:
    """AmneziaDNS: unbound in a vendored image on its own docker network."""
    spec = DEPLOYABLE["dns"]
    _absent(backend, spec, 0)
    backend.ensure_network(DNS_NETWORK, DNS_SUBNET)
    dockerfile = (Path(__file__).parent / "deploy_assets" / "dns.Dockerfile").read_text()
    backend.build_image(spec.image, dockerfile)
    backend.run_container(spec.container, spec.image, ports={}, env={}, volumes={})
    backend.connect_network(DNS_NETWORK, spec.container, ip=DNS_IP)
    # Connect the already-running Amnezia containers, as the official client does —
    # otherwise protocols installed before DNS never see the resolver.
    for s in backend.list_services():
        if s.name.startswith("amnezia-") and s.name != spec.container:
            try:
                backend.connect_network(DNS_NETWORK, s.name)
            except Exception:
                pass  # already connected or gone — non-fatal


def _wait_file(backend: Backend, container: str, path: str, tries: int = 10) -> bool:
    """Poll until a file appears inside the container (entrypoints write asynchronously)."""
    for _ in range(tries):
        code, _ = backend.exec(container, ["cat", path])
        if code == 0:
            return True
        time.sleep(1)
    return False


def deploy_mtproxy(backend: Backend, port: int, tls_domain: str) -> None:
    spec = DEPLOYABLE["mtproxy"]
    _absent(backend, spec, port)
    if not valid_domain(tls_domain):
        raise AWGError(f"invalid masking domain: {tls_domain!r}")
    backend.pull_image(spec.image)
    backend.run_container(
        spec.container, spec.image,
        ports={f"{port}/tcp": port},
        env={"MTPROXY_PORT": str(port), "MTPROXY_TRANSPORT_MODE": "faketls",
             "MTPROXY_TLS_DOMAIN": tls_domain},
        volumes={"amnezia-mtproxy-data": {"bind": "/data", "mode": "rw"}})
    # The image entrypoint generates /data/secret asynchronously; without it the
    # extras page cannot build connection links, so wait before returning.
    if not _wait_file(backend, spec.container, "/data/secret"):
        raise AWGError("mtproxy started but /data/secret did not appear — check container logs")


TELEMT_CONFIG = '''show_link = ["tg_main"]

[general]
use_middle_proxy = false

[general.modes]
classic = false
secure = false
tls = true

[server]
port = {port}
listen_addr_ipv4 = "0.0.0.0"

[censorship]
tls_domain = "{tls_domain}"
mask = true
fake_cert_len = 2048

[access.users]
tg_main = "{secret}"
'''


def deploy_telemt(backend: Backend, port: int, tls_domain: str) -> None:
    spec = DEPLOYABLE["telemt"]
    _absent(backend, spec, port)
    if not valid_domain(tls_domain):
        raise AWGError(f"invalid masking domain: {tls_domain!r}")
    backend.pull_image(spec.image)
    backend.run_container(
        spec.container, spec.image,
        ports={f"{port}/tcp": port}, env={"RUST_LOG": "info"},
        volumes={"amnezia-telemt-data": {"bind": "/etc/telemt", "mode": "rw"}},
        cap_add=["NET_BIND_SERVICE"], ulimits=True)
    _write(backend, spec.container, "/etc/telemt/config.toml",
           TELEMT_CONFIG.format(port=port, tls_domain=tls_domain,
                                secret=secrets.token_hex(16)))
    backend.restart(spec.container)


def by_container(container: str) -> tuple[str, DeploySpec] | tuple[None, None]:
    """Reverse lookup: container name -> (deploy key, spec)."""
    for key, spec in DEPLOYABLE.items():
        if spec.container == container:
            return key, spec
    return None, None


def remove_service(backend: Backend, key: str, wipe_data: bool) -> None:
    spec = DEPLOYABLE[key]
    backend.remove_container(spec.container, remove_volumes=wipe_data)
