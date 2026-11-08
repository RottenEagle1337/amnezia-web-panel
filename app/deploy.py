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

DEPLOYABLE["wireguard"] = DeploySpec("wireguard", "amnezia-wireguard", "amnezia-wireguard",
                                     "vpn", 51820, subnet="10.8.1.0/24", iface="wg0",
                                     conf_path="/opt/amnezia/wireguard/wg0.conf")
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


# The client's images idle on `tail -f /dev/null` until the REAL start script is
# written to /opt/amnezia/start.sh — mirroring client/server_scripts/awg{,_legacy}.
AWG_START_SH = '''#!/bin/bash
echo "Container startup"

# kill daemons in case of restart
{quick} down {conf}

# start daemons if configured
if [ -f {conf} ]; then ({quick} up {conf}); fi

# Allow traffic on the TUN interface.
iptables -A INPUT -i {iface} -j ACCEPT
iptables -A FORWARD -i {iface} -j ACCEPT
iptables -A OUTPUT -o {iface} -j ACCEPT

# Allow forwarding traffic only from the VPN.
iptables -A FORWARD -i {iface} -o eth0 -s {subnet_ip}/{cidr} -j ACCEPT
iptables -A FORWARD -i {iface} -o eth1 -s {subnet_ip}/{cidr} -j ACCEPT

iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -t nat -A POSTROUTING -s {subnet_ip}/{cidr} -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s {subnet_ip}/{cidr} -o eth1 -j MASQUERADE

tail -f /dev/null
'''


def _awg_start_sh(version: str, conf_path: str, subnet: str, iface: str) -> str:
    quick = "wg-quick" if version == "2.0" else "awg-quick"
    subnet_ip, cidr = subnet.split("/")
    return AWG_START_SH.format(quick=quick, conf=conf_path, iface=iface,
                               subnet_ip=subnet_ip, cidr=cidr)


# WireGuard start.sh: like AWG_START_SH but with a fallback — host AppArmor
# (Ubuntu 24.04+, profile "wg-quick") can break wg-quick inside containers with
# "readlink: Permission denied", leaving the interface down. Fall back to
# direct ip/wg setup with our own strip (same keys wg-quick strip drops).
WG_START_SH = '''#!/bin/bash
echo "Container startup"

CONF={conf}
IFACE={iface}
ADDR=$(awk -F' = ' '/^Address/ {{print $2; exit}}' "$CONF" 2>/dev/null)

# kill daemons in case of restart
wg-quick down "$CONF" 2>/dev/null || ip link del "$IFACE" 2>/dev/null || true

# start daemons if configured
if [ -f "$CONF" ]; then
  if ! (wg-quick up "$CONF"); then
    echo "wg-quick failed (host AppArmor?) - falling back to direct setup"
    ip link del "$IFACE" 2>/dev/null || true
    ip link add dev "$IFACE" type wireguard
    grep -vE '^[[:space:]]*(Address|DNS|DNSSearch|MTU|Table|PreUp|PostUp|PreDown|PostDown|SaveConfig)[[:space:]]*=' "$CONF" > /tmp/.wg0.stripped
    wg setconf "$IFACE" /tmp/.wg0.stripped
    rm -f /tmp/.wg0.stripped
    ip addr replace "$ADDR" dev "$IFACE"
    ip link set mtu 1420 up dev "$IFACE"
  fi
fi

# Allow traffic on the TUN interface.
iptables -A INPUT -i {iface} -j ACCEPT
iptables -A FORWARD -i {iface} -j ACCEPT
iptables -A OUTPUT -o {iface} -j ACCEPT

# Allow forwarding traffic only from the VPN.
iptables -A FORWARD -i {iface} -o eth0 -s {subnet_ip}/{cidr} -j ACCEPT
iptables -A FORWARD -i {iface} -o eth1 -s {subnet_ip}/{cidr} -j ACCEPT

iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -t nat -A POSTROUTING -s {subnet_ip}/{cidr} -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s {subnet_ip}/{cidr} -o eth1 -j MASQUERADE

tail -f /dev/null
'''


def _wg_start_sh(conf_path: str, subnet: str, iface: str) -> str:
    subnet_ip, cidr = subnet.split("/")
    return WG_START_SH.format(conf=conf_path, iface=iface,
                              subnet_ip=subnet_ip, cidr=cidr)


def _wg_conf(port: int, subnet: str) -> tuple[str, str]:
    """Classic WireGuard server config — no obfuscation params."""
    priv = crypto.gen_private_key()
    addr = f"{subnet.split('/')[0].rsplit('.', 1)[0]}.1/24"
    lines = ["[Interface]", f"PrivateKey = {priv}",
             f"Address = {addr}", f"ListenPort = {port}", ""]
    return "\n".join(lines), crypto.public_key(priv)


def deploy_wg(backend: Backend, port: int) -> None:
    """Deploy classic WireGuard (amnezia-wireguard), mirroring the official client."""
    spec = DEPLOYABLE["wireguard"]
    _absent(backend, spec, port)
    dockerfile = (Path(__file__).parent / "deploy_assets" / "wireguard.Dockerfile").read_text()
    backend.build_image(spec.image, dockerfile)  # no hub image — the client builds it too
    backend.run_container(
        spec.container, spec.image,
        ports={f"{port}/udp": port}, env={},
        volumes={"/lib/modules": {"bind": "/lib/modules", "mode": "rw"}},
        privileged=True, cap_add=["NET_ADMIN", "SYS_MODULE"],
        sysctls={"net.ipv4.conf.all.src_valid_mark": "1"})
    _ensure_dir(backend, spec.container, "/opt/amnezia/wireguard")
    conf, pub = _wg_conf(port, spec.subnet)
    _write(backend, spec.container, spec.conf_path, conf)
    _write(backend, spec.container, "/opt/amnezia/wireguard/wireguard_server_public_key.key", pub + "\n")
    _write(backend, spec.container, "/opt/amnezia/wireguard/wireguard_psk.key", crypto.gen_psk() + "\n")
    _write(backend, spec.container, "/opt/amnezia/wireguard/clientsTable", "[]\n")
    # The entrypoint idles until the real start script lands — write it (exec'd
    # directly by dumb-init, so chmod +x or the container crash-loops).
    _write(backend, spec.container, "/opt/amnezia/start.sh",
           _wg_start_sh(spec.conf_path, spec.subnet, spec.iface))
    code, out = backend.exec(spec.container, ["chmod", "+x", "/opt/amnezia/start.sh"])
    if code != 0:
        raise AWGError(f"chmod start.sh failed ({code}): {out.strip()}")
    try:
        backend.connect_network("amnezia-dns-net", spec.container)
    except Exception:
        pass  # DNS network is optional
    backend.restart(spec.container)


def deploy_awg(backend: Backend, version: str, port: int) -> None:
    """Deploy amnezia-awg2 (AWG 3.1, awg0.conf)."""
    spec = DEPLOYABLE["awg2"]
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
    # The entrypoint idles until the real start script lands — write it, then restart.
    _write(backend, spec.container, "/opt/amnezia/start.sh",
           _awg_start_sh(version, spec.conf_path, spec.subnet, spec.iface))
    # ENTRYPOINT execs the script directly: a freshly written file is 0644,
    # without +x the container crash-loops on "permission denied".
    code, out = backend.exec(spec.container, ["chmod", "+x", "/opt/amnezia/start.sh"])
    if code != 0:
        raise AWGError(f"chmod start.sh failed ({code}): {out.strip()}")
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


# Mirrors client/server_scripts/mtproxy/start.sh with values baked in
# (the client substitutes variables into the script text — no container env).
MTPROXY_START_SH = '''#!/bin/sh

echo "Container startup"

SECRET=""
if [ -f /data/secret ]; then
    SECRET=$(cat /data/secret)
fi

if [ -z "$SECRET" ]; then
    echo "ERROR: /data/secret not found — run configure_container first"
    tail -f /dev/null
    exit 1
fi

INTERNAL_IP=$(hostname -i 2>/dev/null | awk '{{print $1}}')
EXTERNAL_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null)
[ -z "$EXTERNAL_IP" ] && EXTERNAL_IP=$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null)

NAT_FLAG=""
NAT_VALUE=""
if [ -n "$INTERNAL_IP" ] && [ -n "$EXTERNAL_IP" ] && [ "$INTERNAL_IP" != "$EXTERNAL_IP" ]; then
    NAT_FLAG="--nat-info"
    NAT_VALUE="${{INTERNAL_IP}}:${{EXTERNAL_IP}}"
fi

exec mtproto-proxy \\
    -u root \\
    -p 2398 \\
    -H {port} \\
    -S ${{SECRET}} \\
    --aes-pwd /data/proxy-secret \\
    -M 1 \\
    -C 60000 \\
    --allow-skip-dh \\
    ${{NAT_FLAG:+${{NAT_FLAG}} ${{NAT_VALUE}}}} \\
    {domain_arg} \\
    /data/proxy-multi.conf
'''


def _run_sh(backend: Backend, container: str, script: str, what: str) -> None:
    code, out = backend.exec(container, ["sh", "-c", script])
    if code != 0:
        raise AWGError(f"{what} failed ({code}): {out.strip()}")


def deploy_mtproxy(backend: Backend, port: int, tls_domain: str) -> None:
    spec = DEPLOYABLE["mtproxy"]
    _absent(backend, spec, port)
    if not valid_domain(tls_domain):
        raise AWGError(f"invalid masking domain: {tls_domain!r}")
    backend.pull_image(spec.image)
    backend.run_container(
        spec.container, spec.image,
        ports={f"{port}/tcp": port}, env={},
        volumes={"amnezia-mtproxy-data": {"bind": "/data", "mode": "rw"}})
    # The image idles on `tail -f /dev/null`; configure it exactly like the client does.
    _run_sh(backend, spec.container,
            "curl -s https://core.telegram.org/getProxySecret -o /data/proxy-secret && "
            "curl -s https://core.telegram.org/getProxyConfig -o /data/proxy-multi.conf",
            "telegram config download")
    _write(backend, spec.container, "/data/secret", secrets.token_hex(16) + "\n")
    _write(backend, spec.container, "/opt/amnezia/start.sh",
           MTPROXY_START_SH.format(port=port, domain_arg=f"--domain {tls_domain}"))
    # Deployment state, read back by the panel and by the client's server rescan.
    _write(backend, spec.container, "/data/mtproxy-meta",
           f"mode=faketls\ndomain={tls_domain}\ntag=\nadditional=\n"
           f"workers_mode=\nworkers=1\nnat_enabled=\nnat_internal=\n"
           f"nat_external=\npublic_host=\n")
    backend.restart(spec.container)


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
