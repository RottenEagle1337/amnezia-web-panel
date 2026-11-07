"""Detection and info for Amnezia side services: MTProxy, Telemt, AmneziaDNS.

Data sources (inside containers, matching the official Amnezia deploy):
- amnezia-mtproxy: /data/secret (32 hex), /data/mtproxy-meta (mode/domain),
  port bindings
- amnezia-telemt:  /data/config.toml ([access.users], [censorship], modes)
- amnezia-dns:     container on amnezia-dns-net, usually 172.29.172.254
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field

from .backend.base import Backend, ContainerNotFound

MTPROXY_CONTAINER = "amnezia-mtproxy"
TELEMT_CONTAINER = "amnezia-telemt"
DNS_CONTAINER = "amnezia-dns"

MTPROXY_SECRET_PATH = "/data/secret"
TELEMT_CONFIG_PATH = "/data/config.toml"


@dataclass
class ProxyLink:
    label: str          # ee FakeTLS / dd Secure / classic
    tg_link: str        # tg://proxy?...
    tme_link: str       # https://t.me/proxy?...


@dataclass
class ProxyInfo:
    container: str
    kind: str                       # mtproxy | telemt
    running: bool = False
    port: str = ""
    domain: str = ""                # masking domain (faketls)
    mode: str = ""                  # faketls | secure | classic
    links: list[ProxyLink] = field(default_factory=list)
    error: str = ""


@dataclass
class DnsInfo:
    container: str
    running: bool = False
    network: str = ""
    ip: str = ""
    image: str = ""
    error: str = ""


def _running(backend: Backend, name: str) -> bool:
    return any(s.name == name and s.status == "running" for s in backend.list_services())


def _read_file(backend: Backend, container: str, path: str) -> str:
    try:
        code, out = backend.exec(container, ["cat", path])
    except ContainerNotFound:
        return ""
    return out if code == 0 else ""


def _tg_links(secret: str, label: str, host: str, port: str) -> ProxyLink:
    link = f"tg://proxy?server={host}&port={port}&secret={secret}"
    return ProxyLink(label=label, tg_link=link,
                     tme_link=link.replace("tg://proxy?", "https://t.me/proxy?"))


def mtproxy_info(backend: Backend, endpoint_host: str) -> ProxyInfo:
    info = ProxyInfo(container=MTPROXY_CONTAINER, kind="mtproxy")
    info.running = _running(backend, MTPROXY_CONTAINER)
    try:
        meta = backend.inspect(MTPROXY_CONTAINER)
    except ContainerNotFound:
        return info
    env = meta["env"]
    # Client-deployed containers carry no env: state lives in /data/mtproxy-meta.
    kv = dict(
        line.split("=", 1) for line in
        _read_file(backend, MTPROXY_CONTAINER, "/data/mtproxy-meta").splitlines()
        if "=" in line
    )
    info.mode = kv.get("mode") or env.get("MTPROXY_TRANSPORT_MODE", "")
    info.domain = kv.get("domain") or env.get("MTPROXY_TLS_DOMAIN", "")
    info.port = env.get("MTPROXY_PORT", "") or next(iter(meta["ports"].values()), "")
    secret = _read_file(backend, MTPROXY_CONTAINER, MTPROXY_SECRET_PATH).strip()
    if not info.running or not secret:
        return info
    if info.mode == "faketls" and info.domain:
        domain_hex = info.domain.encode().hex()
        info.links.append(_tg_links(f"ee{secret}{domain_hex}", "FakeTLS (ee)", endpoint_host, info.port))
    info.links.append(_tg_links(f"dd{secret}", "Secure (dd)", endpoint_host, info.port))
    return info


def telemt_info(backend: Backend, endpoint_host: str) -> ProxyInfo:
    info = ProxyInfo(container=TELEMT_CONTAINER, kind="telemt")
    info.running = _running(backend, TELEMT_CONTAINER)
    try:
        meta = backend.inspect(TELEMT_CONTAINER)
    except ContainerNotFound:
        return info
    info.port = next(iter(meta["ports"].values()), "")
    raw = _read_file(backend, TELEMT_CONTAINER, "/etc/telemt/config.toml") or \
        _read_file(backend, TELEMT_CONTAINER, TELEMT_CONFIG_PATH)
    if not raw:
        return info
    try:
        cfg = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        info.error = f"config.toml: {exc}"
        return info
    info.domain = cfg.get("censorship", {}).get("tls_domain", "")
    modes = cfg.get("general", {}).get("modes", {})
    info.mode = "faketls" if modes.get("tls") else ("secure" if modes.get("secure") else "classic")
    if not info.running:
        return info
    domain_hex = info.domain.encode().hex() if info.domain else ""
    for user, secret in (cfg.get("access", {}).get("users", {}) or {}).items():
        if info.mode == "faketls" and domain_hex:
            link_secret, label = f"ee{secret}{domain_hex}", f"{user} · FakeTLS (ee)"
        elif info.mode == "secure":
            link_secret, label = f"dd{secret}", f"{user} · Secure (dd)"
        else:
            link_secret, label = secret, f"{user} · Classic"
        info.links.append(_tg_links(link_secret, label, endpoint_host, info.port))
    return info


def dns_info(backend: Backend) -> DnsInfo:
    info = DnsInfo(container=DNS_CONTAINER)
    info.running = _running(backend, DNS_CONTAINER)
    services = {s.name: s for s in backend.list_services()}
    if DNS_CONTAINER in services:
        info.image = services[DNS_CONTAINER].image
    try:
        meta = backend.inspect(DNS_CONTAINER)
    except ContainerNotFound:
        return info
    for name, net in meta["networks"].items():
        info.network, info.ip = name, net["ip"]
    return info
