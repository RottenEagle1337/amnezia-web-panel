"""Safe editing of deployed service configs: backup -> validate -> write -> apply."""
from __future__ import annotations

import contextlib
import re
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone

from . import awg
from .backend.base import Backend
from .keys import AWGError, _layout, _locks, _read, _syncconf, _write


@dataclass
class ConfigSpec:
    container: str
    path: str
    fmt: str      # "awg" | "toml"
    apply: str    # "syncconf" | "restart"


def _awg_spec(container: str) -> ConfigSpec:
    return ConfigSpec(container, _layout(container)["conf"], "awg", "syncconf")


SPECS: dict[str, ConfigSpec] = {
    "amnezia-awg": _awg_spec("amnezia-awg"),
    "amnezia-awg2": _awg_spec("amnezia-awg2"),
    "amnezia-telemt": ConfigSpec("amnezia-telemt", "/data/config.toml", "toml", "restart"),
}

# [Interface] fields the form editor manages, grouped like the Amnezia client's
# protocol settings page. kind: "port" | "int" | "range" ("min-max") | "text" | "onoff".
# Everything else (PrivateKey, Address, PostUp/PostDown, I1..I5) is preserved
# as-is and never editable — same as the official client.
FIELD_SECTIONS: list[tuple[str, list[tuple[str, str]]]] = [
    ("General", [("ListenPort", "port")]),
    ("Junk packets", [("Jc", "int"), ("Jmin", "int"), ("Jmax", "int")]),
    ("Packet sizes", [("S1", "int"), ("S2", "int"), ("S3", "int"), ("S4", "int")]),
    ("Magic headers", [("H1", "int"), ("H2", "int"), ("H3", "int"), ("H4", "int")]),
    ("Header protection (AWG 3.1)", [("HeaderProtectionKey", "text"),
                                     ("ContentPaddingAddition", "range")]),
    ("Rekey (AWG 3.1)", [("RekeyAfterTime", "range"), ("RekeyTimeout", "range"),
                         ("RejectAfterTime", "range"), ("KeepaliveTimeout", "range"),
                         ("MaxHandshakeAttempts", "range")]),
    ("Cookies (AWG 3.1)", [("RandomTrailers", "onoff"), ("DisableCookies", "onoff")]),
]
FIELD_SPECS: list[tuple[str, str]] = [f for _, fields in FIELD_SECTIONS for f in fields]
INT_FIELDS = tuple(name for name, _ in FIELD_SPECS)

_INT_RE = re.compile(r"^[0-9]+(-[0-9]+)?$")  # int or "min-max" range


def read_config(backend: Backend, container: str) -> str:
    spec = SPECS[container]
    return _read(backend, container, spec.path)


def _validate_awg(text: str, live_peers: list[awg.Peer]) -> list[str]:
    errors: list[str] = []
    cfg = awg.parse_wg_conf(text)
    if not cfg.interface.get("Address"):
        errors.append("missing Address in [Interface]")
    else:
        import ipaddress
        try:
            ipaddress.ip_network(cfg.interface["Address"], strict=False)
        except ValueError:
            errors.append(f"bad Address: {cfg.interface['Address']}")
    port = cfg.interface.get("ListenPort", "")
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        errors.append(f"bad ListenPort: {port or '(empty)'}")
    for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"):
        value = cfg.interface.get(key, "")
        if value and not _INT_RE.match(value):
            errors.append(f"{key} must be an integer or a min-max range, got: {value}")
    s1, s2 = cfg.interface.get("S1", ""), cfg.interface.get("S2", "")
    if s1.isdigit() and s2.isdigit() and int(s1) + 56 == int(s2):
        errors.append("S1 + 56 must not equal S2 (packets would collide in size)")
    hs = [cfg.interface.get(f"H{i}", "") for i in range(1, 5)]
    hs = [h for h in hs if h]
    if len(set(hs)) != len(hs):
        errors.append("H1..H4 must be unique")
    # Peers are managed on the Keys page only — the editor must not touch them.
    new = [(p.public_key, p.allowed_ips) for p in cfg.peers]
    old = [(p.public_key, p.allowed_ips) for p in live_peers]
    if new != old:
        errors.append("[Peer] sections must not be edited here — use the Keys page")
    return errors


def validate_config(backend: Backend, container: str, text: str) -> list[str]:
    spec = SPECS[container]
    if spec.fmt == "toml":
        try:
            tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            return [f"TOML: {exc}"]
        return []
    live = awg.parse_wg_conf(read_config(backend, container))
    return _validate_awg(text, live.peers)


def _backup_name(path: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{path}.bak-{ts}"


def apply_config(backend: Backend, container: str, text: str) -> None:
    spec = SPECS[container]
    errors = validate_config(backend, container, text)
    if errors:
        raise AWGError("; ".join(errors))
    # Same per-container lock as key issue/revoke: both rewrite the same conf
    # read-modify-write, and an unlocked apply would lose a concurrent peer add.
    with _locks.get(container, contextlib.nullcontext()):
        current = read_config(backend, container)
        if current:
            _write(backend, container, _backup_name(spec.path), current)
        _write(backend, container, spec.path, text)
        if spec.apply == "syncconf":
            _syncconf(backend, container)
        else:
            backend.restart(container)


def list_backups(backend: Backend, container: str) -> list[str]:
    spec = SPECS[container]
    code, out = backend.exec(container, ["sh", "-c", f"ls -1 {spec.path}.bak-* 2>/dev/null"])
    if code != 0:
        return []
    return sorted((line.strip() for line in out.splitlines() if line.strip()), reverse=True)


def restore_backup(backend: Backend, container: str, backup_name: str) -> None:
    spec = SPECS[container]
    base = f"{spec.path}.bak-"
    # The suffix becomes part of a shell argument — no slashes, no traversal.
    suffix = backup_name[len(base):] if backup_name.startswith(base) else ""
    if not suffix or not re.fullmatch(r"[A-Za-z0-9._-]+", suffix):
        raise AWGError("bad backup name")
    text = _read(backend, container, backup_name)
    if not text:
        raise AWGError("backup not found")
    if spec.fmt == "awg":
        # Peers are owned by the Keys page: restore only [Interface], keep the
        # live [Peer] sections — otherwise any key issued after the backup
        # would make every restore fail validation.
        backup_cfg = awg.parse_wg_conf(text)
        live_cfg = awg.parse_wg_conf(read_config(backend, container))
        live_cfg.interface = backup_cfg.interface
        text = awg.render_wg_conf(live_cfg)
    apply_config(backend, container, text)
