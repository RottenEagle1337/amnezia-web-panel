"""Pure-Python WireGuard key generation (X25519, RFC 7748).

Lets the panel create keypairs locally instead of exec-ing `wg genkey`
inside the container: fewer moving parts, works the same in mock and prod.
"""
from __future__ import annotations

import base64
import secrets

P = 2**255 - 19
A24 = 121665


def _x25519(scalar: bytes, point: bytes) -> bytes:
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    scalar_int = int.from_bytes(k, "little")
    u = int.from_bytes(point, "little")
    x1, x2, z2, x3, z3 = u, 1, 0, u, 1
    swap = 0
    for t in range(254, -1, -1):
        bit = (scalar_int >> t) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit
        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    result = x2 * pow(z2, P - 2, P) % P
    return result.to_bytes(32, "little")


_BASE_POINT = (9).to_bytes(32, "little")


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def gen_private_key() -> str:
    return _b64(secrets.token_bytes(32))


def gen_psk() -> str:
    return _b64(secrets.token_bytes(32))


def public_key(private_b64: str) -> str:
    return _b64(_x25519(base64.b64decode(private_b64), _BASE_POINT))
