import base64
import json
import zlib

from app import keys
from app.amnezia_fmt import build_vpn_link, encode_vpn_config
from app.awg import parse_wg_conf
from app.backend.mock_backend import MockBackend, WG0_CONF_AWG, WG0_CONF_AWG2


def decode_vpn(link: str) -> dict:
    """Same steps the Amnezia client import does: base64url -> qUncompress -> json."""
    payload = base64.urlsafe_b64decode(link.removeprefix("vpn://") + "=" * (-len(link.removeprefix("vpn://")) % 4))
    return json.loads(zlib.decompress(payload[4:]).decode())


def test_encode_roundtrip():
    link = encode_vpn_config({"hello": "world"})
    assert link.startswith("vpn://")
    assert decode_vpn(link) == {"hello": "world"}


def test_vpn_qr_frames_structure():
    import struct
    from app.amnezia_fmt import QR_CHUNK_SIZE, QR_MAGIC_CODE, vpn_qr_frames

    _, _, link = keys.create_client(MockBackend(), "amnezia-awg2", "qr-t", "1.2.3.4", "51821")
    frames = vpn_qr_frames(link)
    assert len(frames) >= 1
    payload = base64.urlsafe_b64decode(link[6:] + "=" * (-len(link[6:]) % 4))
    expected = max(1, (len(payload) + QR_CHUNK_SIZE - 1) // QR_CHUNK_SIZE)
    assert len(frames) == expected

    rebuilt = b""
    for i, f in enumerate(frames):
        raw = base64.urlsafe_b64decode(f + "=" * (-len(f) % 4))
        magic, count, index, size = struct.unpack(">hBBI", raw[:8])
        assert magic == QR_MAGIC_CODE
        assert count == expected
        assert index == i
        assert size == len(raw[8:])
        rebuilt += raw[8:]
    # Reassembled frames == original payload (4 length bytes + deflate)
    assert rebuilt == payload
    assert decode_vpn(link)["defaultContainer"] == "amnezia-awg2"


def _check_common(server: dict, container: str, name: str, block: str = "awg"):
    assert server["defaultContainer"] == container
    assert server["containers"][0]["container"] == container
    assert name in server["description"]
    assert server["dns1"] and server["dns2"]
    assert server["hostName"] == "1.2.3.4"
    awg = server["containers"][0][block]
    last = json.loads(awg["last_config"])
    assert last["config"].startswith("[Interface]")
    assert last["client_priv_key"]
    assert last["client_pub_key"] == last["clientId"]
    assert last["server_pub_key"]
    assert last["psk_key"]
    assert last["allowed_ips"] == ["0.0.0.0/0", "::/0"]
    return awg, last


def test_vpn_link_wireguard():
    backend = MockBackend()
    _, _, link = keys.create_client(backend, "amnezia-wireguard", "phone-t", "1.2.3.4", "51820")
    server = decode_vpn(link)
    wg, last = _check_common(server, "amnezia-wireguard", "phone-t", block="wireguard")
    assert "protocol_version" not in wg          # classic wg: no obfuscation block
    assert "Jc = " not in last["config"]
    assert "Endpoint = 1.2.3.4:51820" in last["config"]


def test_vpn_link_awg31():
    backend = MockBackend()
    _, _, link = keys.create_client(backend, "amnezia-awg2", "tab-t", "1.2.3.4", "51821")
    server = decode_vpn(link)
    awg, last = _check_common(server, "amnezia-awg2", "tab-t")
    assert awg["protocol_version"] == "3.1"
    assert awg["S3"] and awg["S4"] and awg["I1"]
    assert last["persistent_keep_alive"] == "25-35"
    assert "S3 = " in last["config"] and "I1 = " in last["config"]
