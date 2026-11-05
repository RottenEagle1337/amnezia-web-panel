import os

os.environ["PANEL_BACKEND"] = "mock"

from fastapi.testclient import TestClient  # noqa: E402

from app import extras  # noqa: E402
from app.backend import make_backend  # noqa: E402
from app.main import create_app  # noqa: E402

HOST = "vpn.example.com"
DOMAIN_HEX = "googletagmanager.com".encode().hex()


def _client() -> TestClient:
    c = TestClient(create_app())
    c.post("/login", data={"password": "admin"}, follow_redirects=False)
    return c


def test_mtproxy_info():
    info = extras.mtproxy_info(make_backend("mock"), HOST)
    assert info.running
    assert info.port == "8443"
    assert info.mode == "faketls"
    assert info.domain == "googletagmanager.com"
    assert len(info.links) == 2
    ee = info.links[0]
    assert ee.tg_link == (
        f"tg://proxy?server={HOST}&port=8443"
        f"&secret=ee1a2b3c4d5e6f7890abcdef1234567890{DOMAIN_HEX}")
    assert ee.tme_link.startswith("https://t.me/proxy?")
    dd = info.links[1]
    assert "secret=dd1a2b3c4d5e6f7890abcdef1234567890" in dd.tg_link


def test_telemt_info():
    info = extras.telemt_info(make_backend("mock"), HOST)
    assert info.running
    assert info.port == "443"
    assert info.mode == "faketls"
    assert info.domain == "googletagmanager.com"
    assert len(info.links) == 1
    link = info.links[0]
    assert "tg_main" in link.label
    assert f"secret=ee7a2f8b5c9d0e1f2a3b4c5d6e7f8a9b0c{DOMAIN_HEX}" in link.tg_link


def test_dns_info():
    info = extras.dns_info(make_backend("mock"))
    assert info.running
    assert info.network == "amnezia-dns-net"
    assert info.ip == "172.29.172.254"
    assert "amnezia-dns" in info.image


def test_extras_root_redirects_to_mtproxy():
    c = _client()
    r = c.get("/extras", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/extras/mtproxy"


def test_extras_mtproxy_page():
    page = _client().get("/extras/mtproxy").text
    assert "MTProxy" in page
    assert "faketls" in page
    assert "tg://proxy?server=" in page
    assert "data:image/png;base64," in page  # link QR codes


def test_extras_telemt_page():
    page = _client().get("/extras/telemt").text
    assert "Telemt" in page
    assert "tg_main" in page
    assert "tg://proxy?server=" in page


def test_extras_dns_page():
    page = _client().get("/extras/dns").text
    assert "AmneziaDNS" in page
    assert "amnezia-dns-net" in page
    assert "172.29.172.254" in page


def test_extras_unknown_service_redirects():
    c = _client()
    r = c.get("/extras/nope", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/extras/mtproxy"


def test_placeholder_pages():
    c = _client()
    for container, title in (("amnezia-xray", "Xray"), ("amnezia-openvpn", "OpenVPN")):
        page = c.get(f"/keys/{container}").text
        assert "coming in a future version" in page
        assert title in page
        # the placeholder must not show the issue form
        assert "Issue key" not in page


def test_unknown_container_redirects():
    c = _client()
    r = c.get("/keys/amnezia-unknown", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
