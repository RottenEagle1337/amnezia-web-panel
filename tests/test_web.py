import os
import re

os.environ["PANEL_BACKEND"] = "mock"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import create_app  # noqa: E402


def _client() -> TestClient:
    c = TestClient(create_app())
    r = c.post("/login", data={"password": "admin"}, follow_redirects=False)
    assert r.status_code == 303
    return c


def test_auth_required():
    c = TestClient(create_app())
    r = c.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    r = c.get("/keys/amnezia-awg", follow_redirects=False)
    assert r.status_code == 303
    # wrong password
    r = c.post("/login", data={"password": "nope"}, follow_redirects=False)
    assert "error=1" in r.headers["location"]


def test_dashboard_lists_services():
    c = _client()
    page = c.get("/").text
    for name in ("amnezia-awg", "amnezia-awg2", "amnezia-xray", "amnezia-openvpn"):
        assert name in page


def test_keys_page_lists_clients():
    c = _client()
    page = c.get("/keys/amnezia-awg").text
    assert "phone-ivan" in page
    assert "laptop-anna" in page


def test_create_and_revoke_via_web():
    c = _client()
    r = c.post("/keys/amnezia-awg/create", data={"name": "web-test"})
    assert r.status_code == 200
    assert "QR" in r.text
    assert "PrivateKey" in r.text

    page = c.get("/keys/amnezia-awg").text
    assert "web-test" in page
    ids = re.findall(r'name="client_id" value="([^"]+)"', page)
    assert ids
    # base64 keys contain '+' and '/' — revoke must survive form-encoding
    r = c.post("/keys/amnezia-awg/revoke", data={"client_id": ids[-1]}, follow_redirects=False)
    assert r.status_code == 303
    page = c.get("/keys/amnezia-awg").text
    assert "web-test" not in page


def test_restart_and_logs():
    c = _client()
    r = c.post("/services/amnezia-xray/restart", follow_redirects=False)
    assert r.status_code == 303
    page = c.get("/services/amnezia-xray/logs").text
    assert "mock log line" in page


def test_keys_page_missing_container_shows_notice():
    c = _client()
    # simulate a server without the amnezia-awg2 container
    backend = c.app.state.backend
    backend._services = [s for s in backend._services if s.name != "amnezia-awg2"]
    page = c.get("/keys/amnezia-awg2").text
    assert "not installed" in page
    assert "Issue key" not in page
    # existing container still works
    assert "phone-ivan" in c.get("/keys/amnezia-awg").text


def test_healthz_no_auth():
    c = TestClient(create_app())
    assert c.get("/healthz").json() == {"ok": True}
