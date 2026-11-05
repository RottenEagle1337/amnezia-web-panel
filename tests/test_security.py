import os

os.environ["PANEL_BACKEND"] = "mock"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import create_app  # noqa: E402


def _client() -> TestClient:
    c = TestClient(create_app())
    c.post("/login", data={"password": "admin"}, follow_redirects=False)
    return c


def test_restart_restricted_to_amnezia_containers():
    c = _client()
    r = c.post("/services/other-app/restart", follow_redirects=False)
    assert r.status_code == 303
    assert c.app.state.backend.restarted == []
    # an amnezia container is allowed
    r = c.post("/services/amnezia-awg/restart", follow_redirects=False)
    assert r.status_code == 303
    assert c.app.state.backend.restarted == ["amnezia-awg"]


def test_panel_cannot_restart_itself():
    c = _client()
    c.post("/services/amnezia-web-panel/restart", follow_redirects=False)
    assert c.app.state.backend.restarted == []


def test_logs_restricted_to_amnezia_containers():
    c = _client()
    r = c.get("/services/other-app/logs", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"


def test_login_throttle():
    c = TestClient(create_app())
    for _ in range(5):
        r = c.post("/login", data={"password": "nope"}, follow_redirects=False)
        assert "error=1" in r.headers["location"]
    # after 5 failures even the correct password is rejected
    r = c.post("/login", data={"password": "admin"}, follow_redirects=False)
    assert "error=rate" in r.headers["location"]


def test_security_headers():
    c = TestClient(create_app())
    r = c.get("/login")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Referrer-Policy"] == "no-referrer"


def test_client_name_rejects_control_chars():
    c = _client()
    r = c.post("/keys/amnezia-awg/create", data={"name": "bad\nname"}, follow_redirects=False)
    assert r.status_code == 303
    assert "error=" in r.headers["location"]
    page = c.get("/keys/amnezia-awg").text
    assert "bad\nname" not in page
