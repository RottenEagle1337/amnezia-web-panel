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


def test_garbage_session_cookie_no_500():
    """A malformed panel_session cookie must redirect to /login, not crash."""
    c = TestClient(create_app())
    for bad in ("abc.def", "notanumber.deadbeef", ".", "99999999999999999999.x"):
        c.cookies.set("panel_session", bad)
        r = c.get("/", follow_redirects=False)
        assert r.status_code == 303, bad
        assert r.headers["location"] == "/login"


def test_client_name_with_quotes_no_js_breakout():
    """Quotes in a client name must not break out of the onsubmit JS string."""
    c = _client()
    evil = "x');alert(1)//"
    r = c.post("/keys/amnezia-awg/create", data={"name": evil}, follow_redirects=False)
    assert r.status_code == 200  # one-time "Key issued" page
    page = c.get("/keys/amnezia-awg").text
    # the name must only appear HTML/JS-escaped, never raw inside onsubmit
    assert "x');alert(1)//" not in page
    assert "alert(1)" not in page or "\\u0027" in page or "&#39;" in page
    # cleanup
    import json as _json
    table = _json.loads(c.app.state.backend._fs["amnezia-awg"]["/opt/amnezia/awg/clientsTable"])
    cid = [e["clientId"] for e in table if e["userData"]["clientName"] == evil][0]
    c.post("/keys/amnezia-awg/revoke", data={"client_id": cid}, follow_redirects=False)


def test_logout_invalidates_token_server_side():
    """A token captured before logout must be rejected afterwards."""
    c = _client()
    token = c.cookies.get("panel_session")
    r = c.get("/", follow_redirects=False)
    assert r.status_code == 200
    c.get("/logout", follow_redirects=False)
    # replay the stolen cookie on a fresh client
    c2 = TestClient(create_app())
    c2.app.state.auth = c.app.state.auth  # same process secret store
    c2.cookies.set("panel_session", token)
    r = c2.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
