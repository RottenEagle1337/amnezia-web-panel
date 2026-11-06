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


def test_config_editor_page_and_apply():
    c = _client()
    r = c.get("/config/amnezia-awg")
    assert r.status_code == 200 and "Jc" in r.text
    # apply a valid change
    text = c.app.state.backend._fs["amnezia-awg"]["/opt/amnezia/awg/wg0.conf"]
    r = c.post("/config/amnezia-awg", data={"text": text.replace("Jc = 3", "Jc = 7")},
               follow_redirects=False)
    assert r.status_code == 303
    assert "Jc = 7" in c.app.state.backend._fs["amnezia-awg"]["/opt/amnezia/awg/wg0.conf"]


def test_config_editor_rejects_invalid():
    c = _client()
    r = c.post("/config/amnezia-awg", data={"text": "garbage"})
    assert "error" in r.text or "ListenPort" in r.text  # re-rendered with errors


def test_config_editor_unknown_container():
    c = _client()
    r = c.get("/config/amnezia-xray", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"


def test_config_editor_requires_auth():
    c = TestClient(create_app())
    r = c.get("/config/amnezia-awg", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_config_editor_field_form():
    c = _client()
    page = c.get("/config/amnezia-awg2").text
    # editable fields rendered as inputs
    for key in ("ListenPort", "Jc", "S1", "H1", "HeaderProtectionKey"):
        assert f'data-key="{key}"' in page
    # on/off fields are dropdowns (AWG 3.1 only)
    assert 'data-key="RandomTrailers"' in page and "<select" in page
    # non-editable fields are NOT inputs
    assert 'data-key="PrivateKey"' not in page
    assert 'data-key="Address"' not in page
    assert 'data-key="PostUp"' not in page
    # awg 2.0 has no 3.1-only fields
    page2 = c.get("/config/amnezia-awg").text
    assert 'data-key="HeaderProtectionKey"' not in page2
    assert 'data-key="RandomTrailers"' not in page2


def test_config_editor_sections():
    c = _client()
    page = c.get("/config/amnezia-awg2").text
    for section in ("General", "Junk packets", "Packet sizes", "Magic headers",
                    "Header protection", "Rekey", "Cookies"):
        assert section in page
    # awg 2.0 shows only the sections its fields belong to
    page2 = c.get("/config/amnezia-awg").text
    assert "Junk packets" in page2 and "Cookies" not in page2


def test_duplicate_key_name_rejected():
    c = _client()
    r = c.post("/keys/amnezia-awg/create", data={"name": "phone-ivan"},
               follow_redirects=False)
    assert r.status_code == 303 and "error=" in r.headers["location"]
    assert "exists" in r.headers["location"]
    # same name on another protocol is fine
    r = c.post("/keys/amnezia-awg2/create", data={"name": "phone-ivan"},
               follow_redirects=False)
    assert r.status_code == 200  # issued -> one-time created page


def test_keys_page_proto_info_and_config_button():
    c = _client()
    page = c.get("/keys/amnezia-awg").text
    assert "51820" in page                      # port from live config
    assert "10.8.1.1/24" in page                # subnet
    assert 'href="/config/amnezia-awg"' in page
    cfg = c.get("/config/amnezia-awg").text
    assert 'href="/keys/amnezia-awg"' in cfg    # Cancel returns to the protocol page


def test_config_restore_bad_backup_shows_error():
    c = _client()
    r = c.post("/config/amnezia-awg/restore",
               data={"backup": "/opt/amnezia/awg/wg0.conf.bak-nope"},
               follow_redirects=False)
    assert "err=" in r.headers["location"]
