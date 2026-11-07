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
    r = c.get("/keys/amnezia-wireguard", follow_redirects=False)
    assert r.status_code == 303
    # wrong password
    r = c.post("/login", data={"password": "nope"}, follow_redirects=False)
    assert "error=1" in r.headers["location"]


def test_dashboard_lists_services():
    c = _client()
    page = c.get("/").text
    for name in ("amnezia-wireguard", "amnezia-awg2", "amnezia-xray", "amnezia-openvpn"):
        assert name in page


def test_keys_page_lists_clients():
    c = _client()
    page = c.get("/keys/amnezia-wireguard").text
    assert "phone-ivan" in page
    assert "laptop-anna" in page


def test_create_and_revoke_via_web():
    c = _client()
    r = c.post("/keys/amnezia-wireguard/create", data={"name": "web-test"})
    assert r.status_code == 200
    assert "QR" in r.text
    assert "PrivateKey" in r.text

    page = c.get("/keys/amnezia-wireguard").text
    assert "web-test" in page
    ids = re.findall(r'name="client_id" value="([^"]+)"', page)
    assert ids
    # base64 keys contain '+' and '/' — revoke must survive form-encoding
    r = c.post("/keys/amnezia-wireguard/revoke", data={"client_id": ids[-1]}, follow_redirects=False)
    assert r.status_code == 303
    page = c.get("/keys/amnezia-wireguard").text
    assert "web-test" not in page


def test_restart_service():
    c = _client()
    r = c.post("/services/amnezia-xray/restart", follow_redirects=False)
    assert r.status_code == 303


def test_keys_page_missing_container_shows_notice():
    c = _client()
    # simulate a server without the amnezia-awg2 container
    backend = c.app.state.backend
    backend._services = [s for s in backend._services if s.name != "amnezia-awg2"]
    page = c.get("/keys/amnezia-awg2").text
    assert "not installed" in page
    assert "Issue key" not in page
    # existing container still works
    assert "phone-ivan" in c.get("/keys/amnezia-wireguard").text


def test_healthz_no_auth():
    c = TestClient(create_app())
    assert c.get("/healthz").json() == {"ok": True}


def test_config_editor_page_and_apply():
    c = _client()
    r = c.get("/config/amnezia-awg2")
    assert r.status_code == 200 and "Jc" in r.text
    # apply a valid change
    text = c.app.state.backend._fs["amnezia-awg2"]["/opt/amnezia/awg/awg0.conf"]
    r = c.post("/config/amnezia-awg2", data={"text": text.replace("Jc = 4", "Jc = 7")},
               follow_redirects=False)
    assert r.status_code == 303
    assert "Jc = 7" in c.app.state.backend._fs["amnezia-awg2"]["/opt/amnezia/awg/awg0.conf"]


def test_config_editor_rejects_invalid():
    c = _client()
    r = c.post("/config/amnezia-wireguard", data={"text": "garbage"})
    assert "error" in r.text or "ListenPort" in r.text  # re-rendered with errors


def test_config_editor_unknown_container():
    c = _client()
    r = c.get("/config/amnezia-xray", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"


def test_config_editor_requires_auth():
    c = TestClient(create_app())
    r = c.get("/config/amnezia-wireguard", follow_redirects=False)
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
    page2 = c.get("/config/amnezia-wireguard").text
    assert 'data-key="HeaderProtectionKey"' not in page2
    assert 'data-key="RandomTrailers"' not in page2


def test_config_editor_sections():
    c = _client()
    page = c.get("/config/amnezia-awg2").text
    for section in ("General", "Junk packets", "Packet sizes", "Magic headers",
                    "Header protection", "Rekey", "Cookies"):
        assert section in page
    # classic WireGuard has no obfuscation sections at all
    page2 = c.get("/config/amnezia-wireguard").text
    assert "Junk packets" not in page2 and "Cookies" not in page2


def test_duplicate_key_name_rejected():
    c = _client()
    r = c.post("/keys/amnezia-wireguard/create", data={"name": "phone-ivan"},
               follow_redirects=False)
    assert r.status_code == 303 and "error=" in r.headers["location"]
    assert "exists" in r.headers["location"]
    # same name on another protocol is fine
    r = c.post("/keys/amnezia-awg2/create", data={"name": "phone-ivan"},
               follow_redirects=False)
    assert r.status_code == 200  # issued -> one-time created page


def test_keys_page_proto_info_and_config_button():
    c = _client()
    page = c.get("/keys/amnezia-wireguard").text
    assert "51820" in page                      # port from live config
    assert "10.8.1.1/24" in page                # subnet
    assert 'href="/config/amnezia-wireguard"' in page
    cfg = c.get("/config/amnezia-wireguard").text
    assert 'href="/keys/amnezia-wireguard"' in cfg    # Cancel returns to the protocol page


def test_config_restore_bad_backup_shows_error():
    c = _client()
    r = c.post("/config/amnezia-wireguard/restore",
               data={"backup": "/opt/amnezia/wireguard/wg0.conf.bak-nope"},
               follow_redirects=False)
    assert "err=" in r.headers["location"]


def test_static_cache_bust():
    c = _client()
    page = c.get("/").text
    assert "style.css?v=" in page


def test_deploy_controls_live_on_protocol_pages():
    c = _client()
    # installed protocol -> Remove under the protocol info
    page = c.get("/keys/amnezia-wireguard").text
    assert 'action="/deploy/wireguard/remove"' in page
    # missing protocol -> inline Install form instead of a link
    b = c.app.state.backend
    b.remove_container("amnezia-wireguard"); b._fs.pop("amnezia-wireguard", None)
    page = c.get("/keys/amnezia-wireguard").text
    assert 'action="/deploy/wireguard"' in page and 'name="port"' in page
    assert 'href="/deploy"' not in page      # no separate Install section
    # services -> controls on the extras pages
    mt = c.get("/extras/mtproxy").text
    assert 'action="/deploy/mtproxy/remove"' in mt
    assert c.get("/deploy").status_code in (404, 405)


def test_deploy_install_awg_and_remove():
    c = _client()
    b = c.app.state.backend
    b.remove_container("amnezia-wireguard"); b._fs.pop("amnezia-wireguard", None)
    r = c.post("/deploy/wireguard", data={"port": "51820", "next": "/keys/amnezia-wireguard"},
               follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/keys/amnezia-wireguard")
    assert b.ran and b.ran[0]["name"] == "amnezia-wireguard"
    r = c.post("/deploy/wireguard/remove", data={"wipe_data": "1", "next": "/keys/amnezia-wireguard"},
               follow_redirects=False)
    assert ("amnezia-wireguard", True) in b.removed


def test_deploy_requires_domain_for_proxies():
    c = _client()
    r = c.post("/deploy/mtproxy",
               data={"port": "8443", "tls_domain": "", "next": "/extras/mtproxy"},
               follow_redirects=False)
    assert r.headers["location"].startswith("/extras/mtproxy?error=")


def test_deploy_unknown_key_redirects():
    c = _client()
    r = c.post("/deploy/nope", data={}, follow_redirects=False)
    assert r.headers["location"] == "/"


def test_key_status_json():
    c = _client()
    r = c.get("/keys/amnezia-wireguard/status.json")
    assert r.status_code == 200
    rows = r.json()
    assert isinstance(rows, list) and rows
    row = rows[0]
    assert {"client_id", "online", "endpoint", "rx", "tx"} <= set(row)


def test_nav_renamed():
    c = _client()
    page = c.get("/").text
    assert ">Info</a>" in page and ">VPN</a>" in page and "Tools" in page
    assert ">Services</a>" not in page


def test_extras_page_ok_after_proxy_removal():
    c = _client()
    r = c.post("/deploy/mtproxy/remove", data={"wipe_data": "1", "next": "/extras/mtproxy"},
               follow_redirects=False)
    assert r.status_code == 303
    r = c.get("/extras/mtproxy", follow_redirects=False)
    assert r.status_code == 200


def test_mtproxy_reinstall_shows_links():
    c = _client()
    c.post("/deploy/mtproxy/remove", data={"wipe_data": "1", "next": "/extras/mtproxy"},
           follow_redirects=False)
    r = c.post("/deploy/mtproxy",
               data={"port": "8443", "tls_domain": "googletagmanager.com", "next": "/extras/mtproxy"},
               follow_redirects=False)
    assert "error" not in r.headers["location"]
    page = c.get("/extras/mtproxy").text
    assert "tg://proxy" in page


def test_deploy_rejects_out_of_range_port():
    c = _client()
    b = c.app.state.backend
    b.remove_container("amnezia-wireguard"); b._fs.pop("amnezia-wireguard", None)
    for bad in ("70000", "-1", "0", "65536"):
        r = c.post("/deploy/wireguard", data={"port": bad, "next": "/keys/amnezia-wireguard"},
                   follow_redirects=False)
        assert "error" in r.headers["location"], bad
    assert not b.ran  # nothing was started





def test_keys_page_survives_backend_exec_error():
    c = _client()
    b = c.app.state.backend
    def boom(container, cmd):
        raise RuntimeError("Container is not running")  # docker APIError analog
    b.exec = boom
    r = c.get("/keys/amnezia-wireguard")
    assert r.status_code == 200


def test_slow_forms_show_loading_overlay():
    c = _client()
    page = c.get("/keys/amnezia-wireguard").text
    assert 'id="loading-overlay"' in page
    assert "data-loading" in page  # issue-key + install/remove forms


def test_issued_key_description_has_location():
    import re
    from test_vpn_format import decode_vpn
    c = _client()
    r = c.post("/keys/amnezia-wireguard/create", data={"name": "geo-check"}, follow_redirects=False)
    assert r.status_code == 200
    link = re.search(r'(vpn://[A-Za-z0-9+/=_-]+)', r.text).group(1)
    # mock host: Netherlands/Amsterdam
    assert decode_vpn(link)["description"] == "geo-check | NL-AMS"
