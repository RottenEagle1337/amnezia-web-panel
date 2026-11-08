"""Xray container deployment (mirrors client server_scripts/xray)."""
import json

from app import deploy
from app.backend.mock_backend import MockBackend


def _deploy(port=1443):
    # The mock pre-seeds amnezia-xray as a placeholder service and telemt sits
    # on 443/tcp — remove the placeholder and use a free port (same pattern as
    # tests/test_deploy.py does for telemt).
    b = MockBackend()
    b.remove_container("amnezia-xray")
    deploy.deploy_xray(b, port)
    return b


def test_spec_registered():
    spec = deploy.DEPLOYABLE["xray"]
    assert spec.container == "amnezia-xray"
    assert spec.default_port == 443
    assert spec.kind == "vpn"


def test_builds_image_and_runs_container():
    b = _deploy()
    assert "amnezia-xray" in b.built
    run = next(r for r in b.ran if r["name"] == "amnezia-xray")
    assert run["ports"] == {"1443/tcp": 1443, "1443/udp": 1443}
    assert run["privileged"] is True
    assert run["cap_add"] == ["NET_ADMIN"]
    assert run["volumes"] == {"amnezia-xray-data": {"bind": "/opt/amnezia/xray", "mode": "rw"}}


def test_generates_reality_key_material():
    b = _deploy()
    files = b._fs["amnezia-xray"]
    for name in ("xray_uuid.key", "xray_short_id.key", "xray_private.key", "xray_public.key"):
        assert files[f"/opt/amnezia/xray/{name}"].strip(), name


def test_writes_server_json_and_clients_table():
    b = _deploy()
    files = b._fs["amnezia-xray"]
    server = json.loads(files["/opt/amnezia/xray/server.json"])
    inbound = server["inbounds"][0]
    assert inbound["port"] == 1443
    assert inbound["protocol"] == "vless"
    assert inbound["settings"] == {"clients": [], "decryption": "none"}
    reality = inbound["streamSettings"]["realitySettings"]
    assert reality["dest"] == "www.googletagmanager.com:443"
    assert reality["serverNames"] == ["www.googletagmanager.com"]
    assert reality["privateKey"] == files["/opt/amnezia/xray/xray_private.key"].strip()
    assert reality["shortIds"] == [files["/opt/amnezia/xray/xray_short_id.key"].strip()]
    assert server["outbounds"] == [{"protocol": "freedom"}]
    assert json.loads(files["/opt/amnezia/xray/clientsTable"]) == []


def test_start_script_written_executable_and_restarted():
    b = _deploy()
    start = b._fs["amnezia-xray"]["/opt/amnezia/start.sh"]
    assert "xray -config /opt/amnezia/xray/server.json" in start
    assert "iptables -A INPUT -p tcp --dport 1443 -j ACCEPT" in start
    assert "/opt/amnezia/start.sh" in b.chmodded
    assert "amnezia-xray" in b.restarted


def test_refuses_second_install_and_busy_port():
    b = _deploy()
    try:
        deploy.deploy_xray(b, 2443)
        assert False, "expected AWGError"
    except Exception as exc:
        assert "already exists" in str(exc)
