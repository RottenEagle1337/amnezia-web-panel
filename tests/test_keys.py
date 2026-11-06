from app import keys
from app.backend.mock_backend import MockBackend


def test_list_clients_merges_table_and_stats():
    backend = MockBackend()
    clients = keys.list_clients(backend, "amnezia-awg")
    assert len(clients) == 2
    by_name = {c.name: c for c in clients}
    ivan = by_name["phone-ivan"]
    assert ivan.ip == "10.8.1.2/32"
    assert ivan.online is True
    assert ivan.endpoint == "203.0.113.50:41234"
    anna = by_name["laptop-anna"]
    assert anna.online is False
    assert anna.orphaned is False


def test_create_then_revoke():
    backend = MockBackend()
    name, config, vpn_link = keys.create_client(backend, "amnezia-awg", "test-device", "1.2.3.4", "51820")

    clients = keys.list_clients(backend, "amnezia-awg")
    assert len(clients) == 3
    new = [c for c in clients if c.name == "test-device"][0]
    assert new.ip == "10.8.1.4/32"
    assert "Endpoint = 1.2.3.4:51820" in config
    assert "[Peer]" in config
    assert backend.synced == ["amnezia-awg"]

    keys.revoke_client(backend, "amnezia-awg", new.client_id)
    clients = keys.list_clients(backend, "amnezia-awg")
    assert len(clients) == 2
    assert all(c.name != "test-device" for c in clients)
    assert backend.synced == ["amnezia-awg", "amnezia-awg"]


def test_revoke_unknown_raises():
    backend = MockBackend()
    try:
        keys.revoke_client(backend, "amnezia-awg", "no-such-key")
    except keys.AWGError as exc:
        assert "not found" in str(exc)
    else:
        raise AssertionError("expected AWGError")


def test_create_rejects_bad_name():
    backend = MockBackend()
    for bad in ("", "   ", "x" * 65):
        try:
            keys.create_client(backend, "amnezia-awg", bad, "1.2.3.4", "51820")
        except keys.AWGError:
            pass
        else:
            raise AssertionError(f"expected AWGError for {bad!r}")


def test_awg2_layout_supported():
    backend = MockBackend()
    clients = keys.list_clients(backend, "amnezia-awg2")
    assert len(clients) == 1
    assert clients[0].name == "tablet-oleg"
    assert clients[0].ip == "10.9.9.2/32"
    _, config, _ = keys.create_client(backend, "amnezia-awg2", "d2", "1.2.3.4", "51821")
    # AWG 3.1 obfuscation params must land in the client config
    assert "S3 = " in config and "I1 = " in config


def test_awg2_writes_awg0_conf():
    """amnezia-awg2 stores peers in awg0.conf, not wg0.conf."""
    from app.backend.mock_backend import WG0_CONF_AWG2
    backend = MockBackend()
    before = backend._fs["amnezia-awg2"]["/opt/amnezia/awg/awg0.conf"]
    keys.create_client(backend, "amnezia-awg2", "layout-check", "1.2.3.4", "51821")
    fs = backend._fs["amnezia-awg2"]
    assert fs["/opt/amnezia/awg/awg0.conf"] != before
    assert fs["/opt/amnezia/awg/awg0.conf"].count("[Peer]") == before.count("[Peer]") + 1
    assert fs["/opt/amnezia/awg/wg0.conf"] == WG0_CONF_AWG2


def test_create_missing_conf_raises_awgerror():
    """Empty/unreadable server config gives AWGError, not a bare ValueError."""
    backend = MockBackend()
    del backend._fs["amnezia-awg"]["/opt/amnezia/awg/wg0.conf"]
    try:
        keys.create_client(backend, "amnezia-awg", "x", "1.2.3.4", "51820")
    except keys.AWGError as exc:
        assert "Address" in str(exc)
    else:
        raise AssertionError("expected AWGError")
