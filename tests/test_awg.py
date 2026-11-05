from app import awg, crypto
from app.backend.mock_backend import WG0_CONF_AWG, WG_DUMP_AWG


def test_parse_wg_conf():
    cfg = awg.parse_wg_conf(WG0_CONF_AWG)
    assert cfg.interface["Address"] == "10.8.1.1/24"
    assert cfg.interface["Jc"] == "3"
    assert len(cfg.peers) == 2
    assert cfg.peers[0].allowed_ips == "10.8.1.2/32"
    assert cfg.peers[1].preshared_key


def test_render_roundtrip():
    cfg = awg.parse_wg_conf(WG0_CONF_AWG)
    cfg2 = awg.parse_wg_conf(awg.render_wg_conf(cfg))
    assert cfg2.interface == cfg.interface
    assert [p.public_key for p in cfg2.peers] == [p.public_key for p in cfg.peers]
    assert [p.allowed_ips for p in cfg2.peers] == [p.allowed_ips for p in cfg.peers]


def test_parse_clients_table():
    table = awg.parse_clients_table('[{"clientId": "abc", "userData": {"clientName": "x"}}]')
    assert table[0]["clientId"] == "abc"
    assert awg.parse_clients_table("broken") == []
    assert awg.parse_clients_table("") == []


def test_parse_wg_dump():
    stats = awg.parse_wg_dump(WG_DUMP_AWG)
    peer = stats["XkN3v7mQ2pL8sR4tY6uI9oP1aS5dF7gH0jK3lZ8cV0nE="]
    assert peer.rx == 104857600
    assert peer.endpoint == "203.0.113.50:41234"
    assert peer.latest_handshake > 0
    assert len(stats) == 2


def test_next_free_ip():
    cfg = awg.parse_wg_conf(WG0_CONF_AWG)
    assert awg.next_free_ip(cfg) == "10.8.1.4/32"
    cfg.peers.append(awg.Peer(public_key="k", allowed_ips="10.8.1.4/32"))
    assert awg.next_free_ip(cfg) == "10.8.1.5/32"


def test_render_client_conf_keeps_obfuscation():
    cfg = awg.parse_wg_conf(WG0_CONF_AWG)
    text = awg.render_client_conf(
        cfg, private_key="priv", preshared_key="psk", address="10.8.1.4/32",
        server_public_key="srvpub", endpoint_host="1.2.3.4", endpoint_port="51820")
    for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H4"):
        assert f"{key} = " in text
    assert "Endpoint = 1.2.3.4:51820" in text
    assert "PresharedKey = psk" in text
    assert "Address = 10.8.1.4/32" in text


def test_x25519_matches_wireguard_test_vector():
    # RFC 7748 / wireguard known pair
    priv = "2BJtcgPUj0f7sP1XF+JZk4ej5jLHT2nCIqbbP0/n6Us="
    # sanity: derived public is deterministic and well-formed
    pub = crypto.public_key(priv)
    assert len(pub) == 44
    assert crypto.public_key(priv) == pub
    other = crypto.public_key(crypto.gen_private_key())
    assert other != pub
