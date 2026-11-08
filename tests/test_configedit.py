from app import configedit
from app.backend.mock_backend import MockBackend


def test_read_config_awg2():
    b = MockBackend()
    text = configedit.read_config(b, "amnezia-awg2")
    assert "[Interface]" in text and "HeaderProtectionKey" in text


def test_validate_ok():
    b = MockBackend()
    text = configedit.read_config(b, "amnezia-wireguard")
    assert configedit.validate_config(b, "amnezia-wireguard", text) == []


def test_validate_rejects_peer_edits():
    b = MockBackend()
    text = configedit.read_config(b, "amnezia-wireguard")
    hacked = text.replace("10.8.1.2/32", "10.8.1.99/32")
    errors = configedit.validate_config(b, "amnezia-wireguard", hacked)
    assert any("Peer" in e for e in errors)


def test_validate_semantics():
    b = MockBackend()
    text = configedit.read_config(b, "amnezia-awg2")
    bad = text.replace("S1 = 52", "S1 = 100").replace("S2 = 43", "S2 = 156")
    assert any("S1 + 56" in e for e in configedit.validate_config(b, "amnezia-awg2", bad))
    bad_h = text.replace("H2 = 1234567891", "H2 = 1234567890")
    assert any("unique" in e for e in configedit.validate_config(b, "amnezia-awg2", bad_h))


def test_apply_writes_backup_and_syncs():
    b = MockBackend()
    text = configedit.read_config(b, "amnezia-awg2").replace("Jc = 4", "Jc = 5")
    configedit.apply_config(b, "amnezia-awg2", text)
    assert "Jc = 5" in configedit.read_config(b, "amnezia-awg2")
    backups = configedit.list_backups(b, "amnezia-awg2")
    assert len(backups) == 1 and backups[0].startswith("/opt/amnezia/awg/awg0.conf.bak-")
    assert b.synced == ["amnezia-awg2"]


def test_apply_invalid_raises_and_writes_nothing():
    b = MockBackend()
    before = configedit.read_config(b, "amnezia-wireguard")
    try:
        configedit.apply_config(b, "amnezia-wireguard", "[Interface]\nListenPort = x\n")
    except Exception:
        pass
    assert configedit.read_config(b, "amnezia-wireguard") == before


def test_telemt_toml_flow():
    b = MockBackend()
    assert configedit.validate_config(b, "amnezia-telemt", "not = [toml") != []
    text = configedit.read_config(b, "amnezia-telemt")
    assert configedit.validate_config(b, "amnezia-telemt", text) == []
    configedit.apply_config(b, "amnezia-telemt", text + "\n# edited\n")
    assert b.restarted == ["amnezia-telemt"]


def test_restore_backup():
    b = MockBackend()
    original = configedit.read_config(b, "amnezia-awg2")
    configedit.apply_config(b, "amnezia-awg2", original.replace("Jc = 4", "Jc = 5"))
    name = configedit.list_backups(b, "amnezia-awg2")[0]
    configedit.restore_backup(b, "amnezia-awg2", name)
    assert "Jc = 4" in configedit.read_config(b, "amnezia-awg2")


def test_restore_rejects_traversal():
    b = MockBackend()
    configedit.apply_config(b, "amnezia-wireguard", configedit.read_config(b, "amnezia-wireguard"))
    for bad in ("/opt/amnezia/wireguard/wg0.conf.bak-../clientsTable",
                "/opt/amnezia/wireguard/wg0.conf.bak-x/../secret",
                "/etc/passwd"):
        try:
            configedit.restore_backup(b, "amnezia-wireguard", bad)
            raise AssertionError(f"accepted: {bad}")
        except configedit.AWGError:
            pass


def test_restore_keeps_live_peers():
    from app import awg, keys
    b = MockBackend()
    original = configedit.read_config(b, "amnezia-awg2")
    configedit.apply_config(b, "amnezia-awg2", original.replace("Jc = 4", "Jc = 9"))
    # a key is issued after the backup — restore must not drop it
    keys.create_client(b, "amnezia-awg2", "new-phone", "1.2.3.4", "51821")
    configedit.restore_backup(b, "amnezia-awg2", configedit.list_backups(b, "amnezia-awg2")[0])
    text = configedit.read_config(b, "amnezia-awg2")
    assert "Jc = 4" in text                       # interface rolled back
    assert len(awg.parse_wg_conf(text).peers) == 2  # but the new peer survived


def test_wireguard_rejects_awg_obfuscation_keys():
    """Classic WireGuard runs wg-quick — AWG-only keys would crash it."""
    b = MockBackend()
    text = configedit.read_config(b, "amnezia-wireguard")
    for key in ("Jc", "S1", "H1", "HeaderProtectionKey", "RandomTrailers"):
        bad = text.replace("ListenPort = 51820", f"ListenPort = 51820\n{key} = 5")
        errors = configedit.validate_config(b, "amnezia-wireguard", bad)
        assert any(key in e for e in errors), key
    # same keys are legal on AWG 3.1
    text2 = configedit.read_config(b, "amnezia-awg2")
    assert configedit.validate_config(b, "amnezia-awg2", text2) == []
