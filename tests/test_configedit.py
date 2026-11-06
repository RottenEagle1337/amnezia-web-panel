from app import configedit
from app.backend.mock_backend import MockBackend


def test_read_config_awg2():
    b = MockBackend()
    text = configedit.read_config(b, "amnezia-awg2")
    assert "[Interface]" in text and "HeaderProtectionKey" in text


def test_validate_ok():
    b = MockBackend()
    text = configedit.read_config(b, "amnezia-awg")
    assert configedit.validate_config(b, "amnezia-awg", text) == []


def test_validate_rejects_peer_edits():
    b = MockBackend()
    text = configedit.read_config(b, "amnezia-awg")
    hacked = text.replace("10.8.1.2/32", "10.8.1.99/32")
    errors = configedit.validate_config(b, "amnezia-awg", hacked)
    assert any("Peer" in e for e in errors)


def test_validate_semantics():
    b = MockBackend()
    text = configedit.read_config(b, "amnezia-awg")
    bad = text.replace("S1 = 96", "S1 = 100").replace("S2 = 38", "S2 = 156")
    assert any("S1 + 56" in e for e in configedit.validate_config(b, "amnezia-awg", bad))
    bad_h = text.replace("H2 = 2", "H2 = 1")
    assert any("unique" in e for e in configedit.validate_config(b, "amnezia-awg", bad_h))


def test_apply_writes_backup_and_syncs():
    b = MockBackend()
    text = configedit.read_config(b, "amnezia-awg").replace("Jc = 3", "Jc = 5")
    configedit.apply_config(b, "amnezia-awg", text)
    assert "Jc = 5" in configedit.read_config(b, "amnezia-awg")
    backups = configedit.list_backups(b, "amnezia-awg")
    assert len(backups) == 1 and backups[0].startswith("/opt/amnezia/awg/wg0.conf.bak-")
    assert b.synced == ["amnezia-awg"]


def test_apply_invalid_raises_and_writes_nothing():
    b = MockBackend()
    before = configedit.read_config(b, "amnezia-awg")
    try:
        configedit.apply_config(b, "amnezia-awg", "[Interface]\nListenPort = x\n")
    except Exception:
        pass
    assert configedit.read_config(b, "amnezia-awg") == before


def test_telemt_toml_flow():
    b = MockBackend()
    assert configedit.validate_config(b, "amnezia-telemt", "not = [toml") != []
    text = configedit.read_config(b, "amnezia-telemt")
    assert configedit.validate_config(b, "amnezia-telemt", text) == []
    configedit.apply_config(b, "amnezia-telemt", text + "\n# edited\n")
    assert b.restarted == ["amnezia-telemt"]


def test_restore_backup():
    b = MockBackend()
    original = configedit.read_config(b, "amnezia-awg")
    configedit.apply_config(b, "amnezia-awg", original.replace("Jc = 3", "Jc = 5"))
    name = configedit.list_backups(b, "amnezia-awg")[0]
    configedit.restore_backup(b, "amnezia-awg", name)
    assert "Jc = 3" in configedit.read_config(b, "amnezia-awg")


def test_restore_rejects_traversal():
    b = MockBackend()
    configedit.apply_config(b, "amnezia-awg", configedit.read_config(b, "amnezia-awg"))
    for bad in ("/opt/amnezia/awg/wg0.conf.bak-../clientsTable",
                "/opt/amnezia/awg/wg0.conf.bak-x/../secret",
                "/etc/passwd"):
        try:
            configedit.restore_backup(b, "amnezia-awg", bad)
            raise AssertionError(f"accepted: {bad}")
        except configedit.AWGError:
            pass


def test_restore_keeps_live_peers():
    from app import awg, keys
    b = MockBackend()
    original = configedit.read_config(b, "amnezia-awg")
    configedit.apply_config(b, "amnezia-awg", original.replace("Jc = 3", "Jc = 9"))
    # a key is issued after the backup — restore must not drop it
    keys.create_client(b, "amnezia-awg", "new-phone", "1.2.3.4", "51820")
    configedit.restore_backup(b, "amnezia-awg", configedit.list_backups(b, "amnezia-awg")[0])
    text = configedit.read_config(b, "amnezia-awg")
    assert "Jc = 3" in text                       # interface rolled back
    assert len(awg.parse_wg_conf(text).peers) == 3  # but the new peer survived
