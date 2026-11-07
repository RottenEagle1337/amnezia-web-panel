from app.backend.mock_backend import MockBackend


def test_mock_records_docker_ops():
    b = MockBackend()
    b.pull_image("amneziavpn/amneziawg-go:latest")
    b.run_container("amnezia-awg2", "amneziavpn/amneziawg-go:latest",
                    ports={"51821/udp": 51821}, env={}, volumes={},
                    privileged=True, cap_add=["NET_ADMIN", "SYS_MODULE"],
                    sysctls={"net.ipv4.conf.all.src_valid_mark": "1"})
    b.ensure_network("amnezia-dns-net", "172.29.172.0/24")
    b.connect_network("amnezia-dns-net", "amnezia-awg2")
    assert b.pulled == ["amneziavpn/amneziawg-go:latest"]
    assert b.ran[0]["name"] == "amnezia-awg2"
    assert b.networks_created == [("amnezia-dns-net", "172.29.172.0/24")]
    b.remove_container("amnezia-awg2", remove_volumes=True)
    assert b.removed == [("amnezia-awg2", True)]


from app import deploy  # noqa: E402


def test_obfuscation_constraints():
    for _ in range(50):
        p = deploy._rand_obfuscation("3.1")
        assert int(p["S1"]) + 56 != int(p["S2"])
        hs = [p["H1"], p["H2"], p["H3"], p["H4"]]
        assert len(set(hs)) == 4
        assert 4 <= int(p["Jc"]) <= 6
        assert "HeaderProtectionKey" in p
    p2 = deploy._rand_obfuscation("2.0")
    assert "HeaderProtectionKey" not in p2 and "S3" not in p2


def test_deploy_awg2_creates_container_and_config():
    b = MockBackend()
    # remove the pre-seeded awg2 to simulate a fresh server
    b.remove_container("amnezia-awg2")
    b._fs.pop("amnezia-awg2", None)
    deploy.deploy_awg(b, "3.1", 51821)
    assert b.pulled == ["amneziavpn/amneziawg-go:latest"]
    assert b.ran[0]["name"] == "amnezia-awg2"
    conf = b._fs["amnezia-awg2"]["/opt/amnezia/awg/awg0.conf"]
    assert "ListenPort = 51821" in conf and "HeaderProtectionKey" in conf
    assert b._fs["amnezia-awg2"]["/opt/amnezia/awg/clientsTable"] == "[]\n"


def test_deploy_refuses_existing_and_busy_port():
    b = MockBackend()
    try:
        deploy.deploy_awg(b, "3.1", 51821)  # amnezia-awg2 exists in the mock
    except Exception as exc:
        assert "already exists" in str(exc)
    else:
        raise AssertionError("expected refusal")


def test_remove_service():
    b = MockBackend()
    deploy.remove_service(b, "awg2", wipe_data=True)
    assert ("amnezia-awg2", True) in b.removed


def test_deploy_dns_builds_image_and_network():
    b = MockBackend()
    b.remove_container("amnezia-dns"); b._fs.pop("amnezia-dns", None)
    deploy.deploy_dns(b)
    assert ("amnezia-dns-net", "172.29.172.0/24") in b.networks_created
    assert b.built == ["amnezia-dns"]
    assert ("amnezia-dns-net", "amnezia-dns", "172.29.172.254") in b.network_connects


def test_deploy_mtproxy_env_and_volume():
    b = MockBackend()
    b.remove_container("amnezia-mtproxy"); b._fs.pop("amnezia-mtproxy", None)
    deploy.deploy_mtproxy(b, 8443, "googletagmanager.com")
    run = b.ran[0]
    assert run["env"]["MTPROXY_TRANSPORT_MODE"] == "faketls"
    assert run["volumes"]["amnezia-mtproxy-data"]["bind"] == "/data"


def test_deploy_telemt_writes_config_and_restarts():
    b = MockBackend()
    b.remove_container("amnezia-telemt"); b._fs.pop("amnezia-telemt", None)
    b.remove_container("amnezia-xray"); b._fs.pop("amnezia-xray", None)  # occupies 443 in the mock
    deploy.deploy_telemt(b, 443, "github.com")
    conf = b._fs["amnezia-telemt"]["/etc/telemt/config.toml"]
    assert 'tls_domain = "github.com"' in conf and "tg_main" in conf
    assert b.restarted == ["amnezia-telemt"]


def test_deploy_dns_connects_existing_awg_containers():
    b = MockBackend()  # amnezia-awg / amnezia-awg2 pre-seeded
    b.remove_container("amnezia-dns"); b._fs.pop("amnezia-dns", None)
    deploy.deploy_dns(b)
    names = {c for _, c, _ in b.network_connects}
    assert {"amnezia-dns", "amnezia-awg", "amnezia-awg2"} <= names


def test_deploy_rejects_invalid_tls_domain():
    b = MockBackend()
    b.remove_container("amnezia-telemt"); b._fs.pop("amnezia-telemt", None)
    b.remove_container("amnezia-xray"); b._fs.pop("amnezia-xray", None)  # frees port 443
    for bad in ('git"hub.com', "evil.com\n[access.users]", "-bad-.com", "no dots"):
        try:
            deploy.deploy_telemt(b, 443, bad)
        except deploy.AWGError:
            pass
        else:
            raise AssertionError(f"accepted bad domain: {bad!r}")
    assert not b.ran  # nothing was started
