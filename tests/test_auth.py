from app.auth import Auth, hash_password, verify_password


def test_hash_roundtrip():
    h = hash_password("s3cret")
    assert h.startswith("pbkdf2$")
    assert verify_password(h, "s3cret")
    assert not verify_password(h, "wrong")


def test_hash_is_salted():
    assert hash_password("same") != hash_password("same")


def test_verify_rejects_malformed():
    for bad in ("", "pbkdf2$", "pbkdf2$abc$zz$zz", "plain-password"):
        assert not verify_password(bad, "x")


def test_auth_accepts_hash_and_plaintext():
    h = hash_password("prod-pass")
    assert Auth(h).check_password("prod-pass")
    assert not Auth(h).check_password("nope")
    # plaintext is dev/mock-only; it still gets hashed inside
    a = Auth("admin")
    assert a._stored.startswith("pbkdf2$")
    assert a.check_password("admin")
    assert not a.check_password("nope")


def test_hash_format_stable():
    # the format .env expects: pbkdf2$iters$salt_hex$hash_hex
    h = hash_password("x")
    _, iters, salt, dk = h.split("$")
    assert int(iters) >= 100_000
    assert len(salt) == 32 and len(dk) == 64
