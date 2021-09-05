import rnp


def test_protect_lock():
    rpgp = rnp.Rnp()
    rpgp.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/secring.gpg"), "GPG")
    key = rpgp.find_key_by_id("326ef111425d14a5")
    assert key.is_protected()
    assert key.is_locked()
    pkts = rnp.parse(rnp.Input.from_bytes(key.secret_key_data()))
    assert "symmetric algorithm" in pkts[0]["material"].keys()

    key.unlock("password")
    assert not key.is_locked()
    key.unprotect()
    assert not key.is_protected()

    pkts = rnp.parse(rnp.Input.from_bytes(key.secret_key_data()))
    assert "symmetric algorithm" not in pkts[0]["material"].keys()

    key.protect("password")
    assert key.is_protected()
    assert key.is_locked()
    pkts = rnp.parse(rnp.Input.from_bytes(key.secret_key_data()))
    assert "symmetric algorithm" in pkts[0]["material"].keys()

    key.lock()
    assert key.is_locked()
