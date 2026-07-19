import time

import pytest
import rnp


@pytest.fixture
def rpgp():
    lib = rnp.Rnp()
    lib.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/pubring.gpg"), "GPG")
    lib.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/secring.gpg"), "GPG")
    return lib


@pytest.fixture
def key(rpgp):
    key = rpgp.find_key_by_id("7bc6709b15c23a4a")
    key.unlock("password")
    return key


def test_get_security_rule_default(rpgp):
    # by default SHA1 data signatures are insecure since 2019-01-19
    rule = rpgp.get_security_rule("hash algorithm", "SHA1", int(time.time()))
    assert rule["level"] == rnp.RNP_SECURITY_INSECURE
    assert rule["from"] <= int(time.time())
    # there is no rule for old signatures, so the default level applies
    rule = rpgp.get_security_rule("hash algorithm", "SHA1", 0)
    assert rule["level"] == rnp.RNP_SECURITY_DEFAULT


def test_security_rule_allow_then_deny(rpgp, key):
    # SHA1 data signature made now is rejected by the default rules
    signature = rpgp.sign(key, rnp.Input.from_bytes(b"test data"), hashalg="SHA1")
    with pytest.raises(rnp.RnpException):
        rpgp.verify(rnp.Input.from_bytes(signature))

    # explicitly allow SHA1 with an override rule
    rpgp.add_security_rule(
        "hash algorithm",
        "SHA1",
        rnp.RNP_SECURITY_DEFAULT,
        from_time=0,
        flags=rnp.RNP_SECURITY_OVERRIDE,
    )
    rule = rpgp.get_security_rule("hash algorithm", "SHA1", int(time.time()))
    assert rule["level"] == rnp.RNP_SECURITY_DEFAULT
    rpgp.verify(rnp.Input.from_bytes(signature))

    # remove the rule again, restoring the default behaviour
    removed = rpgp.remove_security_rule(
        "hash algorithm",
        "SHA1",
        level=rnp.RNP_SECURITY_DEFAULT,
        flags=rnp.RNP_SECURITY_OVERRIDE,
        from_time=0,
    )
    assert removed == 1
    with pytest.raises(rnp.RnpException):
        rpgp.verify(rnp.Input.from_bytes(signature))


def test_remove_security_rule_all(rpgp):
    rpgp.add_security_rule(
        "hash algorithm", "SHA256", rnp.RNP_SECURITY_INSECURE, from_time=0
    )
    rule = rpgp.get_security_rule("hash algorithm", "SHA256", int(time.time()))
    assert rule["level"] == rnp.RNP_SECURITY_INSECURE
    removed = rpgp.remove_security_rule(
        "hash algorithm", "SHA256", flags=rnp.RNP_SECURITY_REMOVE_ALL
    )
    assert removed >= 1
    rule = rpgp.get_security_rule("hash algorithm", "SHA256", int(time.time()))
    assert rule["level"] == rnp.RNP_SECURITY_DEFAULT


def test_add_security_rule_bad_params(rpgp):
    with pytest.raises(rnp.RnpException):
        rpgp.add_security_rule("nonsense", "SHA1", rnp.RNP_SECURITY_INSECURE)
    with pytest.raises(rnp.RnpException):
        rpgp.add_security_rule("hash algorithm", "SHA1", 42)


def test_set_timestamp():
    rpgp = rnp.Rnp()
    rpgp.set_timestamp(1500000000)
    key = rpgp.generate_eddsa_25519("timestamp@test", None)
    assert key.creation_time() == 1500000000
    rpgp.set_timestamp(0)
    key = rpgp.generate_eddsa_25519("timestamp2@test", None)
    assert abs(key.creation_time() - int(time.time())) < 60
