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
    return rpgp.find_key_by_id("7bc6709b15c23a4a")


def test_key_to(key):
    assert key.to("sign").keyid() == key.keyid()
    assert key.to("certify").keyid() == key.keyid()
    assert key.to("sign", True) is None
    assert key.to("encrypt").keyid() == "8A05B89FAD5ADED1"
