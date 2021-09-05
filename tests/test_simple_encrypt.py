import pytest
import rnp


@pytest.fixture
def rpgp():
    lib = rnp.Rnp()
    lib.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/pubring.gpg"), "GPG")
    lib.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/secring.gpg"), "GPG")
    return lib


def simple_password_provider(key, reason):
    return "password"


def test_simple_encrypt(rpgp):
    key = rpgp.find_key_by_id("54505a936a4a970e")
    plaintext = "this is a test".encode("utf-8")
    encrypted = rpgp.encrypt(rnp.Input.from_bytes(plaintext), key)
    assert isinstance(encrypted, bytes)
    rpgp.set_password_provider(simple_password_provider)
    decrypted = rpgp.decrypt(rnp.Input.from_bytes(encrypted))
    assert decrypted == plaintext


def test_simple_encrypt_sign(rpgp):
    key1 = rpgp.find_key_by_userid("key0-uid2")
    key2 = rpgp.find_key_by_userid("key1-uid0")
    plaintext = b"this is a test"
    rpgp.set_password_provider(lambda key, reason: "password")
    encrypted = rpgp.encrypt_and_sign(
        rnp.Input.from_bytes(plaintext), [key1, key2], [key1]
    )
    assert isinstance(encrypted, bytes)
    decrypted = rpgp.decrypt(rnp.Input.from_bytes(encrypted))
    assert decrypted == plaintext

    verify = rpgp.verify(rnp.Input.from_bytes(encrypted))
    signatures = list(verify.signatures())
    assert len(signatures) == 1
    assert signatures[0].keyid() == key1.keyid()


def test_simple_symmetric_encrypt_single():
    rpgp = rnp.Rnp()
    plaintext = b"secret data"
    encrypted = rpgp.symmetric_encrypt(rnp.Input.from_bytes(plaintext), "pass")
    rpgp.set_password_provider(lambda key, reason: "pass")
    assert rpgp.decrypt(rnp.Input.from_bytes(encrypted)) == plaintext


def test_simple_symmetric_encrypt_multiple():
    rpgp = rnp.Rnp()
    plaintext = b"secret data"
    encrypted = rpgp.symmetric_encrypt(
        rnp.Input.from_bytes(plaintext), ["pass1", "pass2"]
    )
    # bad password
    with pytest.raises(rnp.RnpException):
        rpgp.set_password_provider(lambda key, reason: "pass")
        rpgp.decrypt(rnp.Input.from_bytes(encrypted))
    # no password
    with pytest.raises(rnp.RnpException):
        rpgp.set_password_provider(None)
        rpgp.decrypt(rnp.Input.from_bytes(encrypted))

    rpgp.set_password_provider(lambda key, reason: "pass1")
    assert rpgp.decrypt(rnp.Input.from_bytes(encrypted)) == plaintext

    rpgp.set_password_provider(lambda key, reason: "pass2")
    assert rpgp.decrypt(rnp.Input.from_bytes(encrypted)) == plaintext
