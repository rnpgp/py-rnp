import pytest
import rnp


@pytest.fixture
def rpgp():
    return rnp.Rnp()


def test_generate_rsa(rpgp):
    key = rpgp.generate_rsa("test-rsa", "hunter2", 1024, 1024)
    assert key.alg() == "RSA"
    assert list(key.userids()) == ["test-rsa"]
    assert key.bits() == 1024
    assert key.is_protected()
    assert len(list(key.subkeys())) == 1
    subkey = next(key.subkeys())
    assert subkey.is_protected()
    assert subkey.alg() == "RSA"
    assert subkey.bits() == 1024
    with pytest.raises(rnp.RnpException):
        key.unlock("badpass")
    key.unlock("hunter2")
    assert not key.is_locked()


def test_generate_rsa_nopass(rpgp):
    key = rpgp.generate_rsa("test", None, 1024, 1024)
    assert not key.is_locked()
    assert not key.is_protected()


def test_generate_dsa_elgamal_nosub(rpgp):
    key = rpgp.generate_dsa_elgamal("test-dsa-elg", None, 1024)
    assert key.alg() == "DSA"
    assert list(key.userids()) == ["test-dsa-elg"]
    assert key.bits() == 1024
    assert isinstance(key.qbits(), int)
    assert not key.is_locked()
    assert not key.is_protected()
    assert len(list(key.subkeys())) == 0


def test_generate_dsa_elgamal(rpgp):
    key = rpgp.generate_dsa_elgamal("test-dsa-elg", None, 1024, 1024)
    assert key.alg() == "DSA"
    assert list(key.userids()) == ["test-dsa-elg"]
    assert len(list(key.subkeys())) == 1
    subkey = next(key.subkeys())
    assert subkey.alg() == "ELGAMAL"
    assert subkey.bits() == 1024


def test_generate_ecdsa_ecdh(rpgp):
    key = rpgp.generate_ecdsa_ecdh("test-ecdsa-ecdh", None, "secp256k1")
    assert key.alg() == "ECDSA"
    assert list(key.userids()) == ["test-ecdsa-ecdh"]
    assert key.curve() == "secp256k1"
    assert len(list(key.subkeys())) == 1
    subkey = next(key.subkeys())
    assert subkey.alg() == "ECDH"
    assert subkey.curve() == "secp256k1"


def test_generate_eddsa_25519(rpgp):
    key = rpgp.generate_eddsa_25519("test-eddsa-25519", None)
    assert key.alg() == "EDDSA"
    assert list(key.userids()) == ["test-eddsa-25519"]
    assert key.curve() == "Ed25519"
    assert len(list(key.subkeys())) == 1
    subkey = next(key.subkeys())
    assert subkey.alg() == "ECDH"
    assert subkey.curve() == "Curve25519"


def test_generate_sm2(rpgp):
    key = rpgp.generate_sm2("test-sm2", None)
    assert key.alg() == "SM2"
    assert list(key.userids()) == ["test-sm2"]
    assert key.curve() == "SM2 P-256"
    assert len(list(key.subkeys())) == 1
    subkey = next(key.subkeys())
    assert subkey.alg() == "SM2"
    assert subkey.curve() == "SM2 P-256"


def test_generate_type_rsa(rpgp):
    key = rpgp.generate("test-rsa", None, "RSA", 1024, None)
    assert key.alg() == "RSA"
    assert list(key.userids()) == ["test-rsa"]
    assert key.bits() == 1024
    assert len(list(key.subkeys())) == 0


def test_generate_type_rsa_withsub(rpgp):
    key = rpgp.generate("test-rsa", None, "RSA", 1024, None, "RSA", 1024)
    assert key.alg() == "RSA"
    assert list(key.userids()) == ["test-rsa"]
    assert key.bits() == 1024
    assert len(list(key.subkeys())) == 1
    subkey = next(key.subkeys())
    assert subkey.alg() == "RSA"
    assert subkey.bits() == 1024


def test_generate_type_ecdsa_sm2(rpgp):
    key = rpgp.generate(
        "test-ecdsa-sm2", None, "ECDSA", 0, "brainpoolP256r1", "SM2", 0, None
    )
    assert key.alg() == "ECDSA"
    assert list(key.userids()) == ["test-ecdsa-sm2"]
    assert key.curve() == "brainpoolP256r1"
    assert len(list(key.subkeys())) == 1
    subkey = next(key.subkeys())
    assert subkey.alg() == "SM2"
