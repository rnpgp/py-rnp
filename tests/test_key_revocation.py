import random
import pytest
import rnp


@pytest.fixture
def rpgp():
    return rnp.Rnp()


@pytest.fixture
def key(rpgp):
    return rpgp.generate_key(
        {"primary": {"type": "RSA", "length": 1024, "userid": "testing"}}
    )["primary"]


def test_key_revocation(key):
    assert not key.is_revoked()
    key.revoke()
    assert key.is_revoked()


def test_key_revocation_sig(key):
    assert key.revocation_signature() is None
    key.revoke()
    assert isinstance(key.revocation_signature(), rnp.Signature)
    assert (
        key.revocation_signature().json()[0]["type.str"] == "Key revocation signature"
    )


def test_key_revocation_reason(key):
    assert not key.is_revoked()
    key.revoke(None, None, "for testing")
    assert key.is_revoked()
    assert key.revocation_reason() == "for testing"


def test_key_revocation_code(key):
    assert not key.is_revoked()
    key.revoke(None, "compromised")
    assert key.is_compromised()
    assert not key.is_retired()
    assert not key.is_superseded()


def test_key_revocation_hash(rpgp, key):
    hashalg = random.choice(rnp.features("hash algorithm"))
    key.revoke(hashalg)
    pkts = key.packets_json()
    pkt = next(
        filter(lambda pkt: pkt.get("type.str") == "Key revocation signature", pkts)
    )
    assert pkt["hash algorithm.str"] == hashalg
