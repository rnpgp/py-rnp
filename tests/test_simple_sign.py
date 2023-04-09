import time
import random
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


def test_simple_sign(rpgp, key):
    signature = rpgp.sign(key, rnp.Input.from_bytes(b"test data"))
    assert isinstance(signature, bytes)
    assert len(signature) >= 1
    rpgp.verify(rnp.Input.from_bytes(signature))
    outp = rnp.Output.to_bytes()
    rpgp.verify(rnp.Input.from_bytes(signature), outp)
    assert outp.bytes() == b"test data"


def test_simple_sign_with_options(rpgp, key):

    # SHA1 signatures produced later than 2019-01-19 are invalid.
    # MD5 signatures produced later than 2012-01-01 are invalid.

    halg = random.choice(
        [
            halg
            for halg in rnp.features("hash algorithm")
            if halg != "MD5" and halg != "SHA1"
        ]
    )

    calg = random.choice(
        [
            calg
            for calg in rnp.features("compression algorithm")
            if calg != "Uncompressed"
        ]
    )

    signature = rpgp.sign(
        key,
        rnp.Input.from_bytes(b"test data"),
        True,
        halg,
        (calg, 1),
        int(time.time()),
        60 * 10,
    )
    assert isinstance(signature, bytes)
    assert len(signature) >= 1
    assert signature.startswith(b"-----BEGIN PGP MESSAGE-----\r\n")
    rpgp.verify(rnp.Input.from_bytes(signature))

    op = rnp.Verify.start(rpgp, rnp.Input.from_bytes(signature))
    op.finish()
    assert len(list(op.signatures())) == 1
    sig = next(op.signatures())
    if rnp.check('have-rnp-signature-get-expiration'):
        assert sig.lifetime() == 60 * 10
    assert sig.status() == 0


def test_simple_sign_cleartext(rpgp, key):
    key2 = rpgp.find_key_by_fingerprint("be1c4ab951f4c2f6b604c7f82fcadf05ffa501bb")
    key2.unlock("password")
    signature = rpgp.sign_cleartext([key, key2], rnp.Input.from_bytes(b"some data"))
    assert signature.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----\r\n")
    pkts = rnp.parse(rnp.Input.from_bytes(signature))

    assert [pkt["header"]["tag.str"] for pkt in pkts] == ["Signature", "Signature"]
    assert {
        subpkt.get("issuer keyid")
        for pkt in pkts
        for subpkt in pkt["subpackets"]
        if "issuer keyid" in subpkt
    } == {"7bc6709b15c23a4a", "2fcadf05ffa501bb"}

    rpgp.verify(rnp.Input.from_bytes(signature))


def test_simple_sign_detached(rpgp, key):
    signature = rpgp.sign_detached(key, rnp.Input.from_bytes(b"test"))
    rpgp.verify_detached(rnp.Input.from_bytes(b"test"), rnp.Input.from_bytes(signature))
    with pytest.raises(rnp.RnpException):
        rpgp.verify_detached(
            rnp.Input.from_bytes(b"test2"), rnp.Input.from_bytes(signature)
        )
    signature = bytearray(signature)
    signature[int(len(signature) / 2)] ^= 0xFF
    with pytest.raises(rnp.RnpException):
        rpgp.verify_detached(
            rnp.Input.from_bytes(b"test"), rnp.Input.from_bytes(signature)
        )
