import pytest
import rnp

RNP_ERROR_SIGNATURE_INVALID = 0x12000002
RNP_ERROR_SIG_LBITS_MISMATCH = 0x14000006

# signature subpacket types, see RFC 4880 section 5.2.3.1
SUBPACKET_CREATION_TIME = 2
SUBPACKET_ISSUER = 16
SUBPACKET_ISSUER_FPR = 33


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


def test_verify_signature_details(rpgp, key):
    signature = rpgp.sign(key, rnp.Input.from_bytes(b"test data"))
    op = rpgp.verify(rnp.Input.from_bytes(signature))
    sig = next(op.signatures())
    assert sig.type() == "binary"
    assert sig.alg() == "RSA"
    assert sig.keyid() == "7BC6709B15C23A4A"
    assert sig.key_fingerprint() == "E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A"
    assert sig.status() == 0
    assert sig.error_count() == 0
    assert list(sig.errors()) == []
    # operation-level signature details
    assert sig.hash() == sig.hashalg()
    assert sig.key().keyid() == "7BC6709B15C23A4A"
    create, expires = sig.times()
    assert create == sig.creation_time()
    assert expires == sig.lifetime()
    # literal data format: binary
    assert op.format() == "b"


def test_verify_signature_errors(rpgp, key):
    signature = rpgp.sign_detached(key, rnp.Input.from_bytes(b"test"))
    op = rnp.Verify.start_detached(
        rpgp, rnp.Input.from_bytes(b"modified"), rnp.Input.from_bytes(signature)
    )
    with pytest.raises(rnp.RnpException):
        op.finish()
    sig = next(op.signatures())
    assert sig.status() == RNP_ERROR_SIGNATURE_INVALID
    assert sig.error_count() >= 1
    errors = list(sig.errors())
    assert len(errors) == sig.error_count()
    assert RNP_ERROR_SIG_LBITS_MISMATCH in errors
    assert RNP_ERROR_SIGNATURE_INVALID in errors


def test_signature_subpackets(rpgp, key):
    signature = rpgp.sign(key, rnp.Input.from_bytes(b"test data"))
    op = rpgp.verify(rnp.Input.from_bytes(signature))
    sig = next(op.signatures())
    subpackets = list(sig.subpackets())
    assert len(subpackets) == sig.subpacket_count()
    assert len(subpackets) >= 3
    types = [subpkt.type() for subpkt in subpackets]
    assert SUBPACKET_CREATION_TIME in types
    assert SUBPACKET_ISSUER_FPR in types
    for subpkt in subpackets:
        assert isinstance(subpkt.hashed(), bool)
        assert isinstance(subpkt.critical(), bool)
        assert isinstance(subpkt.data(), bytes)
    # find issuer fingerprint subpacket in the hashed area
    subpkt = sig.find_subpacket(SUBPACKET_ISSUER_FPR, hashed=True)
    assert subpkt is not None
    assert subpkt.type() == SUBPACKET_ISSUER_FPR
    assert subpkt.hashed()
    # no such subpacket type in this signature
    assert sig.find_subpacket(12) is None


def test_signature_export(rpgp, key):
    signature = rpgp.sign(key, rnp.Input.from_bytes(b"test data"))
    op = rpgp.verify(rnp.Input.from_bytes(signature))
    sig = next(op.signatures())
    armored = sig.export()
    assert armored.startswith(b"-----BEGIN PGP ")
    assert armored.rstrip().endswith(b"-----")
    raw = sig.export(armored=False)
    # new-format signature packet header: 0xc0 | tag 2
    assert raw[0] == 0xC0 | 2
    # raw and armored export carry the same packet
    assert raw in rnp.dearmor(rnp.Input.from_bytes(armored))


def test_recipient_symenc_enumeration(rpgp, key):
    outp = rnp.Output.to_bytes()
    op = rnp.Encrypt.start(rpgp, rnp.Input.from_bytes(b"secret data"), outp)
    op.add_recipient(key)
    op.add_password("sympass123", "SHA256", 10000, "AES256")
    op.finish()

    # return the symenc password only, so the message is decrypted with it
    # and not with the recipient's key
    rpgp.set_password_provider(lambda _key, _reason: "sympass123")
    vop = rnp.Verify.start(rpgp, rnp.Input.from_bytes(outp.bytes()))
    vop.finish()

    assert vop.recipient_count() == 1
    recipients = list(vop.recipients())
    assert len(recipients) == 1
    recipient = recipients[0]
    assert recipient.keyid() == "8A05B89FAD5ADED1"
    assert recipient.alg() == "RSA"

    assert vop.symenc_count() == 1
    symencs = list(vop.symencs())
    assert len(symencs) == 1
    symenc = symencs[0]
    assert symenc.cipher() == "AES256"
    assert symenc.aead_alg() == "None"
    assert symenc.hash_alg() == "SHA256"
    assert symenc.s2k_type() == "Iterated and salted"
    assert symenc.s2k_iterations() > 0

    # message was decrypted with the password, not the recipient's key
    assert vop.used_recipient() is None
    assert vop.used_symenc() is not None
    assert vop.protection_mode() == "cfb-mdc"
    assert vop.protection_valid()


def test_used_recipient(rpgp, key):
    outp = rnp.Output.to_bytes()
    op = rnp.Encrypt.start(rpgp, rnp.Input.from_bytes(b"secret data"), outp)
    op.add_recipient(key)
    op.finish()

    rpgp.set_password_provider(lambda _key, _reason: "password")
    vop = rnp.Verify.start(rpgp, rnp.Input.from_bytes(outp.bytes()))
    vop.finish()

    assert vop.recipient_count() == 1
    used = vop.used_recipient()
    assert used is not None
    assert used.keyid() == "8A05B89FAD5ADED1"
    assert used.alg() == "RSA"
    assert vop.used_symenc() is None


def test_verify_flags_ignore_sigs_on_decrypt(rpgp, key):
    # SHA1 data signatures are considered insecure by the default security
    # rules, so verification fails unless signature errors are ignored
    message = rpgp.encrypt_and_sign(
        rnp.Input.from_bytes(b"data"), key, key, hashalg="SHA1"
    )
    rpgp.set_password_provider(lambda _key, _reason: "password")
    with pytest.raises(rnp.RnpException):
        rpgp.verify(rnp.Input.from_bytes(message))

    op = rnp.Verify.start(rpgp, rnp.Input.from_bytes(message))
    op.flags = rnp.RNP_VERIFY_IGNORE_SIGS_ON_DECRYPT
    assert op.flags == rnp.RNP_VERIFY_IGNORE_SIGS_ON_DECRYPT
    op.finish()
    sigs = list(op.signatures())
    assert len(sigs) == 1
    assert sigs[0].status() == RNP_ERROR_SIGNATURE_INVALID
