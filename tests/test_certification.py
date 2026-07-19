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


@pytest.fixture
def other_key(rpgp):
    return rpgp.find_key_by_id("2fcadf05ffa501bb")


def test_direct_signature(key):
    sig = rnp.KeySignature.direct(key)
    sig.set_hash("SHA256")
    sig.set_creation_time(1700000000)
    sig.set_key_flags(rnp.RNP_KEY_USAGE_CERTIFY | rnp.RNP_KEY_USAGE_SIGN)
    sig.set_key_expiration(86400)
    sig.set_features(rnp.RNP_KEY_FEATURE_MDC | rnp.RNP_KEY_FEATURE_AEAD)
    sig.add_preferred_cipher("AES256")
    sig.add_preferred_cipher("AES128")
    sig.add_preferred_hash("SHA512")
    sig.add_preferred_hash("SHA256")
    sig.add_preferred_compression("ZIP")
    sig.set_primary_uid(True)
    sig.set_key_server("hkp://keys.example.com")
    sig.set_key_server_prefs(rnp.RNP_KEY_SERVER_NO_MODIFY)
    sig.sign()

    directs = [s for s in key.signatures() if s.type() == "direct"]
    assert len(directs) == 1
    sig = directs[0]
    assert sig.alg() == "RSA"
    assert sig.hashalg() == "SHA256"
    assert sig.creation_time() == 1700000000
    assert sig.key_flags() == rnp.RNP_KEY_USAGE_CERTIFY | rnp.RNP_KEY_USAGE_SIGN
    assert sig.key_expiration() == 86400
    assert (
        sig.features() == rnp.RNP_KEY_FEATURE_MDC | rnp.RNP_KEY_FEATURE_AEAD
    )
    assert list(sig.preferred_ciphers()) == ["AES256", "AES128"]
    assert list(sig.preferred_hashes()) == ["SHA512", "SHA256"]
    assert list(sig.preferred_compression()) == ["ZIP"]
    assert sig.primary_uid()
    assert sig.key_server() == "hkp://keys.example.com"
    assert sig.key_server_prefs() == rnp.RNP_KEY_SERVER_NO_MODIFY
    assert sig.key_fingerprint() == key.fingerprint()
    assert sig.status() == 0


def test_certification(key, other_key):
    uid = next(other_key.uids())
    sig = rnp.KeySignature.certification(key, uid, rnp.RNP_CERTIFICATION_CASUAL)
    sig.set_hash("SHA256")
    sig.set_trust_level(2, 120)
    sig.sign()

    sigs = list(next(other_key.uids()).signatures())
    made = [s for s in sigs if s.keyid() == "7BC6709B15C23A4A"]
    assert len(made) == 1
    sig = made[0]
    assert sig.type() == "certification (casual)"
    assert sig.hashalg() == "SHA256"
    assert sig.trust_level() == (2, 120)
    assert sig.signer().keyid() == key.keyid()
    assert sig.status() == 0

    # export and re-import the certification
    exported = sig.export()
    assert exported.startswith(b"-----BEGIN PGP ")
    raw = sig.export(armored=False)
    assert raw[0] == 0xC0 | 2


def test_certification_self_default_type(key):
    uid = next(key.uids())
    sig = rnp.KeySignature.certification(key, uid)
    sig.sign()
    uid_sigs = list(next(key.uids()).signatures())
    latest = sorted(uid_sigs, key=lambda s: s.creation_time())[-1]
    assert latest.type() == "certification (positive)"


def test_revocation_signature(rpgp):
    key = rpgp.generate_eddsa_25519("revocable@test", None)
    assert not key.is_revoked()

    sig = rnp.KeySignature.revocation(key)
    sig.set_hash("SHA256")
    sig.set_revocation_reason("retired", "no longer used")
    sig.sign()

    key = rpgp.find_key_by_userid("revocable@test")
    assert key.is_revoked()
    assert key.is_retired()
    assert key.revocation_reason() == "no longer used"
    rev = key.revocation_signature()
    assert rev is not None
    assert rev.type() == "key revocation"
    assert rev.revocation_reason() == ("retired", "no longer used")


def test_designated_revoker(key, other_key):
    sig = rnp.KeySignature.direct(key)
    sig.set_revoker(other_key)
    sig.sign()

    assert list(key.revokers()) == [other_key.fingerprint().upper()]
    direct = [s for s in key.signatures() if s.type() == "direct"][-1]
    assert direct.revoker() == other_key.fingerprint().upper()


def test_remove_signature(key, other_key):
    uid = next(other_key.uids())
    rnp.KeySignature.certification(key, uid).sign()
    sigs = list(next(other_key.uids()).signatures())
    made = [s for s in sigs if s.keyid() == "7BC6709B15C23A4A"]
    assert len(made) == 1

    other_key.remove_signature(made[0])
    sigs = list(next(other_key.uids()).signatures())
    assert [s for s in sigs if s.keyid() == "7BC6709B15C23A4A"] == []


def test_remove_signatures_non_self(rpgp):
    key = rpgp.generate_eddsa_25519("remove-sigs-a@test", None)
    signer = rpgp.generate_eddsa_25519("remove-sigs-b@test", None)
    uid = next(key.uids())
    rnp.KeySignature.certification(signer, uid).sign()
    sigs = list(next(key.uids()).signatures())
    assert any(s.keyid() == signer.keyid() for s in sigs)

    removed = []

    def callback(sig, action):
        removed.append((sig.type(), sig.keyid(), action))
        return None

    key.remove_signatures(non_self=True, callback=callback)
    assert len(removed) >= 1
    # all reported signatures were inspected: self-sigs kept, others removed
    for _typ, keyid, action in removed:
        if keyid == signer.keyid():
            assert action == rnp.RNP_KEY_SIGNATURE_REMOVE
        else:
            assert action == rnp.RNP_KEY_SIGNATURE_KEEP

    sigs = list(next(key.uids()).signatures())
    assert not any(s.keyid() == signer.keyid() for s in sigs)
    assert any(s.keyid() == key.keyid() for s in sigs)


def test_remove_signatures_callback_filter(rpgp):
    key = rpgp.generate_eddsa_25519("keep-sigs-a@test", None)
    signer = rpgp.generate_eddsa_25519("keep-sigs-b@test", None)
    uid = next(key.uids())
    rnp.KeySignature.certification(signer, uid).sign()

    # override the default removal action, keeping all signatures
    key.remove_signatures(
        non_self=True, callback=lambda _sig, _action: rnp.RNP_KEY_SIGNATURE_KEEP
    )
    sigs = list(next(key.uids()).signatures())
    assert any(s.keyid() == signer.keyid() for s in sigs)
