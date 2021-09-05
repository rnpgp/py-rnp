import rnp


def test_key_user_attr_photo():
    rpgp = rnp.Rnp()
    rpgp.load_keys(
        rnp.Input.from_path("tests/data/keys/ecc-25519-photo-pub.asc"), "GPG"
    )
    key = rpgp.find_key_by_id("CC786278981B0728")
    assert list(key.userids()) == ["ecc-25519"]
    uids = list(key.uids())
    assert len(uids) == 2
    assert uids[0].type() == rnp.UID.RNP_USER_ID
    assert not uids[0].is_primary()
    assert uids[0].is_valid()
    assert not uids[0].is_revoked()
    assert uids[0].data() == b"ecc-25519"

    assert uids[1].type() == rnp.UID.RNP_USER_ATTR
    assert not uids[1].is_primary()
    assert uids[1].is_valid()
    assert not uids[1].is_revoked()


def test_key_uid_revsig():
    rpgp = rnp.Rnp()
    rpgp.load_keys(
        rnp.Input.from_path("tests/data/keys/ecc-p256-revoked-uid.asc"), "GPG"
    )
    key = rpgp.find_key_by_id("23674f21b2441527")
    uids = list(key.uids())
    assert len(uids) == 2
    assert uids[0].revocation_signature() is None

    sigs = list(uids[0].signatures())
    assert len(sigs) == 1
    sig = sigs[0]
    assert sig.type() == "certification (positive)"
    assert sig.alg() == "ECDSA"
    assert sig.hashalg() == "SHA256"
    assert sig.keyid() == "23674F21B2441527"
    assert sig.creation_time() == 1549119463
    if rnp.check('have-rnp-signature-get-expiration'):
        assert sig.lifetime() == 0
    assert sig.signer().keyid() == "23674F21B2441527"
    assert sig.status() == 0

    sigs = list(uids[1].signatures())
    assert len(sigs) == 2
    sig = sigs[0]
    assert sig.type() == "certification revocation"
    assert sig.alg() == "ECDSA"
    assert sig.hashalg() == "SHA256"
    assert sig.keyid() == "23674F21B2441527"
    assert sig.creation_time() == 1556630215
    if rnp.check('have-rnp-signature-get-expiration'):
        assert sig.lifetime() == 0
    assert sig.signer().keyid() == "23674F21B2441527"
    assert sig.status() == 0

    sig = sigs[1]
    assert sig.type() == "certification (positive)"
    assert sig.alg() == "ECDSA"
    assert sig.hashalg() == "SHA256"
    assert sig.keyid() == "23674F21B2441527"
    assert sig.creation_time() == 1556630177
    if rnp.check('have-rnp-signature-get-expiration'):
        assert sig.lifetime() == 0
    assert sig.signer().keyid() == "23674F21B2441527"
    assert sig.status() == 0

    assert uids[1].revocation_signature().creation_time() == 1556630215
