import rnp


def test_import_sig_rev():
    rpgp = rnp.Rnp()
    rpgp.load_keys(rnp.Input.from_path("tests/data/keys/alice-pub.asc"), "GPG")
    key = rpgp.find_key_by_userid("Alice <alice@rnp>")
    assert len(list(key.signatures())) == 0

    imported = rpgp.import_signatures(
        rnp.Input.from_path("tests/data/keys/alice-rev.pgp")
    )
    assert len(imported["sigs"]) == 1
    assert imported["sigs"][0]["public"] == "new"
    assert (
        imported["sigs"][0]["signer fingerprint"]
        == "73edcc9119afc8e2dbbdcde50451409669ffde3c"
    )
    assert len(list(key.signatures())) == 1
    sig = next(key.signatures())
    assert sig.type() == "key revocation"
    assert sig.alg() == key.alg()
    assert sig.keyid() == "0451409669FFDE3C"
    assert sig.hashalg() == "SHA256"
    assert sig.creation_time() == 1578663151
    if rnp.check('have-rnp-signature-get-expiration'):
        assert sig.lifetime() == 0
    assert sig.signer().keyid() == key.keyid()
    assert sig.status() == 0
