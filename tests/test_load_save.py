import rnp


def test_load_keys():
    rpgp = rnp.Rnp()
    assert rpgp.public_key_count() == 0
    assert rpgp.secret_key_count() == 0
    rpgp.load_keys(
        rnp.Input.from_path("tests/data/keyrings/gpg/pubring.gpg"), "GPG", False, True
    )
    assert rpgp.public_key_count() == 0
    assert rpgp.secret_key_count() == 0
    rpgp.load_keys(
        rnp.Input.from_path("tests/data/keyrings/gpg/pubring.gpg"), "GPG", True, False
    )
    assert rpgp.public_key_count() == 7
    assert rpgp.secret_key_count() == 0

    rpgp.load_keys(
        rnp.Input.from_path("tests/data/keyrings/gpg/secring.gpg"), "GPG", True, False
    )
    assert rpgp.public_key_count() == 7
    assert rpgp.secret_key_count() == 0
    rpgp.load_keys(
        rnp.Input.from_path("tests/data/keyrings/gpg/secring.gpg"), "GPG", False, True
    )
    assert rpgp.public_key_count() == 7
    assert rpgp.secret_key_count() == 7


def test_load_keys_public_from_secret():
    rpgp = rnp.Rnp()
    rpgp.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/secring.gpg"), "GPG")
    assert rpgp.public_key_count() == 7
    assert rpgp.secret_key_count() == 7


def test_save_keys():
    rpgp = rnp.Rnp()
    rpgp.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/pubring.gpg"), "GPG")
    rpgp.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/secring.gpg"), "GPG")

    # public
    outp = rnp.Output.to_bytes()
    rpgp.save_keys(outp, "GPG", True, False)
    assert {
        pkt["header"]["tag.str"]
        for pkt in rnp.parse(rnp.Input.from_bytes(outp.bytes()))
    } == {"Public Key", "Public Subkey", "User ID", "Signature"}

    # secret
    outp = rnp.Output.to_bytes()
    rpgp.save_keys(outp, "GPG", False, True)
    assert {
        pkt["header"]["tag.str"]
        for pkt in rnp.parse(rnp.Input.from_bytes(outp.bytes()))
    } == {"Secret Key", "Secret Subkey", "User ID", "Signature"}


def test_unload_keys():
    # public
    rpgp = rnp.Rnp()
    rpgp.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/pubring.gpg"), "GPG")
    rpgp.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/secring.gpg"), "GPG")
    assert rpgp.public_key_count() == 7
    assert rpgp.secret_key_count() == 7
    rpgp.unload_keys(True, False)
    assert rpgp.public_key_count() == 0
    assert rpgp.secret_key_count() == 7

    # secret
    rpgp = rnp.Rnp()
    rpgp.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/pubring.gpg"), "GPG")
    rpgp.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/secring.gpg"), "GPG")
    assert rpgp.public_key_count() == 7
    assert rpgp.secret_key_count() == 7
    rpgp.unload_keys(False, True)
    assert rpgp.public_key_count() == 7
    assert rpgp.secret_key_count() == 0

    # both
    rpgp = rnp.Rnp()
    rpgp.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/pubring.gpg"), "GPG")
    rpgp.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/secring.gpg"), "GPG")
    assert rpgp.public_key_count() == 7
    assert rpgp.secret_key_count() == 7
    rpgp.unload_keys()
    assert rpgp.public_key_count() == 0
    assert rpgp.secret_key_count() == 0
