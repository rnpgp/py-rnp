import rnp


def test_key_count():
    rpgp = rnp.Rnp()
    rpgp.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/pubring.gpg"), "GPG")
    assert rpgp.public_key_count() == 7
    assert rpgp.secret_key_count() == 0
    rpgp.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/secring.gpg"), "GPG")
    assert rpgp.secret_key_count() == 7
