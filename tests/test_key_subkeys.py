import rnp


def test_subkeys():
    rpgp = rnp.Rnp()
    rpgp.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/pubring.gpg"), "GPG")
    key = rpgp.find_key_by_id("2fcadf05ffa501bb")
    assert set(map(lambda key: key.keyid(), key.subkeys())) == set(
        ["54505A936A4A970E", "326EF111425D14A5"]
    )
    rpgp.find_key_by_id("326EF111425D14A5").remove(True, False)
    assert set(map(lambda key: key.keyid(), key.subkeys())) == set(["54505A936A4A970E"])
