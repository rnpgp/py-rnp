import rnp


def test_key_add_uid():
    rpgp = rnp.Rnp()
    key = rpgp.generate_key(
        {"primary": {"type": "RSA", "length": 1024, "userid": "test"}}
    )["primary"]
    key.add_userid("test2")
    assert set(key.userids()) == set(["test", "test2"])
