import rnp


def test_key_lifetime():
    rpgp = rnp.Rnp()
    rpgp.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/secring.gpg"), "GPG")
    key = rpgp.find_key_by_id("7bc6709b15c23a4a")
    key.unlock("password")
    assert key.lifetime() == 0
    key.set_lifetime(1234)
    assert key.lifetime() == 1234
    pkts = rnp.parse(rnp.Input.from_bytes(key.public_key_data()))
    certs = [
        pkt for pkt in pkts if pkt.get("type.str") == "Positive User ID certification"
    ]
    assert len(certs) == 3
    for cert in certs:
        exp = [
            sub
            for sub in cert["subpackets"]
            if sub["type.str"] == "key expiration time"
        ]
        assert len(exp) == 1
        exp[0]["key expiration"] == 1234
