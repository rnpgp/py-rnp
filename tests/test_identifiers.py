import rnp


def test_identifiers():
    rpgp = rnp.Rnp()
    rpgp.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/pubring.gpg"), "GPG")
    assert set(rpgp.userids()) == set(
        ["key0-uid0", "key0-uid1", "key0-uid2", "key1-uid0", "key1-uid1", "key1-uid2"]
    )
    assert set(rpgp.keyids()) == set(
        [
            "7BC6709B15C23A4A",
            "1ED63EE56FADC34D",
            "8A05B89FAD5ADED1",
            "2FCADF05FFA501BB",
            "54505A936A4A970E",
            "326EF111425D14A5",
            "1D7E8A5393C997A8",
        ]
    )
    assert set(rpgp.fingerprints()) == set(
        [
            "E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A",
            "E332B27CAF4742A11BAA677F1ED63EE56FADC34D",
            "C5B15209940A7816A7AF3FB51D7E8A5393C997A8",
            "5CD46D2A0BD0B8CFE0B130AE8A05B89FAD5ADED1",
            "BE1C4AB951F4C2F6B604C7F82FCADF05FFA501BB",
            "A3E94DE61A8CB229413D348E54505A936A4A970E",
            "57F8ED6E5C197DB63C60FFAF326EF111425D14A5",
        ]
    )
    assert set(rpgp.grips()) == set(
        [
            "66D6A0800A3FACDE0C0EB60B16B3669ED380FDFA",
            "D9839D61EDAF0B3974E0A4A341D6E95F3479B9B7",
            "B1CC352FEF9A6BD4E885B5351840EF9306D635F0",
            "E7C8860B70DC727BED6DB64C633683B41221BB40",
            "B2A7F6C34AA2C15484783E9380671869A977A187",
            "43C01D6D96BE98C3C87FE0F175870ED92DE7BE45",
            "8082FE753013923972632550838A5F13D81F43B9",
        ]
    )
