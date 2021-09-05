import rnp


def test_op_generate_rsa():
    rpgp = rnp.Rnp()
    op = rnp.Generate.start(rpgp, "RSA")
    op.bits = 1024
    op.hashalg = "SM3"
    op.cipher = "SM4"
    op.password = "\u3042"
    op.s2k_hashalg = "SM3"
    op.s2k_iterations = 12800
    op.usage = ["sign", "certify"]
    op.uid = "test"
    op.lifetime = 1234

    key = op.finish()
    assert key.alg() == "RSA"
    assert key.bits() == 1024
    assert key.can_sign()
    assert key.can_certify()
    assert not key.can_encrypt()
    assert key.lifetime() == 1234
    assert list(key.userids()) == ["test"]

    key.unlock("\u3042")

    pkts = rnp.parse(rnp.Input.from_bytes(key.secret_key_data()))
    assert pkts[0]["material"]["s2k"]["hash algorithm.str"] == "SM3"
    assert pkts[0]["material"]["s2k"]["iterations"] == 12800
    assert pkts[0]["material"]["symmetric algorithm.str"] == "SM4"
    assert pkts[1]["userid"] == "test"
    assert pkts[2]["hash algorithm.str"] == "SM3"
    assert set(
        next(filter(lambda pkt: pkt["type.str"] == "key flags", pkts[2]["subpackets"]))[
            "flags.str"
        ]
    ) == {"sign", "certify"}


def test_op_generate_dsa():
    rpgp = rnp.Rnp()
    op = rnp.Generate.start(rpgp, "DSA")
    op.qbits = 160
    key = op.finish()
    assert key.alg() == "DSA"
    assert key.qbits() == 160


def test_op_generate_ecdsa():
    rpgp = rnp.Rnp()
    op = rnp.Generate.start(rpgp, "ECDSA")
    op.curve = "secp256k1"
    op.preferences = {
        "hashes": ["SM3", "RIPEMD160"],
        "compression": ["ZIP"],
        "ciphers": ["SM4", "AES128"],
        "key_server": "hkp://pgp.mit.edu",
    }
    key = op.finish()
    assert key.alg() == "ECDSA"
    assert key.curve() == "secp256k1"

    pkts = rnp.parse(rnp.Input.from_bytes(key.secret_key_data()))

    assert next(
        filter(
            lambda pkt: pkt["type.str"] == "preferred hash algorithms",
            pkts[2]["subpackets"],
        )
    )["algorithms.str"] == ["SM3", "RIPEMD160"]
    assert next(
        filter(
            lambda pkt: pkt["type.str"] == "preferred compression algorithms",
            pkts[2]["subpackets"],
        )
    )["algorithms.str"] == ["ZIP"]
    assert next(
        filter(
            lambda pkt: pkt["type.str"] == "preferred symmetric algorithms",
            pkts[2]["subpackets"],
        )
    )["algorithms.str"] == ["SM4", "AES-128"]
    assert (
        next(
            filter(
                lambda pkt: pkt["type.str"] == "preferred key server",
                pkts[2]["subpackets"],
            )
        )["uri"]
        == "hkp://pgp.mit.edu"
    )


def test_op_generate_subkey():
    rpgp = rnp.Rnp()
    op = rnp.Generate.start(rpgp, "RSA")
    op.bits = 1024
    op.userid = "test"
    primary = op.finish()
    assert len(list(primary.subkeys())) == 0

    op = rnp.Generate.start_subkey(rpgp, primary, "RSA")
    op.bits = 1024
    subkey = op.finish()

    assert primary.is_primary()
    assert subkey.is_sub()

    assert subkey.primary_fingerprint() == primary.fingerprint()

    # re-obtain handle to see new subkey
    primary = rpgp.find_key_by_id(primary.keyid())
    assert len(list(primary.subkeys())) == 1
