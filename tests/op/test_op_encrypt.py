import time
import rnp


def test_op_encrypt():
    rpgp = rnp.Rnp()
    rpgp.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/pubring.gpg"), "GPG")
    rpgp.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/secring.gpg"), "GPG")
    inp = rnp.Input.from_bytes(b"secret data")
    outp = rnp.Output.to_bytes()
    op = rnp.Encrypt.start(rpgp, inp, outp)
    tm = int(time.time())
    op.armored = True
    op.aead = "EAX"
    op.aead_bits = 8
    op.cipher = "SM4"
    op.compression = ("ZIP", 9)
    op.hashalg = "SHA512"
    op.creation_time = tm
    op.lifetime = 0
    op.file_mtime = tm
    op.filename = "secret.txt"

    key = rpgp.find_key_by_userid("key0-uid0")
    op.add_recipient(key)
    op.add_password("pass", "SM3", 12800, "SM4")
    op.add_signature(key, "SM3", tm, 4321)

    key.unlock("password")
    op.finish()

    encrypted = outp.bytes()
    pkts = list(rnp.parse(rnp.Input.from_bytes(encrypted)))

    assert len(pkts) == 3
    assert [pkt["header"]["tag.str"] for pkt in pkts] == [
        "Public-Key Encrypted Session Key",
        "Symmetric-Key Encrypted Session Key",
        "AEAD Encrypted Data Packet",
    ]

    assert pkts[1]["aead algorithm.str"] == "EAX"
    assert pkts[1]["algorithm.str"] == "SM4"
    assert pkts[1]["s2k"]["hash algorithm.str"] == "SM3"
    assert pkts[1]["s2k"]["iterations"] == 12800

    assert pkts[2]["aead algorithm.str"] == "EAX"
    assert pkts[2]["chunk size"] == 8
    assert pkts[2]["algorithm.str"] == "SM4"
