import os

import pytest
import rnp


@pytest.fixture
def rpgp():
    lib = rnp.Rnp()
    lib.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/pubring.gpg"), "GPG")
    lib.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/secring.gpg"), "GPG")
    return lib


@pytest.fixture
def key(rpgp):
    key = rpgp.find_key_by_id("7bc6709b15c23a4a")
    key.unlock("password")
    return key


def test_backend():
    assert rnp.backend_string() in ("Botan", "OpenSSL")
    version = rnp.backend_version()
    assert isinstance(version, str)
    assert version[0].isdigit()


def test_buffer_clear():
    data = bytearray(b"sensitive")
    rnp.buffer_clear(data)
    assert bytes(data) == b"\x00" * 9


def test_request_password(rpgp):
    rpgp.set_password_provider(lambda _key, _reason: "secret-value")
    assert rpgp.request_password(context="decrypt") == "secret-value"

    rpgp.set_password_provider(None)
    with pytest.raises(rnp.RnpException):
        rpgp.request_password(context="decrypt")


def test_key_version_and_expiration(rpgp, key):
    assert key.version() == 4
    assert not key.is_expired()
    # key never expires, so the maximum values are reported
    assert key.valid_till() == 0xFFFFFFFF
    assert key.valid_until() == 0xFFFFFFFFFFFFFFFF


def test_generate_request_password():
    rpgp = rnp.Rnp()
    rpgp.set_password_provider(lambda _key, _reason: "gen-password")
    op = rnp.Generate.start(rpgp, "RSA")
    op.bits = 2048
    op.uid = "gen-request@test"
    op.request_password = True
    assert op.request_password
    key = op.finish()
    assert key.is_protected()
    key.lock()
    key.unlock("gen-password")
    assert not key.is_locked()


def test_encrypt_flags_nowrap(rpgp, key):
    rpgp.set_password_provider(lambda _key, _reason: "password")
    # encrypt an already-signed message without wrapping it in another
    # literal data packet
    signed = rpgp.sign(key, rnp.Input.from_bytes(b"data"))
    outp = rnp.Output.to_bytes()
    op = rnp.Encrypt.start(rpgp, rnp.Input.from_bytes(signed), outp)
    op.add_recipient(key)
    op.flags = rnp.RNP_ENCRYPT_NOWRAP
    assert op.flags == rnp.RNP_ENCRYPT_NOWRAP
    op.finish()
    assert rpgp.decrypt(rnp.Input.from_bytes(outp.bytes())) == b"data"


def test_output_file_write_finish(rpgp, tmp_path):
    path = os.path.join(tmp_path, "output.bin")
    outp = rnp.Output.to_file(path)
    assert outp.write(b"hello ") == 6
    assert outp.write(b"world") == 5
    outp.finish()
    del outp
    with open(path, "rb") as f:
        assert f.read() == b"hello world"

    # existing file requires the overwrite flag
    with pytest.raises(rnp.RnpException):
        rnp.Output.to_file(path)
    outp = rnp.Output.to_file(path, overwrite=True)
    outp.write(b"new")
    del outp
    with open(path, "rb") as f:
        assert f.read() == b"new"


def test_output_armor_line_length():
    base = rnp.Output.to_bytes()
    outp = rnp.Output.to_armor(base, "message")
    outp.set_armor_line_length(16)
    outp.write(b"0123456789abcdef" * 4)
    outp.finish()
    del outp
    armored = base.bytes()
    assert armored.startswith(b"-----BEGIN PGP MESSAGE-----")
    payload = [
        line
        for line in armored.decode("ascii").splitlines()
        if line and not line.startswith(("-----", "="))
    ]
    assert max(len(line) for line in payload) == 16

    # invalid line length is rejected
    outp = rnp.Output.to_armor(rnp.Output.to_bytes(), "message")
    with pytest.raises(rnp.RnpException):
        outp.set_armor_line_length(8)


def test_dump_packets(rpgp, key):
    dump = rnp.dump_packets(rnp.Input.from_bytes(key.export_public(armored=False)))
    text = dump.decode("ascii")
    assert "packet header" in text
    assert "tag 6" in text  # public key packet


def test_output_pipe():
    outp = rnp.Output.to_bytes()
    outp.pipe(rnp.Input.from_bytes(b"piped data"))
    assert outp.bytes() == b"piped data"
