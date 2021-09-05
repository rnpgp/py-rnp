import rnp


def test_debug():
    # ensure callable
    rnp.enable_debug()
    rnp.disable_debug()


def test_default_homedir():
    assert isinstance(rnp.default_homedir(), str)


def test_homedir_info_gpg():
    info = rnp.homedir_info("tests/data/keyrings/gpg")
    assert info["public"]["format"] == "GPG"
    assert info["public"]["path"] == "tests/data/keyrings/gpg/pubring.gpg"
    assert info["secret"]["format"] == "GPG"
    assert info["secret"]["path"] == "tests/data/keyrings/gpg/secring.gpg"


def test_homedir_info_gpg21():
    info = rnp.homedir_info("tests/data/keyrings/gpg21")
    assert info["public"]["format"] == "KBX"
    assert info["public"]["path"] == "tests/data/keyrings/gpg21/pubring.kbx"
    assert info["secret"]["format"] == "G10"
    assert info["secret"]["path"] == "tests/data/keyrings/gpg21/private-keys-v1.d"


def test_key_format():
    assert (
        rnp.key_format(open("tests/data/keyrings/gpg/pubring.gpg", mode="rb").read(20))
        == "GPG"
    )
    assert (
        rnp.key_format(
            open("tests/data/keyrings/gpg21/pubring.kbx", mode="rb").read(20)
        )
        == "KBX"
    )
    assert (
        rnp.key_format(
            open(
                "tests/data/keyrings/gpg21/private-keys-v1.d/63E59092E4B1AE9F8E675B2F98AA2B8BD9F4EA59.key",
                mode="rb",
            ).read(20)
        )
        == "G10"
    )
    assert rnp.key_format(b"ABC") is None


def test_calc_iters():
    hashalg = rnp.features("hash algorithm")[0]
    assert isinstance(rnp.calculate_iterations(hashalg, 1), int)


def test_supports():
    assert isinstance(rnp.supports("hash algorithm", "SHA1"), bool)


def test_features():
    assert isinstance(rnp.features("hash algorithm"), list)


def test_armor_msg_default_output():
    msg = rnp.enarmor(rnp.Input.from_bytes(b"Test message"), None, "message")
    assert msg.startswith(b"-----BEGIN PGP MESSAGE-----")
    assert rnp.dearmor(rnp.Input.from_bytes(msg)) == b"Test message"


def test_dearmor_key(tmp_path):
    path = str(tmp_path / "alice-pub.gpg")
    rnp.dearmor(
        rnp.Input.from_path("tests/data/keys/alice-pub.asc"), rnp.Output.to_path(path)
    )
    rnp.guess_contents(rnp.Input.from_path(path)) == "public key"


def test_armor_public_key():
    outp = rnp.Output.to_bytes()
    rnp.enarmor(rnp.Input.from_path("tests/data/keyrings/gpg/pubring.gpg"), outp)
    result = outp.bytes()
    assert result.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----")
    assert (
        rnp.dearmor(rnp.Input.from_bytes(result))
        == open("tests/data/keyrings/gpg/pubring.gpg", mode="rb").read()
    )


def test_guess_contents():
    assert rnp.guess_contents(rnp.Input.from_bytes(b"BEEF")) == "unknown"
    assert (
        rnp.guess_contents(rnp.Input.from_path("tests/data/keyrings/gpg/pubring.gpg"))
        == "public key"
    )
