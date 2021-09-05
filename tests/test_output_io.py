import io
import rnp


def test_output_io():
    rpgp = rnp.Rnp()
    rpgp.set_password_provider(lambda key, reason: "password")

    plaintext = b"some secret"
    bio = io.BytesIO()
    outp = rnp.Output.to_io(bio)
    assert (
        rpgp.symmetric_encrypt(rnp.Input.from_bytes(plaintext), "password", outp=outp)
        is None
    )
    assert rpgp.decrypt(bytes(bio.getbuffer())) == plaintext
