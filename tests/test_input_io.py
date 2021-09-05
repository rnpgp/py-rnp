import io
import rnp


def test_input_io():
    rpgp = rnp.Rnp()
    rpgp.set_password_provider(lambda key, reason: "password")

    sio = io.StringIO("some secret text")
    encrypted = rpgp.symmetric_encrypt(rnp.Input.from_io(sio), "password")

    bio = io.BytesIO(encrypted)
    assert rpgp.decrypt(rnp.Input.from_io(bio)) == b"some secret text"
