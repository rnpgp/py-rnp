import io
import subprocess
import sys

import rnp


def test_input_io():
    rpgp = rnp.Rnp()
    rpgp.set_password_provider(lambda key, reason: "password")

    sio = io.StringIO("some secret text")
    encrypted = rpgp.symmetric_encrypt(rnp.Input.from_io(sio), "password")

    bio = io.BytesIO(encrypted)
    assert rpgp.decrypt(rnp.Input.from_io(bio)) == b"some secret text"


def test_input_from_stdin():
    # hermetic: stdin is fed from a pipe, no TTY involved
    script = (
        "import sys\n"
        "import rnp\n"
        "outp = rnp.Output.to_bytes()\n"
        "outp.pipe(rnp.Input.from_stdin())\n"
        "sys.stdout.buffer.write(outp.bytes())\n"
        "sys.stdout.buffer.flush()\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        input=b"stdin test data",
        capture_output=True,
        check=True,
    )
    assert proc.stdout == b"stdin test data"
    assert proc.stderr == b""
