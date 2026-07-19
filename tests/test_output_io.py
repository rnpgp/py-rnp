import io
import subprocess
import sys

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


def test_output_to_stdout():
    # hermetic: stdout is captured from a pipe, no TTY involved
    script = (
        "import rnp\n"
        "outp = rnp.Output.to_stdout()\n"
        "outp.write(b'stdout test data')\n"
        "outp.finish()\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, check=True
    )
    assert proc.stdout == b"stdout test data"
    assert proc.stderr == b""
