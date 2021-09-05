import pytest
import rnp


@pytest.fixture
def rpgp():
    lib = rnp.Rnp()
    lib.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/pubring.gpg"), "GPG")
    return lib


@pytest.fixture
def key(rpgp):
    return rpgp.find_key_by_id("54505a936a4a970e")


def test_key_signatures(key):
    assert len(list(key.signatures())) == 1
    sig = next(key.signatures())
    assert sig.type() == "subkey binding"
    assert sig.alg() == "DSA"
    assert sig.hashalg() == "SHA1"
    assert sig.keyid() == "2FCADF05FFA501BB"
    assert sig.creation_time() == 1500569946
    assert sig.signer().keyid() == "2FCADF05FFA501BB"
    assert sig.status() == 0


def test_key_signatures_json(key):
    # mpi, raw, grip
    sig = next(key.signatures())

    assert len(sig.json()) == 1
    assert sig.json()[0]["type.str"] == "Subkey Binding Signature"

    # mpi
    assert "r.raw" not in sig.json()[0]["material"].keys()
    assert "r.raw" in sig.json(True)[0]["material"].keys()

    # raw
    assert "raw" not in sig.json()[0].keys()
    assert "raw" in sig.json(False, True)[0].keys()
