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
    return rpgp.find_key_by_id("326ef111425d14a5")


def test_export_defaults(rpgp, key):
    assert key.has_public_key()
    assert key.has_secret_key()

    secexported = key.export_secret()

    pubexported = key.export_public()
    pubdata = key.public_key_data()
    assert pubexported.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n")
    assert pubexported.endswith(b"-----END PGP PUBLIC KEY BLOCK-----\r\n")
    key.remove()
    key = None
    assert rpgp.find_key_by_id("326ef111425d14a5") is None

    rpgp.load_keys(rnp.Input.from_bytes(pubexported), "GPG")
    key = rpgp.find_key_by_id("326ef111425d14a5")
    assert key
    assert key.public_key_data() == pubdata
    assert key.has_public_key()
    assert not key.has_secret_key()

    rpgp.import_keys(rnp.Input.from_bytes(secexported), "GPG")
    # must obtain new key handle after importing sec
    key = rpgp.find_key_by_id("326ef111425d14a5")
    assert key.has_secret_key()


def test_export_autocrypt(rpgp):
    primary = rpgp.find_key_by_id("2fcadf05ffa501bb")
    subkey = rpgp.find_key_by_id("54505a936a4a970e")
    exported = rpgp.export_autocrypt("key1-uid2", primary, subkey)
    pkts = rnp.parse(rnp.Input.from_bytes(exported))
    # primary key, userid, userid cert, subkey, subkey binding
    assert len(pkts) == 5
    assert pkts[0]["keyid"] == "2fcadf05ffa501bb"
    assert pkts[1]["userid"] == "key1-uid2"
    assert pkts[3]["keyid"] == "54505a936a4a970e"


def test_export_autocrypt_default_sub(rpgp):
    primary = rpgp.find_key_by_id("2fcadf05ffa501bb")
    exported = rpgp.export_autocrypt("key1-uid2", primary)
    pkts = rnp.parse(rnp.Input.from_bytes(exported))
    # primary key, userid, userid cert, subkey, subkey binding
    assert len(pkts) == 5
    assert pkts[0]["keyid"] == "2fcadf05ffa501bb"
    assert pkts[1]["userid"] == "key1-uid2"
    assert pkts[3]["keyid"] == "326ef111425d14a5"


def test_export_revocation(rpgp):
    key = rpgp.find_key_by_id("2fcadf05ffa501bb")
    key.unlock("password")
    revocation = key.export_revocation()
    pkts = rnp.parse(rnp.Input.from_bytes(revocation))
    assert len(pkts) == 1
    assert pkts[0]["type.str"] == "Key revocation signature"
