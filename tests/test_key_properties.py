import rnp
import pytest


@pytest.fixture
def rpgp():
    lib = rnp.Rnp()
    lib.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/pubring.gpg"), "GPG")
    lib.load_keys(rnp.Input.from_path("tests/data/keyrings/gpg/secring.gpg"), "GPG")
    return lib


@pytest.fixture
def key0(rpgp):
    return rpgp.find_key_by_id("7bc6709b15c23a4a")


def test_key0_alg(key0):
    assert key0.alg() == "RSA"


def test_key0_valid(key0):
    assert key0.is_valid()


def test_key0_identifiers(key0):
    assert key0.keyid() == "7bc6709b15c23a4a".upper()
    assert key0.fingerprint() == "e95a3cbf583aa80a2ccc53aa7bc6709b15c23a4a".upper()
    assert key0.grip() == "66D6A0800A3FACDE0C0EB60B16B3669ED380FDFA"
    assert set(key0.userids()) == set(["key0-uid0", "key0-uid1", "key0-uid2"])
    assert key0.primary_userid() == "key0-uid0"


def test_key0_times(key0):
    assert key0.creation_time() == 1500569820
    assert key0.lifetime() == 0


def test_key0_revoked(key0):
    assert not key0.is_revoked()


def test_key0_usage(key0):
    assert key0.can_sign()
    assert key0.can_certify()
    assert not key0.can_encrypt()
    assert not key0.can_authenticate()


def test_key0_sigs(key0):
    assert list(key0.signatures()) == []


def test_key0_bits(key0):
    assert key0.bits() == 1024


def test_key0_primary_sub(key0):
    assert key0.is_primary()
    assert not key0.is_sub()


def test_key0_pub_sec(key0):
    assert key0.has_public_key()
    assert key0.has_secret_key()


def test_key0_protection(key0):
    assert key0.is_locked()
    assert key0.is_protected()


def test_key0_keydata(key0):
    assert isinstance(key0.public_key_data(), bytes)
    assert isinstance(key0.secret_key_data(), bytes)


def test_key0_json(key0):
    jsn = key0.json()
    assert jsn["fingerprint"] == "E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A"


@pytest.fixture
def key0s2(rpgp):
    return rpgp.find_key_by_id("1d7e8a5393c997a8")


def test_key0s2_valid(key0s2):
    assert not key0s2.is_valid()


def test_key0s2_valid_until(key0s2):
    assert key0s2.valid_until() == key0s2.creation_time() + (60 * 60 * 24 * 123)


def test_key0s2_protection(key0s2):
    assert key0s2.protection_cipher() == "CAST5"
    assert key0s2.protection_hashalg() == "SHA1"
    assert key0s2.protection_mode() == "CFB"
    assert key0s2.protection_type() == "Encrypted-Hashed"
    assert key0s2.protection_iterations() == 9961472


def test_key0s2_alg(key0s2):
    assert key0s2.alg() == "DSA"


def test_key0s2_lifetime(key0s2):
    assert key0s2.lifetime() == 10627200


def test_key0s2_primary_sub(key0s2):
    assert not key0s2.is_primary()
    assert key0s2.is_sub()


def test_key0s2_primary_ids(key0, key0s2):
    assert key0s2.primary_grip() == key0.grip()
    assert key0s2.primary_fingerprint() == key0.fingerprint()


def test_key0s2_qbits(key0s2):
    assert key0s2.qbits() == 160


@pytest.fixture
def ecclib():
    lib = rnp.Rnp()
    lib.load_keys(rnp.Input.from_path("tests/data/keys/ecc-p384-pub.asc"), "GPG")
    return lib


@pytest.fixture
def ecckey(ecclib):
    return ecclib.find_key_by_id("242A3AA5EA85F44A")


def test_ecc_curve(ecckey):
    assert ecckey.curve() == "NIST P-384"
