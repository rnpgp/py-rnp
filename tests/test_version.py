import rnp


def test_version_string():
    assert isinstance(rnp.version_string(), str)
    assert isinstance(rnp.version_string_full(), str)


def test_version():
    assert isinstance(rnp.version(), int)
    assert rnp.version("1.23.4") == ((1 << 20) | (23 << 10) | (4 << 0))
    assert rnp.version_for(1, 23, 4) == ((1 << 20) | (23 << 10) | (4 << 0))


def test_version_components():
    assert isinstance(rnp.version_major(), int)
    assert isinstance(rnp.version_minor(), int)
    assert isinstance(rnp.version_patch(), int)


def test_version_commit_time():
    assert isinstance(rnp.commit_time(), int)
