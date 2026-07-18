import pytest

from rnp.lib import RnpException, _load_lib


def test_load_lib():
    assert _load_lib() is not None


def test_load_lib_bad_path(monkeypatch, tmp_path):
    monkeypatch.setenv("LIBRNP_PATH", str(tmp_path / "no-such-library.dylib"))
    with pytest.raises(RnpException):
        _load_lib()
