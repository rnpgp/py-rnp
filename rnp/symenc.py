from ctypes import c_char_p, c_uint32, byref

from .lib import _lib


class Symenc:
    """Single password-based encryption entry, obtained from a Verify operation
    via Verify.symencs() or Verify.used_symenc(). The underlying handle is owned
    by the operation and is not destroyed separately."""

    def __init__(self, obj):
        self._obj = obj

    def obj(self):
        return self._obj

    def cipher(self):
        return self._string_property(_lib.rnp_symenc_get_cipher)

    def aead_alg(self):
        return self._string_property(_lib.rnp_symenc_get_aead_alg)

    def hash_alg(self):
        return self._string_property(_lib.rnp_symenc_get_hash_alg)

    def s2k_type(self):
        return self._string_property(_lib.rnp_symenc_get_s2k_type)

    def s2k_iterations(self):
        iterations = c_uint32()
        _lib.rnp_symenc_get_s2k_iterations(self._obj, byref(iterations))
        return iterations.value

    def _string_property(self, fn):
        prop = c_char_p()
        try:
            fn(self._obj, byref(prop))
            # pylint: disable=E1101
            return prop.value.decode("ascii") if prop.value else None
        finally:
            _lib.rnp_buffer_destroy(prop)
