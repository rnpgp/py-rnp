from ctypes import c_char_p, byref

from .lib import _lib


class Recipient:
    """Single message recipient, obtained from a Verify operation via
    Verify.recipients() or Verify.used_recipient(). The underlying handle is
    owned by the operation and is not destroyed separately."""

    def __init__(self, obj):
        self._obj = obj

    def obj(self):
        return self._obj

    def keyid(self):
        return self._string_property(_lib.rnp_recipient_get_keyid)

    def alg(self):
        return self._string_property(_lib.rnp_recipient_get_alg)

    def _string_property(self, fn):
        prop = c_char_p()
        try:
            fn(self._obj, byref(prop))
            # pylint: disable=E1101
            return prop.value.decode("ascii") if prop.value else None
        finally:
            _lib.rnp_buffer_destroy(prop)
