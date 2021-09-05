from ctypes import (
    c_size_t,
    c_uint8,
    c_uint32,
    c_bool,
    c_void_p,
    POINTER,
    cast,
    byref,
    addressof,
)

from .lib import _lib


class UID:
    RNP_USER_ID = 1
    RNP_USER_ATTR = 2

    def __init__(self, obj):
        self._obj = obj

    def __del__(self):
        _lib.rnp_uid_handle_destroy(self._obj)

    def obj(self):
        return self._obj

    def type(self):
        uidtype = c_uint32()
        _lib.rnp_uid_get_type(self._obj, byref(uidtype))
        return uidtype.value

    def data(self):
        buf = c_void_p()
        buf_size = c_size_t()
        try:
            _lib.rnp_uid_get_data(self._obj, byref(buf), byref(buf_size))
            buf = cast(buf, POINTER(c_uint8))
            return bytes(
                (c_uint8 * buf_size.value).from_address(addressof(buf.contents))
            )
        finally:
            _lib.rnp_buffer_destroy(buf)

    def is_primary(self):
        primary = c_bool()
        _lib.rnp_uid_is_primary(self._obj, byref(primary))
        return primary.value

    def is_valid(self):
        valid = c_bool()
        _lib.rnp_uid_is_valid(self._obj, byref(valid))
        return valid.value

    def is_revoked(self):
        revoked = c_bool()
        _lib.rnp_uid_is_revoked(self._obj, byref(revoked))
        return revoked.value

    def revocation_signature(self):
        from .signature import Signature

        psig = c_void_p()
        _lib.rnp_uid_get_revocation_signature(self._obj, byref(psig))
        if psig.value:
            return Signature(psig.value)

    def signatures(self):
        from .signature import Signature

        count = c_size_t()
        _lib.rnp_uid_get_signature_count(self._obj, byref(count))
        for i in range(count.value):
            psig = c_void_p()
            _lib.rnp_uid_get_signature_at(self._obj, i, byref(psig))
            yield Signature(psig.value)
