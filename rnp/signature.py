import json
from ctypes import c_char_p, c_uint32, c_void_p, byref
from .lib import (
    _lib,
    _flags,
    RNP_JSON_DUMP_MPI,
    RNP_JSON_DUMP_RAW,
    RNP_JSON_DUMP_GRIP,
    RnpException,
)
from .key import Key


class Signature:
    def __init__(self, obj):
        self._obj = obj

    def __del__(self):
        _lib.rnp_signature_handle_destroy(self._obj)

    def obj(self):
        return self._obj

    def type(self):
        return self._string_property(_lib.rnp_signature_get_type)

    def alg(self):
        return self._string_property(_lib.rnp_signature_get_alg)

    def hashalg(self):
        return self._string_property(_lib.rnp_signature_get_hash_alg)

    def keyid(self):
        return self._string_property(_lib.rnp_signature_get_keyid)

    def creation_time(self):
        time = c_uint32()
        _lib.rnp_signature_get_creation(self._obj, byref(time))
        return time.value

    def lifetime(self):
        if _lib.features.get("have-rnp-signature-get-expiration"):
            time = c_uint32()
            _lib.rnp_signature_get_expiration(self._obj, byref(time))
            return time.value
        raise RnpException("Not supported in this version of librnp")

    def signer(self):
        signer = c_void_p()
        _lib.rnp_signature_get_signer(self._obj, byref(signer))
        if signer.value:
            return Key(signer.value)

    def status(self):
        return _lib.rnp_signature_is_valid(self._obj, 0)

    def json(self, mpis=False, raw=False, grip=False):
        flags = _flags(
            [
                (mpis, RNP_JSON_DUMP_MPI),
                (raw, RNP_JSON_DUMP_RAW),
                (grip, RNP_JSON_DUMP_GRIP),
            ]
        )
        jsn = c_char_p()
        try:
            _lib.rnp_signature_packet_to_json(self._obj, flags, byref(jsn))
            # pylint: disable=E1101
            return json.loads(jsn.value.decode("utf-8"))
        finally:
            _lib.rnp_buffer_destroy(jsn)

    def _string_property(self, fn):
        prop = c_char_p()
        try:
            fn(self._obj, byref(prop))
            # pylint: disable=E1101
            return prop.value.decode("ascii")
        finally:
            _lib.rnp_buffer_destroy(prop)
