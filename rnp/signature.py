import json
from ctypes import (
    c_char_p,
    c_uint8,
    c_uint32,
    c_bool,
    c_void_p,
    c_size_t,
    byref,
    pointer,
    addressof,
)
from .lib import (
    _lib,
    _flags,
    RNP_JSON_DUMP_MPI,
    RNP_JSON_DUMP_RAW,
    RNP_JSON_DUMP_GRIP,
    RNP_KEY_EXPORT_ARMORED,
    RNP_ERROR_NOT_FOUND,
    RnpException,
)
from .key import Key
from .output import Output


class Signature:
    def __init__(self, obj, free=True):
        self._obj = obj
        self._free = free

    def __del__(self):
        if self._free:
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

    def key_fingerprint(self):
        return self._string_property(_lib.rnp_signature_get_key_fprint)

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

    def key_flags(self):
        flags = c_uint32()
        _lib.rnp_signature_get_key_flags(self._obj, byref(flags))
        return flags.value

    def key_expiration(self):
        expiry = c_uint32()
        _lib.rnp_signature_get_key_expiration(self._obj, byref(expiry))
        return expiry.value

    def features(self):
        features = c_uint32()
        _lib.rnp_signature_get_features(self._obj, byref(features))
        return features.value

    def primary_uid(self):
        primary = c_bool()
        _lib.rnp_signature_get_primary_uid(self._obj, byref(primary))
        return primary.value

    def trust_level(self):
        level = c_uint8()
        amount = c_uint8()
        _lib.rnp_signature_get_trust_level(self._obj, byref(level), byref(amount))
        return level.value, amount.value

    def revoker(self):
        return self._string_property(_lib.rnp_signature_get_revoker)

    def revocation_reason(self):
        code = c_char_p()
        reason = c_char_p()
        try:
            _lib.rnp_signature_get_revocation_reason(
                self._obj, byref(code), byref(reason)
            )
            return (
                # pylint: disable=E1101
                code.value.decode("utf-8") if code.value else None,
                reason.value.decode("utf-8") if reason.value else None,
            )
        finally:
            _lib.rnp_buffer_destroy(code)
            _lib.rnp_buffer_destroy(reason)

    def key_server(self):
        return self._string_property(_lib.rnp_signature_get_key_server)

    def key_server_prefs(self):
        prefs = c_uint32()
        _lib.rnp_signature_get_key_server_prefs(self._obj, byref(prefs))
        return prefs.value

    def preferred_ciphers(self):
        return self._preferred(
            _lib.rnp_signature_get_preferred_alg_count,
            _lib.rnp_signature_get_preferred_alg,
        )

    def preferred_hashes(self):
        return self._preferred(
            _lib.rnp_signature_get_preferred_hash_count,
            _lib.rnp_signature_get_preferred_hash,
        )

    def preferred_compression(self):
        return self._preferred(
            _lib.rnp_signature_get_preferred_zalg_count,
            _lib.rnp_signature_get_preferred_zalg,
        )

    def signer(self):
        signer = c_void_p()
        _lib.rnp_signature_get_signer(self._obj, byref(signer))
        if signer.value:
            return Key(signer.value)

    def status(self):
        return _lib.rnp_signature_is_valid(self._obj, 0)

    def error_count(self):
        count = c_size_t()
        _lib.rnp_signature_error_count(self._obj, byref(count))
        return count.value

    def errors(self):
        for idx in range(self.error_count()):
            err = c_uint32()
            _lib.rnp_signature_error_at(self._obj, idx, byref(err))
            yield err.value

    def subpacket_count(self):
        count = c_size_t()
        _lib.rnp_signature_subpacket_count(self._obj, byref(count))
        return count.value

    def subpackets(self):
        for idx in range(self.subpacket_count()):
            subpkt = c_void_p()
            rc = _lib.rnp_signature_subpacket_at(self._obj, idx, byref(subpkt))
            if rc != 0:
                raise RnpException("rnp_signature_subpacket_at failed", rc)
            yield SignatureSubpacket(subpkt)

    def find_subpacket(self, subtype, hashed=False, skip=0):
        subpkt = c_void_p()
        rc = _lib.rnp_signature_subpacket_find(
            self._obj, subtype, hashed, skip, byref(subpkt)
        )
        if rc == RNP_ERROR_NOT_FOUND:
            return None
        if rc != 0:
            raise RnpException("rnp_signature_subpacket_find failed", rc)
        return SignatureSubpacket(subpkt)

    def export(self, outp=None, armored=True):
        with Output.default(outp) as outp:
            flags = _flags([(armored, RNP_KEY_EXPORT_ARMORED)])
            _lib.rnp_signature_export(self._obj, outp.obj(), flags)
            return outp.default_output()

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

    def _preferred(self, count_fn, at_fn):
        count = c_size_t()
        count_fn(self._obj, byref(count))
        for idx in range(count.value):
            yield self._string_property(at_fn, idx)

    def _string_property(self, fn, *args):
        prop = c_char_p()
        try:
            fn(self._obj, *args, byref(prop))
            # pylint: disable=E1101
            return prop.value.decode("ascii") if prop.value else None
        finally:
            _lib.rnp_buffer_destroy(prop)


class SignatureSubpacket:
    """Single signature subpacket, obtained via Signature.subpackets() or
    Signature.find_subpacket(). Owns the underlying librnp handle."""

    def __init__(self, obj):
        self._obj = obj

    def __del__(self):
        _lib.rnp_signature_subpacket_destroy(self._obj)

    def obj(self):
        return self._obj

    def type(self):
        return self._info()[0]

    def hashed(self):
        return self._info()[1]

    def critical(self):
        return self._info()[2]

    def data(self):
        buf = pointer(c_uint8())
        size = c_size_t()
        try:
            _lib.rnp_signature_subpacket_data(self._obj, byref(buf), byref(size))
            return bytes((c_uint8 * size.value).from_address(addressof(buf.contents)))
        finally:
            _lib.rnp_buffer_destroy(buf)

    def _info(self):
        subtype = c_uint8()
        hashed = c_bool()
        critical = c_bool()
        _lib.rnp_signature_subpacket_info(
            self._obj, byref(subtype), byref(hashed), byref(critical)
        )
        return subtype.value, hashed.value, critical.value
