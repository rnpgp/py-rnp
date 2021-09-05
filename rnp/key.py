import json

from ctypes import (
    c_char_p,
    c_size_t,
    c_uint8,
    c_uint32,
    c_uint64,
    c_bool,
    c_void_p,
    byref,
    pointer,
    addressof,
)

from .lib import (
    _lib,
    _encode,
    _flags,
    RNP_KEY_EXPORT_ARMORED,
    RNP_KEY_EXPORT_PUBLIC,
    RNP_KEY_EXPORT_SECRET,
    RNP_KEY_EXPORT_SUBKEYS,
    RNP_JSON_PUBLIC_MPIS,
    RNP_JSON_SECRET_MPIS,
    RNP_JSON_SIGNATURES,
    RNP_JSON_SIGNATURE_MPIS,
    RNP_KEY_REMOVE_PUBLIC,
    RNP_KEY_REMOVE_SECRET,
    RNP_KEY_REMOVE_SUBKEYS,
    RNP_JSON_DUMP_MPI,
    RNP_JSON_DUMP_RAW,
    RNP_JSON_DUMP_GRIP,
    RNP_KEY_SUBKEYS_ONLY,
    RNP_ERROR_KEY_NOT_FOUND,
    RNP_ERROR_NO_SUITABLE_KEY,
    RnpException,
)
from .output import Output


class Key:
    def __init__(self, obj, free=True):
        self._obj = obj
        self._free = free

    def __del__(self):
        if self._free:
            _lib.rnp_key_handle_destroy(self._obj)

    def obj(self):
        return self._obj

    def alg(self):
        return self._string_property(_lib.rnp_key_get_alg)

    def fingerprint(self):
        return self._string_property(_lib.rnp_key_get_fprint)

    def keyid(self):
        return self._string_property(_lib.rnp_key_get_keyid)

    def grip(self):
        return self._string_property(_lib.rnp_key_get_grip)

    def primary_grip(self):
        return self._string_property(_lib.rnp_key_get_primary_grip)

    def primary_fingerprint(self):
        return self._string_property(_lib.rnp_key_get_primary_fprint)

    def primary_userid(self):
        return self._string_property(_lib.rnp_key_get_primary_uid)

    def userids(self):
        from .uid import UID

        return map(
            lambda uid: uid.data().decode("utf-8"),
            filter(lambda uid: uid.type() == UID.RNP_USER_ID, self.uids()),
        )

    def uids(self):
        from .uid import UID

        count = c_size_t()
        _lib.rnp_key_get_uid_count(self._obj, byref(count))
        for i in range(count.value):
            userid = c_void_p()
            _lib.rnp_key_get_uid_handle_at(self._obj, i, byref(userid))
            yield UID(userid.value)

    def add_userid(
        self, userid, hashalg=None, expiration_time=0, key_flags=0, primary=False
    ):
        _lib.rnp_key_add_uid(
            self._obj,
            userid.encode("utf-8"),
            _encode(hashalg),
            expiration_time,
            key_flags,
            primary,
        )

    def signatures(self):
        from .signature import Signature

        count = c_size_t()
        _lib.rnp_key_get_signature_count(self._obj, byref(count))
        for i in range(count.value):
            psig = c_void_p()
            _lib.rnp_key_get_signature_at(self._obj, i, byref(psig))
            yield Signature(psig.value)

    def bits(self):
        bits = c_uint32()
        _lib.rnp_key_get_bits(self._obj, byref(bits))
        return bits.value

    def qbits(self):
        qbits = c_uint32()
        _lib.rnp_key_get_dsa_qbits(self._obj, byref(qbits))
        return qbits.value

    def curve(self):
        return self._string_property(_lib.rnp_key_get_curve)

    def is_locked(self):
        pbool = c_bool()
        _lib.rnp_key_is_locked(self.obj(), byref(pbool))
        return pbool.value

    def lock(self):
        _lib.rnp_key_lock(self.obj())

    def unlock(self, password=None):
        _lib.rnp_key_unlock(self._obj, _encode(password))

    def is_protected(self):
        pbool = c_bool()
        _lib.rnp_key_is_protected(self.obj(), byref(pbool))
        return pbool.value

    def protect(
        self,
        password,
        cipher=None,
        cipher_mode=None,
        s2k_hashalg=None,
        s2k_iterations=0,
    ):
        _lib.rnp_key_protect(
            self._obj,
            _encode(password),
            _encode(cipher),
            _encode(cipher_mode),
            _encode(s2k_hashalg),
            s2k_iterations,
        )

    def unprotect(self, password=None):
        _lib.rnp_key_unprotect(self._obj, _encode(password))

    def is_primary(self):
        return self._bool_property(_lib.rnp_key_is_primary)

    def is_sub(self):
        return self._bool_property(_lib.rnp_key_is_sub)

    def has_public_key(self):
        return self._bool_property(_lib.rnp_key_have_public)

    def has_secret_key(self):
        return self._bool_property(_lib.rnp_key_have_secret)

    def is_valid(self):
        return self._bool_property(_lib.rnp_key_is_valid)

    def protection_cipher(self):
        return self._string_property(_lib.rnp_key_get_protection_cipher)

    def protection_hashalg(self):
        return self._string_property(_lib.rnp_key_get_protection_hash)

    def protection_mode(self):
        return self._string_property(_lib.rnp_key_get_protection_mode)

    def protection_type(self):
        return self._string_property(_lib.rnp_key_get_protection_type)

    def protection_iterations(self):
        return self._size_t_property(_lib.rnp_key_get_protection_iterations)

    def export_public(self, armored=True, include_subkeys=False, outp=None):
        with Output.default(outp) as outp:
            self._export(armored, True, False, include_subkeys, outp)
            return outp.default_output()

    def export_secret(self, armored=True, include_subkeys=False, outp=None):
        with Output.default(outp) as outp:
            self._export(armored, False, True, include_subkeys, outp)
            return outp.default_output()

    def export_revocation(self, hashalg=None, code=None, reason=None, outp=None):
        with Output.default(outp) as outp:
            _lib.rnp_key_export_revocation(
                self.obj(),
                outp.obj(),
                0,
                _encode(hashalg),
                _encode(code),
                _encode(reason),
            )
            return outp.default_output()

    def public_key_data(self):
        return self._buf_property(_lib.rnp_get_public_key_data)

    def secret_key_data(self):
        return self._buf_property(_lib.rnp_get_secret_key_data)

    def to(self, usage, subkeys_only=False):
        pkey = c_void_p()
        flags = _flags([(subkeys_only, RNP_KEY_SUBKEYS_ONLY)])
        rc = _lib.rnp_key_get_default_key(
            self._obj, usage.encode("ascii"), flags, byref(pkey)
        )
        if rc not in [0, RNP_ERROR_KEY_NOT_FOUND, RNP_ERROR_NO_SUITABLE_KEY]:
            raise RnpException("rnp_key_get_default_key failed", rc)
        if pkey.value:
            return Key(pkey.value)
        return None

    def json(
        self,
        public_mpis=False,
        secret_mpis=False,
        signatures=True,
        signature_mpis=False,
    ):
        flags = _flags(
            [
                (public_mpis, RNP_JSON_PUBLIC_MPIS),
                (secret_mpis, RNP_JSON_SECRET_MPIS),
                (signatures, RNP_JSON_SIGNATURES),
                (signature_mpis, RNP_JSON_SIGNATURE_MPIS),
            ]
        )
        jsn = c_char_p()
        try:
            _lib.rnp_key_to_json(self._obj, flags, byref(jsn))
            # pylint: disable=E1101
            return json.loads(jsn.value.decode("utf-8"))
        finally:
            _lib.rnp_buffer_destroy(jsn)

    def packets_json(self, secret=False, mpi=False, raw=False, grip=False):
        flags = _flags(
            [
                (mpi, RNP_JSON_DUMP_MPI),
                (raw, RNP_JSON_DUMP_RAW),
                (grip, RNP_JSON_DUMP_GRIP),
            ]
        )
        jsn = c_char_p()
        try:
            _lib.rnp_key_packets_to_json(self._obj, secret, flags, byref(jsn))
            # pylint: disable=E1101
            return json.loads(jsn.value.decode("utf-8"))
        finally:
            _lib.rnp_buffer_destroy(jsn)

    def remove(self, remove_public=True, remove_secret=True, remove_subkeys=False):
        flags = _flags(
            [
                (remove_public, RNP_KEY_REMOVE_PUBLIC),
                (remove_secret, RNP_KEY_REMOVE_SECRET),
                (remove_subkeys, RNP_KEY_REMOVE_SUBKEYS),
            ]
        )
        _lib.rnp_key_remove(self._obj, flags)

    def revoke(self, hashalg=None, code=None, reason=None):
        _lib.rnp_key_revoke(
            self._obj, 0, _encode(hashalg), _encode(code), _encode(reason)
        )

    def revocation_signature(self):
        from .signature import Signature

        psig = c_void_p()
        _lib.rnp_key_get_revocation_signature(self._obj, byref(psig))
        if psig.value:
            return Signature(psig.value)

        return None

    def subkeys(self):
        count = c_size_t()
        _lib.rnp_key_get_subkey_count(self._obj, byref(count))
        for i in range(count.value):
            pkey = c_void_p()
            _lib.rnp_key_get_subkey_at(self._obj, i, byref(pkey))
            yield Key(pkey.value)

    def can_sign(self):
        result = c_bool()
        _lib.rnp_key_allows_usage(self._obj, "sign".encode("ascii"), byref(result))
        return result.value

    def can_certify(self):
        result = c_bool()
        _lib.rnp_key_allows_usage(self._obj, "certify".encode("ascii"), byref(result))
        return result.value

    def can_encrypt(self):
        result = c_bool()
        _lib.rnp_key_allows_usage(self._obj, "encrypt".encode("ascii"), byref(result))
        return result.value

    def can_authenticate(self):
        result = c_bool()
        _lib.rnp_key_allows_usage(
            self._obj, "authenticate".encode("ascii"), byref(result)
        )
        return result.value

    def is_revoked(self):
        return self._bool_property(_lib.rnp_key_is_revoked)

    def is_compromised(self):
        return self._bool_property(_lib.rnp_key_is_compromised)

    def is_retired(self):
        return self._bool_property(_lib.rnp_key_is_retired)

    def is_superseded(self):
        return self._bool_property(_lib.rnp_key_is_superseded)

    def revocation_reason(self):
        return self._string_property(_lib.rnp_key_get_revocation_reason)

    def creation_time(self):
        time = c_uint32()
        _lib.rnp_key_get_creation(self._obj, byref(time))
        return time.value

    def lifetime(self):
        secs = c_uint32()
        _lib.rnp_key_get_expiration(self._obj, byref(secs))
        return secs.value

    def set_lifetime(self, secs):
        _lib.rnp_key_set_expiration(self._obj, secs)

    def valid_until(self):
        result = c_uint64()
        _lib.rnp_key_valid_till64(self._obj, byref(result))
        return result.value

    def _export(self, armored, public_key, secret_key, include_subkeys, outp):
        flags = _flags(
            [
                (armored, RNP_KEY_EXPORT_ARMORED),
                (public_key, RNP_KEY_EXPORT_PUBLIC),
                (secret_key, RNP_KEY_EXPORT_SECRET),
                (include_subkeys, RNP_KEY_EXPORT_SUBKEYS),
            ]
        )
        _lib.rnp_key_export(self._obj, outp.obj(), flags)

    def _buf_property(self, fn):
        buf = pointer(c_uint8())
        buf_len = c_size_t()
        try:
            fn(self._obj, byref(buf), byref(buf_len))
            return bytes(
                (c_uint8 * buf_len.value).from_address(addressof(buf.contents))
            )
        finally:
            _lib.rnp_buffer_destroy(buf)

    def _string_property(self, fn):
        prop = c_char_p()
        try:
            fn(self._obj, byref(prop))
            # pylint: disable=E1101
            return prop.value.decode("utf-8")
        finally:
            _lib.rnp_buffer_destroy(prop)

    def _bool_property(self, fn):
        prop = c_bool()
        fn(self._obj, byref(prop))
        return prop.value

    def _size_t_property(self, fn):
        prop = c_size_t()
        fn(self._obj, byref(prop))
        return prop.value
