#!/usr/bin/env python

from collections.abc import Iterable

from ctypes import (
    pointer,
    c_bool,
    c_char_p,
    c_void_p,
    c_size_t,
    byref,
    c_char,
    addressof,
    py_object,
    cast,
    CFUNCTYPE,
    POINTER,
)
import json
from .lib import (
    _lib,
    _flags,
    _obj,
    _encode,
    _inp,
    PASS_PROVIDER,
    KEY_PROVIDER,
    RNP_LOAD_SAVE_PUBLIC_KEYS,
    RNP_LOAD_SAVE_SECRET_KEYS,
    RNP_LOAD_SAVE_PERMISSIVE,
    RNP_LOAD_SAVE_SINGLE,
)
from .output import Output
from .key import Key
from .op.sign import Sign
from .op.verify import Verify
from .op.encrypt import Encrypt


class Rnp:
    def __init__(self, pub_format="GPG", sec_format="GPG"):
        self._obj = c_void_p()
        _lib.rnp_ffi_create(
            byref(self._obj), pub_format.encode("ascii"), sec_format.encode("ascii")
        )

    def __del__(self):
        _lib.rnp_ffi_destroy(self._obj)

    def obj(self):
        return self._obj

    def load_keys(self, inp, fmt, public_keys=True, secret_keys=True):
        inp = _inp(inp)
        flags = Rnp._load_save_flags(public_keys, secret_keys)
        _lib.rnp_load_keys(self._obj, fmt.encode("ascii"), inp.obj(), flags)

    def unload_keys(self, public_keys=True, secret_keys=True):
        flags = Rnp._load_save_flags(public_keys, secret_keys)
        _lib.rnp_unload_keys(self._obj, flags)

    def save_keys(self, outp, fmt, public_keys=True, secret_keys=True):
        flags = Rnp._load_save_flags(public_keys, secret_keys)
        _lib.rnp_save_keys(self._obj, fmt.encode("ascii"), outp.obj(), flags)

    def import_keys(
        self, inp, public_keys=True, secret_keys=True, permissive=True, single=False
    ):
        inp = _inp(inp)
        try:
            jsn = None
            pjsn = pointer(c_char_p())
            flags = Rnp._import_key_flags(public_keys, secret_keys, permissive, single)
            _lib.rnp_import_keys(self._obj, inp.obj(), flags, pjsn)
            jsn = pjsn.contents
            return json.loads(jsn.value.decode("utf-8"))
        finally:
            _lib.rnp_buffer_destroy(jsn)

    def import_signatures(self, inp):
        inp = _inp(inp)
        try:
            jsn = None
            pjsn = pointer(c_char_p())
            _lib.rnp_import_signatures(self._obj, inp.obj(), 0, pjsn)
            jsn = pjsn.contents
            return json.loads(jsn.value.decode("utf-8"))
        finally:
            _lib.rnp_buffer_destroy(jsn)

    def public_key_count(self):
        count = c_size_t()
        _lib.rnp_get_public_key_count(self._obj, byref(count))
        return count.value

    def secret_key_count(self):
        count = c_size_t()
        _lib.rnp_get_secret_key_count(self._obj, byref(count))
        return count.value

    def _find_key(self, identifier_type, identifier):
        handle = c_void_p()
        _lib.rnp_locate_key(self._obj, identifier_type, identifier, byref(handle))
        if handle.value:
            return Key(handle)

    def find_key_by_id(self, keyid):
        return self._find_key("keyid".encode("ascii"), keyid.encode("ascii"))

    def find_key_by_userid(self, userid):
        return self._find_key("userid".encode("ascii"), userid.encode("utf-8"))

    def find_key_by_fingerprint(self, fpr):
        return self._find_key("fingerprint".encode("ascii"), fpr.encode("ascii"))

    def userids(self):
        return self._identifiers("userid")

    def keyids(self):
        return self._identifiers("keyid")

    def fingerprints(self):
        return self._identifiers("fingerprint")

    def grips(self):
        return self._identifiers("grip")

    def _identifiers(self, typ):
        it = c_void_p()
        try:
            _lib.rnp_identifier_iterator_create(
                self._obj, byref(it), typ.encode("ascii")
            )
            while True:
                identifier = c_char_p()
                _lib.rnp_identifier_iterator_next(it, byref(identifier))
                if identifier.value:
                    # pylint: disable=E1101
                    yield identifier.value.decode("utf-8")
                else:
                    break
        finally:
            _lib.rnp_identifier_iterator_destroy(it)

    def generate_key(self, description):
        try:
            presults = c_char_p()
            jsn = json.dumps(description)
            _lib.rnp_generate_key_json(self._obj, jsn.encode("utf-8"), byref(presults))
            # pylint: disable=E1101
            results = json.loads(presults.value.decode("utf-8"))
            for entry in results:
                results[entry] = self._find_key(
                    next(iter(results[entry].keys())).encode("ascii"),
                    next(iter(results[entry].values())).encode("ascii"),
                )
            return results
        finally:
            _lib.rnp_buffer_destroy(presults)

    def generate_rsa(self, userid, password, bits, subbits=0):
        pkey = c_void_p()
        _lib.rnp_generate_key_rsa(
            self._obj,
            bits,
            subbits,
            userid.encode("utf-8"),
            _encode(password),
            byref(pkey),
        )
        if pkey.value:
            return Key(pkey)

    def generate_dsa_elgamal(self, userid, password, bits, subbits=0):
        pkey = c_void_p()
        _lib.rnp_generate_key_dsa_eg(
            self._obj,
            bits,
            subbits,
            userid.encode("utf-8"),
            _encode(password),
            byref(pkey),
        )
        if pkey.value:
            return Key(pkey)

    def generate_ecdsa_ecdh(self, userid, password, curve):
        pkey = c_void_p()
        _lib.rnp_generate_key_ec(
            self._obj,
            curve.encode("ascii"),
            userid.encode("utf-8"),
            _encode(password),
            byref(pkey),
        )
        if pkey.value:
            return Key(pkey)

    def generate_eddsa_25519(self, userid, password):
        pkey = c_void_p()
        _lib.rnp_generate_key_25519(
            self._obj, userid.encode("utf-8"), _encode(password), byref(pkey)
        )
        if pkey.value:
            return Key(pkey)

    def generate_sm2(self, userid, password):
        pkey = c_void_p()
        _lib.rnp_generate_key_sm2(
            self._obj, userid.encode("utf-8"), _encode(password), byref(pkey)
        )
        if pkey.value:
            return Key(pkey)

    def generate(
        self, userid, password, typ, bits, curve, subtyp=None, subbits=0, subcurve=None
    ):
        pkey = c_void_p()
        _lib.rnp_generate_key_ex(
            self._obj,
            typ.encode("ascii"),
            _encode(subtyp),
            bits,
            subbits,
            _encode(curve),
            _encode(subcurve),
            userid.encode("utf-8"),
            _encode(password),
            byref(pkey),
        )
        if pkey.value:
            return Key(pkey)

    def export_autocrypt(self, userid, primary, subkey=None, outp=None):
        with Output.default(outp) as outp:
            _lib.rnp_key_export_autocrypt(
                primary.obj(), _obj(subkey), _encode(userid), outp.obj(), 0
            )
            return outp.default_output()

    def sign(
        self,
        signers,
        inp,
        armored=None,
        hashalg=None,
        compression=None,
        creation_time=None,
        lifetime=None,
        outp=None,
    ):
        with Output.default(outp) as outp:
            op = Sign.start(self, inp, outp)
            self._do_sign(
                op, signers, armored, hashalg, compression, creation_time, lifetime
            )
            return outp.default_output()

    def sign_cleartext(
        self,
        signers,
        inp,
        hashalg=None,
        compression=None,
        creation_time=None,
        lifetime=None,
        outp=None,
    ):
        with Output.default(outp) as outp:
            op = Sign.start_cleartext(self, inp, outp)
            self._do_sign(
                op, signers, None, hashalg, compression, creation_time, lifetime
            )
            return outp.default_output()

    def sign_detached(
        self,
        signers,
        inp,
        armored=None,
        hashalg=None,
        compression=None,
        creation_time=None,
        lifetime=None,
        outp=None,
    ):
        with Output.default(outp) as outp:
            op = Sign.start_detached(self, inp, outp)
            self._do_sign(
                op, signers, armored, hashalg, compression, creation_time, lifetime
            )
            return outp.default_output()

    def verify(self, inp, outp=None):
        op = Verify.start(self, inp, outp)
        op.finish()
        return op

    def verify_detached(self, inpdata, inpsig):
        op = Verify.start_detached(self, inpdata, inpsig)
        op.finish()
        return op

    def encrypt(
        self,
        inp,
        recipients,
        armored=None,
        compression=None,
        cipher=None,
        aead=None,
        aead_bits=None,
        outp=None,
    ):
        with Output.default(outp) as outp:
            op = Encrypt.start(self, inp, outp)
            self._do_encrypt(
                op,
                recipients,
                armored=armored,
                compression=compression,
                cipher=cipher,
                aead=aead,
                aead_bits=aead_bits,
            )
            return outp.default_output()

    def encrypt_and_sign(
        self,
        inp,
        recipients,
        signers,
        armored=None,
        compression=None,
        cipher=None,
        aead=None,
        aead_bits=None,
        hashalg=None,
        creation_time=None,
        lifetime=None,
        outp=None,
    ):
        with Output.default(outp) as outp:
            op = Encrypt.start(self, inp, outp)
            if hashalg is not None:
                op.hashalg = hashalg
            if creation_time is not None:
                op.creation_time = creation_time
            if lifetime is not None:
                op.lifetime = lifetime

            signers = [] if signers is None else signers
            signers = [signers] if isinstance(signers, Key) else signers
            for signer in signers:
                op.add_signature(signer)

            self._do_encrypt(
                op,
                recipients=recipients,
                armored=armored,
                compression=compression,
                cipher=cipher,
                aead=aead,
                aead_bits=aead_bits,
            )
            return outp.default_output()

    def symmetric_encrypt(
        self,
        inp,
        passwords,
        armored=None,
        compression=None,
        cipher=None,
        aead=None,
        aead_bits=None,
        s2k_hashalg=None,
        s2k_iterations=None,
        s2k_cipher=None,
        outp=None,
    ):
        with Output.default(outp) as outp:
            op = Encrypt.start(self, inp, outp)
            passwords = [] if passwords is None else passwords
            passwords = (
                [passwords]
                if isinstance(passwords, (str, bytes, bytearray))
                else passwords
            )
            for password in passwords:
                op.add_password(password, s2k_hashalg, s2k_iterations, s2k_cipher)

            self._do_encrypt(
                op,
                recipients=None,
                armored=armored,
                compression=compression,
                cipher=cipher,
                aead=aead,
                aead_bits=aead_bits,
            )
            return outp.default_output()

    @staticmethod
    def _do_encrypt(op, recipients, armored, compression, cipher, aead, aead_bits):
        if armored is not None:
            op.armored = armored
        if compression is not None:
            op.compression = compression
        if cipher is not None:
            op.cipher = cipher
        if aead is not None:
            op.aead = aead
        if aead_bits is not None:
            op.aead_bits = aead_bits
        recipients = [] if recipients is None else recipients
        recipients = [recipients] if isinstance(recipients, Key) else recipients
        for recipient in recipients:
            op.add_recipient(recipient)

        op.finish()

    @staticmethod
    def _do_sign(op, signers, armored, hashalg, compression, creation_time, lifetime):
        signers = (signers,) if not isinstance(signers, Iterable) else signers
        for signer in signers:
            op.add_signer(signer)
        if armored is not None:
            op.armored = armored
        if hashalg is not None:
            op.hashalg = hashalg
        if compression is not None:
            op.compression = compression
        if creation_time is not None:
            op.creation_time = creation_time
        if lifetime is not None:
            op.lifetime = lifetime
        op.finish()

    def decrypt(self, inp, outp=None):
        inp = _inp(inp)
        with Output.default(outp) as outp:
            _lib.rnp_decrypt(self._obj, inp.obj(), outp.obj())
            return outp.default_output()

    def set_password_provider(self, provider):
        if provider is None:
            _lib.rnp_ffi_set_pass_provider(self._obj, cast(None, PASS_PROVIDER), None)
        else:
            self.pass_provider = py_object(provider)
            _lib.rnp_ffi_set_pass_provider(
                self._obj, Rnp.PASS_PROVIDER_PROXY, byref(self.pass_provider)
            )

    @staticmethod
    @CFUNCTYPE(
        c_bool, c_void_p, c_void_p, c_void_p, c_char_p, POINTER(c_char), c_size_t
    )
    def PASS_PROVIDER_PROXY(_rnp, app_ctx, pkey, reason, buf, buf_len):
        password = cast(app_ctx, POINTER(py_object)).contents.value
        if callable(password):
            key = Key(c_void_p(pkey), False)
            password = password(key, reason)

        if password is not None:
            if isinstance(password, str):
                password = password.encode("utf-8")

            if len(password) >= buf_len:
                return False

            buf = (c_char * buf_len).from_address(addressof(buf.contents))
            buf[: len(password)] = password[: len(password)]
            return True

        return False

    def set_key_provider(self, provider):
        if provider is None:
            _lib.rnp_ffi_set_key_provider(self._obj, cast(None, KEY_PROVIDER), None)
        else:
            self.key_provider = py_object([provider, self])
            _lib.rnp_ffi_set_key_provider(
                self._obj, Rnp.KEY_PROVIDER_PROXY, byref(self.key_provider)
            )

    @staticmethod
    @CFUNCTYPE(None, c_void_p, c_void_p, c_char_p, c_char_p, c_bool)
    def KEY_PROVIDER_PROXY(_rnp, app_ctx, identifier_type, identifier, is_secret):
        ctx = cast(app_ctx, POINTER(py_object)).contents.value
        identifier_type = identifier_type.decode("ascii")
        identifier = identifier.decode("utf-8")
        return ctx[0](ctx[1], identifier_type, identifier, is_secret)

    @staticmethod
    def _load_save_flags(public_keys, secret_keys):
        return _flags(
            [
                (public_keys, RNP_LOAD_SAVE_PUBLIC_KEYS),
                (secret_keys, RNP_LOAD_SAVE_SECRET_KEYS),
            ]
        )

    @staticmethod
    def _import_key_flags(public_keys, secret_keys, permissive, single):
        return _flags(
            [
                (public_keys, RNP_LOAD_SAVE_PUBLIC_KEYS),
                (secret_keys, RNP_LOAD_SAVE_SECRET_KEYS),
                (permissive, RNP_LOAD_SAVE_PERMISSIVE),
                (single, RNP_LOAD_SAVE_SINGLE),
            ]
        )
