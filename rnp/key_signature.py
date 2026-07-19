from ctypes import c_void_p, byref

from .lib import _lib, _obj, _encode, RNP_REVOKER_SENSITIVE
from .signature import Signature


class KeySignature(Signature):
    """Editable key signature (direct-key, certification or revocation), created
    via one of the create() calls, customized via the setters and finalized with
    sign(). The handle is owned by this object and destroyed with it; after a
    successful sign() the signature is also attached to the target key."""

    @staticmethod
    def direct(signer, target=None):
        psig = c_void_p()
        _lib.rnp_key_direct_signature_create(signer.obj(), _obj(target), byref(psig))
        return KeySignature(psig)

    @staticmethod
    def certification(signer, uid, certification_type=None):
        psig = c_void_p()
        _lib.rnp_key_certification_create(
            signer.obj(), uid.obj(), _encode(certification_type), byref(psig)
        )
        return KeySignature(psig)

    @staticmethod
    def revocation(signer, target=None):
        psig = c_void_p()
        _lib.rnp_key_revocation_signature_create(
            signer.obj(), _obj(target), byref(psig)
        )
        return KeySignature(psig)

    def set_hash(self, hashalg):
        _lib.rnp_key_signature_set_hash(self._obj, hashalg.encode("ascii"))

    def set_creation_time(self, ctime):
        _lib.rnp_key_signature_set_creation(self._obj, ctime)

    def set_key_flags(self, flags):
        _lib.rnp_key_signature_set_key_flags(self._obj, flags)

    def set_key_expiration(self, expiry):
        _lib.rnp_key_signature_set_key_expiration(self._obj, expiry)

    def set_features(self, features):
        _lib.rnp_key_signature_set_features(self._obj, features)

    def add_preferred_cipher(self, alg):
        _lib.rnp_key_signature_add_preferred_alg(self._obj, alg.encode("ascii"))

    def add_preferred_hash(self, hashalg):
        _lib.rnp_key_signature_add_preferred_hash(self._obj, hashalg.encode("ascii"))

    def add_preferred_compression(self, zalg):
        _lib.rnp_key_signature_add_preferred_zalg(self._obj, zalg.encode("ascii"))

    def set_primary_uid(self, primary=True):
        _lib.rnp_key_signature_set_primary_uid(self._obj, primary)

    def set_key_server(self, keyserver):
        _lib.rnp_key_signature_set_key_server(self._obj, _encode(keyserver))

    def set_key_server_prefs(self, prefs):
        _lib.rnp_key_signature_set_key_server_prefs(self._obj, prefs)

    def set_revocation_reason(self, code=None, reason=None):
        _lib.rnp_key_signature_set_revocation_reason(
            self._obj, _encode(code), _encode(reason)
        )

    def set_revoker(self, revoker, sensitive=False):
        flags = RNP_REVOKER_SENSITIVE if sensitive else 0
        _lib.rnp_key_signature_set_revoker(self._obj, revoker.obj(), flags)

    def set_trust_level(self, level, amount):
        _lib.rnp_key_signature_set_trust_level(self._obj, level, amount)

    def sign(self):
        _lib.rnp_key_signature_sign(self._obj)
