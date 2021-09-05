from ctypes import c_void_p, byref

from ..lib import _lib, _inp


class Sign:
    def __init__(self, obj, io):
        self._obj = obj
        self._armored = None
        self._compression = None
        self._hashalg = None
        self._creation_time = None
        self._lifetime = None
        self._io = io

    def __del__(self):
        _lib.rnp_op_sign_destroy(self._obj)

    def obj(self):
        return self._obj

    @staticmethod
    def start(rnp, inp, outp):
        inp = _inp(inp)
        pop = c_void_p()
        _lib.rnp_op_sign_create(byref(pop), rnp.obj(), inp.obj(), outp.obj())
        if pop.value:
            return Sign(pop, (inp, outp))

    @staticmethod
    def start_cleartext(rnp, inp, outp):
        inp = _inp(inp)
        pop = c_void_p()
        _lib.rnp_op_sign_cleartext_create(byref(pop), rnp.obj(), inp.obj(), outp.obj())
        if pop.value:
            return Sign(pop, (inp, outp))

    @staticmethod
    def start_detached(rnp, inp, outp):
        inp = _inp(inp)
        pop = c_void_p()
        _lib.rnp_op_sign_detached_create(byref(pop), rnp.obj(), inp.obj(), outp.obj())
        if pop.value:
            return Sign(pop, (inp, outp))

    def add_signer(self, signer, hashalg=None, creation_time=None, lifetime=None):
        psig = c_void_p()
        _lib.rnp_op_sign_add_signature(self.obj(), signer.obj(), byref(psig))
        Sign._set_signature_opts(psig, hashalg, creation_time, lifetime)

    @property
    def armored(self):
        return self._armored

    @armored.setter
    def armored(self, armored):
        _lib.rnp_op_sign_set_armor(self._obj, armored)
        self._armored = armored

    @property
    def compression(self):
        return self._compression

    @compression.setter
    def compression(self, compression):
        if compression is None:
            compression = ("Uncompressed", 0)
        _lib.rnp_op_sign_set_compression(
            self._obj, compression[0].encode("ascii"), compression[1]
        )
        self._compression = compression

    @property
    def hashalg(self):
        return self._hashalg

    @hashalg.setter
    def hashalg(self, hashalg):
        _lib.rnp_op_sign_set_hash(self._obj, hashalg.encode("ascii"))
        self._hashalg = hashalg

    @property
    def creation_time(self):
        return self._creation_time

    @creation_time.setter
    def creation_time(self, creation_time):
        _lib.rnp_op_sign_set_creation_time(self._obj, creation_time)
        self._creation_time = creation_time

    @property
    def lifetime(self):
        return self._lifetime

    @lifetime.setter
    def lifetime(self, lifetime):
        _lib.rnp_op_sign_set_expiration_time(self._obj, lifetime)
        self._lifetime = lifetime

    def finish(self):
        _lib.rnp_op_sign_execute(self.obj())

    @staticmethod
    def _set_signature_opts(psig, hashalg, creation_time, lifetime):
        if hashalg:
            _lib.rnp_op_sign_signature_set_hash(psig, hashalg.encode("ascii"))
        if creation_time:
            _lib.rnp_op_sign_signature_set_creation_time(psig, creation_time)
        if lifetime:
            _lib.rnp_op_sign_signature_set_expiration_time(psig, lifetime)
