from ctypes import c_void_p, byref

from ..lib import _lib, _encode, _inp
from ..key import Key


class Encrypt:
    def __init__(self, obj, io):
        self._obj = obj
        self._armored = None
        self._compression = None
        self._cipher = None
        self._aead = None
        self._aead_bits = None
        self._hashalg = None
        self._creation_time = None
        self._lifetime = None
        self._file_mtime = None
        self._filename = None
        self._io = io

    def __del__(self):
        _lib.rnp_op_encrypt_destroy(self._obj)

    def obj(self):
        return self._obj

    @staticmethod
    def start(rnp, inp, outp):
        inp = _inp(inp)
        pop = c_void_p()
        _lib.rnp_op_encrypt_create(byref(pop), rnp.obj(), inp.obj(), outp.obj())
        if pop.value:
            return Encrypt(pop, (inp, outp))

    @property
    def armored(self):
        return self._armored

    @armored.setter
    def armored(self, armored):
        _lib.rnp_op_encrypt_set_armor(self._obj, armored)
        self._armored = armored

    @property
    def cipher(self):
        return self._cipher

    @cipher.setter
    def cipher(self, cipher):
        _lib.rnp_op_encrypt_set_cipher(self._obj, cipher.encode("ascii"))
        self._cipher = cipher

    @property
    def aead(self):
        return self._aead

    @aead.setter
    def aead(self, aead):
        _lib.rnp_op_encrypt_set_aead(self._obj, aead.encode("ascii"))
        self._aead = aead

    @property
    def aead_bits(self):
        return self._aead_bits

    @aead_bits.setter
    def aead_bits(self, aead_bits):
        _lib.rnp_op_encrypt_set_aead_bits(self._obj, aead_bits)
        self._aead_bits = aead_bits

    @property
    def compression(self):
        return self._compression

    @compression.setter
    def compression(self, compression):
        if compression is None:
            compression = ("Uncompressed", 0)
        _lib.rnp_op_encrypt_set_compression(
            self._obj, compression[0].encode("ascii"), compression[1]
        )
        self._compression = compression

    @property
    def hashalg(self):
        return self._hashalg

    @hashalg.setter
    def hashalg(self, hashalg):
        _lib.rnp_op_encrypt_set_hash(self._obj, hashalg.encode("ascii"))
        self._hashalg = hashalg

    @property
    def creation_time(self):
        return self._creation_time

    @creation_time.setter
    def creation_time(self, creation_time):
        _lib.rnp_op_encrypt_set_creation_time(self._obj, creation_time)
        self._creation_time = creation_time

    @property
    def lifetime(self):
        return self._lifetime

    @lifetime.setter
    def lifetime(self, lifetime):
        _lib.rnp_op_encrypt_set_expiration_time(self._obj, lifetime)
        self._lifetime = lifetime

    @property
    def file_mtime(self):
        return self._file_mtime

    @file_mtime.setter
    def file_mtime(self, mtime):
        self._file_mtime = mtime
        _lib.rnp_op_encrypt_set_file_mtime(self._obj, mtime)

    @property
    def filename(self):
        return self._filename

    @filename.setter
    def filename(self, name):
        self._filename = name
        _lib.rnp_op_encrypt_set_file_name(self._obj, _encode(name))

    def add_recipient(self, recipient):
        assert isinstance(recipient, Key)
        _lib.rnp_op_encrypt_add_recipient(self._obj, recipient.obj())

    def add_password(
        self, password, s2k_hashalg=None, iterations=None, s2k_cipher=None
    ):
        _lib.rnp_op_encrypt_add_password(
            self._obj,
            password.encode("utf-8"),
            _encode(s2k_hashalg),
            iterations or 0,
            _encode(s2k_cipher),
        )

    def add_signature(self, signer, hashalg=None, creation_time=None, lifetime=None):
        from .sign import Sign

        assert isinstance(signer, Key)
        psig = c_void_p()
        _lib.rnp_op_encrypt_add_signature(self._obj, signer.obj(), byref(psig))
        Sign._set_signature_opts(psig, hashalg, creation_time, lifetime)

    def finish(self):
        _lib.rnp_op_encrypt_execute(self._obj)
