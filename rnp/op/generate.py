from ctypes import c_void_p, byref

from ..lib import _lib
from ..key import Key


class Generate:
    def __init__(self, obj):
        self._obj = obj
        self._bits = None
        self._hashalg = None
        self._qbits = None
        self._curve = None
        self._password = None
        self._cipher = None
        self._s2k_hashalg = None
        self._protection_mode = None
        self._s2k_iterations = None
        self._usage = None
        self._uid = None
        self._lifetime = None
        self._preferences = None

    def __del__(self):
        _lib.rnp_op_generate_destroy(self._obj)

    def obj(self):
        return self._obj

    @staticmethod
    def start(rnp, typ):
        pop = c_void_p()
        _lib.rnp_op_generate_create(byref(pop), rnp.obj(), typ.encode("ascii"))
        if pop.value:
            return Generate(pop)

    @staticmethod
    def start_subkey(rnp, primary, typ):
        pop = c_void_p()
        _lib.rnp_op_generate_subkey_create(
            byref(pop), rnp.obj(), primary.obj(), typ.encode("ascii")
        )
        if pop.value:
            return Generate(pop)

    @property
    def bits(self):
        return self._bits

    @bits.setter
    def bits(self, value):
        _lib.rnp_op_generate_set_bits(self.obj(), value)
        self._bits = value

    @property
    def hashalg(self):
        return self._hashalg

    @hashalg.setter
    def hashalg(self, value):
        _lib.rnp_op_generate_set_hash(self.obj(), value.encode("ascii"))
        self._hashalg = value

    @property
    def qbits(self):
        return self._qbits

    @qbits.setter
    def qbits(self, value):
        _lib.rnp_op_generate_set_dsa_qbits(self.obj(), value)
        self._qbits = value

    @property
    def curve(self):
        return self._curve

    @curve.setter
    def curve(self, value):
        _lib.rnp_op_generate_set_curve(self.obj(), value.encode("ascii"))
        self._curve = value

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        _lib.rnp_op_generate_set_protection_password(self.obj(), value.encode("utf-8"))
        self._password = value

    @property
    def cipher(self):
        return self._cipher

    @cipher.setter
    def cipher(self, value):
        _lib.rnp_op_generate_set_protection_cipher(self.obj(), value.encode("ascii"))
        self._cipher = value

    @property
    def s2k_hashalg(self):
        return self._s2k_hashalg

    @s2k_hashalg.setter
    def s2k_hashalg(self, value):
        _lib.rnp_op_generate_set_protection_hash(self.obj(), value.encode("ascii"))
        self._s2k_hashalg = value

    @property
    def protection_mode(self):
        return self._protection_mode

    @protection_mode.setter
    def protection_mode(self, value):
        _lib.rnp_op_generate_set_protection_mode(self.obj(), value.encode("ascii"))
        self._protection_mode = value

    @property
    def s2k_iterations(self):
        return self._s2k_iterations

    @s2k_iterations.setter
    def s2k_iterations(self, value):
        _lib.rnp_op_generate_set_protection_iterations(self.obj(), value)
        self._s2k_iterations = value

    @property
    def usage(self):
        return self._usage

    @usage.setter
    def usage(self, value):
        _lib.rnp_op_generate_clear_usage(self.obj())
        if not isinstance(value, list):
            value = [value]
        for usage in value:
            _lib.rnp_op_generate_add_usage(self.obj(), usage.encode("ascii"))
        self._usage = value

    @property
    def uid(self):
        return self._uid

    @uid.setter
    def uid(self, value):
        _lib.rnp_op_generate_set_userid(self.obj(), value.encode("utf-8"))
        self._uid = value

    @property
    def lifetime(self):
        return self._lifetime

    @lifetime.setter
    def lifetime(self, value):
        _lib.rnp_op_generate_set_expiration(self.obj(), value)
        self._lifetime = value

    @property
    def preferences(self):
        return self._preferences

    @preferences.setter
    def preferences(self, value):
        _lib.rnp_op_generate_clear_pref_hashes(self.obj())
        _lib.rnp_op_generate_clear_pref_compression(self.obj())
        _lib.rnp_op_generate_clear_pref_ciphers(self.obj())
        _lib.rnp_op_generate_set_pref_keyserver(self.obj(), None)
        for alg in value.get("hashes"):
            _lib.rnp_op_generate_add_pref_hash(self.obj(), alg.encode("ascii"))
        for alg in value.get("compression"):
            _lib.rnp_op_generate_add_pref_compression(self.obj(), alg.encode("ascii"))
        for alg in value.get("ciphers"):
            _lib.rnp_op_generate_add_pref_cipher(self.obj(), alg.encode("ascii"))
        if value.get("key_server"):
            _lib.rnp_op_generate_set_pref_keyserver(
                self.obj(), value.get("key_server").encode("utf-8")
            )

    def finish(self):
        _lib.rnp_op_generate_execute(self.obj())
        handle = c_void_p()
        _lib.rnp_op_generate_get_key(self.obj(), byref(handle))
        if handle:
            return Key(handle)
