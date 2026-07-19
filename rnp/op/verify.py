from ctypes import c_void_p, c_size_t, c_uint32, c_bool, c_char, c_char_p, byref

from ..lib import _lib, _inp
from ..output import Output
from ..key import Key
from ..signature import Signature
from ..recipient import Recipient
from ..symenc import Symenc


class VerifiedSignature(Signature):
    """Signature obtained from a Verify operation. In addition to the base
    Signature interface it exposes operation-level status and details."""

    def __init__(self, obj, vsig):
        super().__init__(obj)
        # verification status context, owned by the Verify operation
        self._vsig = vsig

    def status(self):
        return _lib.rnp_op_verify_signature_get_status(self._vsig)

    def hash(self):
        prop = c_char_p()
        try:
            _lib.rnp_op_verify_signature_get_hash(self._vsig, byref(prop))
            # pylint: disable=E1101
            return prop.value.decode("ascii") if prop.value else None
        finally:
            _lib.rnp_buffer_destroy(prop)

    def key(self):
        pkey = c_void_p()
        _lib.rnp_op_verify_signature_get_key(self._vsig, byref(pkey))
        if pkey.value:
            return Key(pkey.value)

    def times(self):
        create = c_uint32()
        expires = c_uint32()
        _lib.rnp_op_verify_signature_get_times(
            self._vsig, byref(create), byref(expires)
        )
        return create.value, expires.value


class Verify:
    def __init__(self, obj, io):
        self._obj = obj
        self._flags = None
        self._io = io

    def __del__(self):
        _lib.rnp_op_verify_destroy(self._obj)

    def obj(self):
        return self._obj

    @staticmethod
    def start(rnp, inp, outp=None):
        inp = _inp(inp)
        pop = c_void_p()
        if outp is None:
            outp = Output.to_null()
        _lib.rnp_op_verify_create(byref(pop), rnp.obj(), inp.obj(), outp.obj())
        if pop.value:
            op = Verify(pop, (inp, outp))
            return op

    @staticmethod
    def start_detached(rnp, inpdata, inpsig):
        inpdata = _inp(inpdata)
        inpsig = _inp(inpsig)
        pop = c_void_p()
        _lib.rnp_op_verify_detached_create(
            byref(pop), rnp.obj(), inpdata.obj(), inpsig.obj()
        )
        if pop.value:
            return Verify(pop, (inpdata, inpsig))

    @property
    def flags(self):
        return self._flags

    @flags.setter
    def flags(self, flags):
        _lib.rnp_op_verify_set_flags(self._obj, flags)
        self._flags = flags

    def finish(self):
        _lib.rnp_op_verify_execute(self._obj)

    def file_mtime(self):
        mtime = c_uint32()
        _lib.rnp_op_verify_get_file_info(self._obj, None, byref(mtime))
        return mtime.value

    def filename(self):
        filename = c_char_p()
        try:
            _lib.rnp_op_verify_get_file_info(self._obj, byref(filename), None)
            # pylint: disable=E1101
            return filename.value.decode("utf-8")
        finally:
            _lib.rnp_buffer_destroy(filename)

    def format(self):
        fmt = c_char()
        _lib.rnp_op_verify_get_format(self._obj, byref(fmt))
        return fmt.value.decode("ascii") if fmt.value != b"\x00" else None

    def protection_mode(self):
        mode = c_char_p()
        try:
            _lib.rnp_op_verify_get_protection_info(self._obj, byref(mode), None, None)
            # pylint: disable=E1101
            return mode.value.decode("utf-8")
        finally:
            _lib.rnp_buffer_destroy(mode)

    def protection_cipher(self):
        cipher = c_char_p()
        try:
            _lib.rnp_op_verify_get_protection_info(self._obj, None, byref(cipher), None)
            # pylint: disable=E1101
            return cipher.value.decode("utf-8")
        finally:
            _lib.rnp_buffer_destroy(cipher)

    def protection_valid(self):
        valid = c_bool()
        _lib.rnp_op_verify_get_protection_info(self._obj, None, None, byref(valid))
        return valid.value

    def recipient_count(self):
        count = c_size_t()
        _lib.rnp_op_verify_get_recipient_count(self._obj, byref(count))
        return count.value

    def recipients(self):
        for idx in range(self.recipient_count()):
            recipient = c_void_p()
            _lib.rnp_op_verify_get_recipient_at(self._obj, idx, byref(recipient))
            yield Recipient(recipient)

    def used_recipient(self):
        recipient = c_void_p()
        _lib.rnp_op_verify_get_used_recipient(self._obj, byref(recipient))
        if recipient.value:
            return Recipient(recipient)

    def symenc_count(self):
        count = c_size_t()
        _lib.rnp_op_verify_get_symenc_count(self._obj, byref(count))
        return count.value

    def symencs(self):
        for idx in range(self.symenc_count()):
            symenc = c_void_p()
            _lib.rnp_op_verify_get_symenc_at(self._obj, idx, byref(symenc))
            yield Symenc(symenc)

    def used_symenc(self):
        symenc = c_void_p()
        _lib.rnp_op_verify_get_used_symenc(self._obj, byref(symenc))
        if symenc.value:
            return Symenc(symenc)

    def signatures(self):
        count = c_size_t()
        _lib.rnp_op_verify_get_signature_count(self._obj, byref(count))
        for i in range(count.value):
            pvsig = c_void_p()
            _lib.rnp_op_verify_get_signature_at(self._obj, i, byref(pvsig))
            psig = c_void_p()
            _lib.rnp_op_verify_signature_get_handle(pvsig, byref(psig))
            yield VerifiedSignature(psig.value, pvsig)
