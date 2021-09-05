from ctypes import c_void_p, c_size_t, c_uint32, c_bool, c_char_p, byref

from ..lib import _lib, _inp
from ..output import Output
from ..signature import Signature


class Verify:
    def __init__(self, obj, io):
        self._obj = obj
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
            return filename.decode("utf-8")
        finally:
            _lib.rnp_buffer_destroy(filename)

    def protection_mode(self):
        mode = c_char_p()
        try:
            _lib.rnp_op_verify_get_protection_info(self._obj, byref(mode), None, None)
            return mode.decode("utf-8")
        finally:
            _lib.rnp_buffer_destroy(mode)

    def protection_cipher(self):
        cipher = c_char_p()
        try:
            _lib.rnp_op_verify_get_protection_info(self._obj, byref(cipher), None, None)
            return cipher.decode("utf-8")
        finally:
            _lib.rnp_buffer_destroy(cipher)

    def protection_valid(self):
        valid = c_bool()
        _lib.rnp_op_verify_get_protection_info(self._obj, None, None, byref(valid))
        return valid.value

    def signatures(self):
        count = c_size_t()
        _lib.rnp_op_verify_get_signature_count(self._obj, byref(count))
        for i in range(count.value):
            pvsig = c_void_p()
            _lib.rnp_op_verify_get_signature_at(self._obj, i, byref(pvsig))
            psig = c_void_p()
            _lib.rnp_op_verify_signature_get_handle(pvsig, byref(psig))
            sig = Signature(psig.value)
            sig.status = lambda: _lib.rnp_op_verify_signature_get_status(pvsig)
            yield sig
