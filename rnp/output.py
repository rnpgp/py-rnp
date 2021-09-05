from ctypes import (
    c_bool,
    c_uint8,
    c_void_p,
    c_size_t,
    pointer,
    addressof,
    byref,
    py_object,
    cast,
    POINTER,
    CFUNCTYPE,
)

from .lib import _lib


class DefaultOutput:
    def __init__(self, outp):
        self.outp = Output.to_bytes() if outp is None else outp
        self.default = outp is None

    def __enter__(self):
        if self.default:
            self.outp.default_output = self.outp.bytes
        return self.outp

    def __exit__(self, type, value, traceback):
        pass


class Output:
    def __init__(self, obj, io=None):
        self._obj = obj
        self._io = io

    def __del__(self):
        _lib.rnp_output_destroy(self._obj)

    def obj(self):
        return self._obj

    @staticmethod
    def to_path(path):
        obj = c_void_p()
        _lib.rnp_output_to_path(byref(obj), path.encode("utf-8"))
        return Output(obj)

    @staticmethod
    def to_bytes(max_alloc=0):
        obj = c_void_p()
        _lib.rnp_output_to_memory(byref(obj), max_alloc)
        return Output(obj)

    @staticmethod
    def to_null():
        obj = c_void_p()
        _lib.rnp_output_to_null(byref(obj))
        return Output(obj)

    @staticmethod
    def to_io(io):
        obj = c_void_p()
        io = py_object(io)
        _lib.rnp_output_to_callback(byref(obj), Output.WRITER, Output.CLOSER, byref(io))
        return Output(obj, io)

    @staticmethod
    @CFUNCTYPE(c_bool, c_void_p, c_void_p, c_size_t)
    def WRITER(app_ctx, buf, buf_len):
        try:
            io = cast(app_ctx, POINTER(py_object)).contents.value
            buf = (c_uint8 * buf_len).from_address(buf)
            return io.write(buf) == buf_len
        except Exception as e:
            print(e)
            return False

    @staticmethod
    @CFUNCTYPE(None, c_void_p, c_bool)
    def CLOSER(app_ctx, discard):
        try:
            io = cast(app_ctx, POINTER(py_object)).contents.value
            io.close()
        except Exception as e:
            print(e)

    # private
    @staticmethod
    def default(outp):
        return DefaultOutput(outp)

    # private
    def default_output(self):
        return None

    def bytes(self):
        buf = pointer(c_uint8())
        buflen = c_size_t()
        _lib.rnp_output_memory_get_buf(self.obj(), byref(buf), byref(buflen), False)
        return bytes((c_uint8 * buflen.value).from_address(addressof(buf.contents)))
