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

from .lib import (
    _lib,
    _flags,
    _encode,
    _inp,
    RNP_OUTPUT_FILE_OVERWRITE,
    RNP_OUTPUT_FILE_RANDOM,
)


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
    def to_file(path, overwrite=False, random=False):
        obj = c_void_p()
        flags = _flags(
            [
                (overwrite, RNP_OUTPUT_FILE_OVERWRITE),
                (random, RNP_OUTPUT_FILE_RANDOM),
            ]
        )
        _lib.rnp_output_to_file(byref(obj), path.encode("utf-8"), flags)
        return Output(obj)

    @staticmethod
    def to_armor(base, typ=None):
        obj = c_void_p()
        _lib.rnp_output_to_armor(base.obj(), byref(obj), _encode(typ))
        outp = Output(obj)
        # The armor stream writes through the base output and keeps a raw
        # pointer to it (rnp_output_t::app_ctx), so the base handle must
        # stay alive for the armor output's whole lifetime and be destroyed
        # only after it. Holding a reference here guarantees both, since
        # __del__ runs (destroying the armor handle) before instance
        # attributes are released (destroying the base handle).
        outp._base = base
        return outp

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

    def write(self, data):
        written = c_size_t()
        buf = (c_uint8 * len(data)).from_buffer_copy(data)
        _lib.rnp_output_write(self._obj, buf, len(data), byref(written))
        return written.value

    def pipe(self, inp):
        inp = _inp(inp)
        _lib.rnp_output_pipe(inp.obj(), self._obj)

    def finish(self):
        _lib.rnp_output_finish(self._obj)

    def set_armor_line_length(self, llen):
        _lib.rnp_output_armor_set_line_length(self._obj, llen)

    def bytes(self):
        buf = pointer(c_uint8())
        buflen = c_size_t()
        _lib.rnp_output_memory_get_buf(self.obj(), byref(buf), byref(buflen), False)
        return bytes((c_uint8 * buflen.value).from_address(addressof(buf.contents)))
