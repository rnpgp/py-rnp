from ctypes import (
    c_bool,
    c_uint8,
    c_void_p,
    c_size_t,
    byref,
    py_object,
    cast,
    POINTER,
    CFUNCTYPE,
)

from .lib import _lib


class Input:
    def __init__(self, obj, io=None):
        self._obj = obj
        self._io = io

    def __del__(self):
        _lib.rnp_input_destroy(self._obj)

    def obj(self):
        return self._obj

    @staticmethod
    def from_path(path):
        obj = c_void_p()
        _lib.rnp_input_from_path(byref(obj), path.encode("utf-8"))
        return Input(obj)

    @staticmethod
    def from_bytes(data):
        obj = c_void_p()
        buf = (c_uint8 * len(data)).from_buffer_copy(data)
        _lib.rnp_input_from_memory(byref(obj), buf, len(data), True)
        return Input(obj)

    @staticmethod
    def from_io(io):
        obj = c_void_p()
        io = py_object(io)
        _lib.rnp_input_from_callback(byref(obj), Input.READER, Input.CLOSER, byref(io))
        return Input(obj, io)

    @staticmethod
    @CFUNCTYPE(c_bool, c_void_p, c_void_p, c_size_t, POINTER(c_size_t))
    def READER(app_ctx, buf, buf_len, read):
        try:
            io = cast(app_ctx, POINTER(py_object)).contents.value
            data = io.read(buf_len)
            if isinstance(data, str):
                data = data.encode("utf-8")

            buf = (c_uint8 * buf_len).from_address(buf)
            buf[: len(data)] = data[: len(data)]
            read.contents.value = len(data)
            return True
        except Exception as e:
            print(e)
            return False

    @staticmethod
    @CFUNCTYPE(None, c_void_p)
    def CLOSER(app_ctx):
        try:
            io = cast(app_ctx, POINTER(py_object)).contents.value
            io.close()
        except Exception as e:
            print(e)
