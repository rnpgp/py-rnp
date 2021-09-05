from ctypes import pointer, c_uint8, c_char_p, c_bool, c_size_t, byref
import json

from .lib import (
    _lib,
    _encode,
    _flags,
    _inp,
    RNP_JSON_DUMP_MPI,
    RNP_JSON_DUMP_RAW,
    RNP_JSON_DUMP_GRIP,
)
from .output import Output


def version_string():
    return _lib.rnp_version_string().decode("ascii")


def version_string_full():
    return _lib.rnp_version_string_full().decode("ascii")


def version(ver=None):
    if ver is None:
        return _lib.rnp_version()

    components = list(map(int, ver.split(".")))
    assert len(components) == 3
    return _lib.rnp_version_for(components[0], components[1], components[2])


def version_for(major, minor, patch):
    return _lib.rnp_version_for(major, minor, patch)


def version_major():
    return _lib.rnp_version_major()


def version_minor():
    return _lib.rnp_version_minor()


def version_patch():
    return _lib.rnp_version_patch()


def commit_time():
    return _lib.rnp_version_commit_timestamp()


def enable_debug(files=None):
    _lib.rnp_enable_debug(_encode(files))


def disable_debug():
    _lib.rnp_disable_debug()


def default_homedir():
    try:
        homedir = None
        phomedir = pointer(c_char_p())
        _lib.rnp_get_default_homedir(phomedir)
        homedir = phomedir.contents
        return homedir.value.decode("utf-8")
    finally:
        _lib.rnp_buffer_destroy(homedir)


def homedir_info(homedir):
    try:
        pub_format = pub_path = sec_format = sec_path = None
        ppub_format = pointer(c_char_p())
        ppub_path = pointer(c_char_p())
        psec_format = pointer(c_char_p())
        psec_path = pointer(c_char_p())
        _lib.rnp_detect_homedir_info(
            homedir.encode("utf-8"), ppub_format, ppub_path, psec_format, psec_path
        )
        pub_format = ppub_format.contents
        pub_path = ppub_path.contents
        sec_format = psec_format.contents
        sec_path = psec_path.contents
        return {
            "public": {
                "format": pub_format.value.decode("utf-8"),
                "path": pub_path.value.decode("utf-8"),
            },
            "secret": {
                "format": sec_format.value.decode("utf-8"),
                "path": sec_path.value.decode("utf-8"),
            },
        }
    finally:
        _lib.rnp_buffer_destroy(pub_format)
        _lib.rnp_buffer_destroy(pub_path)
        _lib.rnp_buffer_destroy(sec_format)
        _lib.rnp_buffer_destroy(sec_path)


def key_format(keybytes):
    try:
        fmt = None
        pfmt = pointer(c_char_p())
        buf = (c_uint8 * len(keybytes)).from_buffer_copy(keybytes)
        _lib.rnp_detect_key_format(buf, len(keybytes), pfmt)
        fmt = pfmt.contents
        if not fmt.value:
            return None
        return fmt.value.decode("utf-8")
    finally:
        _lib.rnp_buffer_destroy(fmt)


def calculate_iterations(hashalg, msec):
    iters = c_size_t()
    _lib.rnp_calculate_iterations(hashalg.encode("ascii"), msec, byref(iters))
    return iters.value


def supports(ftype, fname):
    supported = c_bool()
    _lib.rnp_supports_feature(
        ftype.encode("ascii"), fname.encode("ascii"), byref(supported)
    )
    return supported.value


def features(ftype):
    try:
        jsn = None
        pjsn = pointer(c_char_p())
        _lib.rnp_supported_features(ftype.encode("ascii"), pjsn)
        jsn = pjsn.contents
        return json.loads(jsn.value.decode("ascii"))
    finally:
        _lib.rnp_buffer_destroy(jsn)


def enarmor(inp, outp=None, typ=None):
    inp = _inp(inp)
    with Output.default(outp) as outp:
        _lib.rnp_enarmor(inp.obj(), outp.obj(), _encode(typ))
        return outp.default_output()


def dearmor(inp, outp=None):
    inp = _inp(inp)
    with Output.default(outp) as outp:
        _lib.rnp_dearmor(inp.obj(), outp.obj())
        return outp.default_output()


def parse(inp, mpi=False, raw=False, grip=False):
    inp = _inp(inp)
    flags = _flags(
        [
            (mpi, RNP_JSON_DUMP_MPI),
            (raw, RNP_JSON_DUMP_RAW),
            (grip, RNP_JSON_DUMP_GRIP),
        ]
    )
    jsn = c_char_p()
    try:
        _lib.rnp_dump_packets_to_json(inp.obj(), flags, byref(jsn))
        if jsn.value is not None:
            # pylint: disable=E1101
            return json.loads(jsn.value.decode("utf-8"))

        return None
    finally:
        _lib.rnp_buffer_destroy(jsn)


def guess_contents(inp):
    inp = _inp(inp)
    result = c_char_p()
    try:
        _lib.rnp_guess_contents(inp.obj(), byref(result))
        # pylint: disable=E1101
        return result.value.decode("utf-8")
    finally:
        _lib.rnp_buffer_destroy(result)


def check(quirk):
    return _lib.features.get(quirk)
