#!/usr/bin/env python

import io
from ctypes import (
    CDLL,
    CFUNCTYPE,
    POINTER,
    c_uint8,
    c_uint32,
    c_uint64,
    c_char_p,
    c_void_p,
    c_bool,
    c_size_t,
    c_int,
    c_char,
)
from sys import platform


class RnpException(Exception):
    def __init__(self, message, rc=0):
        self.rc = rc
        if rc == 0:
            super(RnpException, self).__init__(message)
        else:
            desc = _lib.rnp_result_to_string(rc).decode("ascii")
            super(RnpException, self).__init__("%s: 0x%x (%s)" % (message, rc, desc))

    def error_code(self):
        return self.rc


PASS_PROVIDER = CFUNCTYPE(
    c_bool, c_void_p, c_void_p, c_void_p, c_char_p, POINTER(c_char), c_size_t
)
KEY_PROVIDER = CFUNCTYPE(None, c_void_p, c_void_p, c_char_p, c_char_p, c_bool)

INPUT_READER = CFUNCTYPE(c_bool, c_void_p, c_void_p, c_size_t, POINTER(c_size_t))
INPUT_CLOSER = CFUNCTYPE(None, c_void_p)

OUTPUT_WRITER = CFUNCTYPE(c_bool, c_void_p, c_void_p, c_size_t)
OUTPUT_CLOSER = CFUNCTYPE(None, c_void_p, c_bool)

RNP_LOAD_SAVE_PUBLIC_KEYS = 1 << 0
RNP_LOAD_SAVE_SECRET_KEYS = 1 << 1
RNP_LOAD_SAVE_PERMISSIVE = 1 << 8
RNP_LOAD_SAVE_SINGLE = 1 << 9

RNP_KEY_EXPORT_ARMORED = 1 << 0
RNP_KEY_EXPORT_PUBLIC = 1 << 1
RNP_KEY_EXPORT_SECRET = 1 << 2
RNP_KEY_EXPORT_SUBKEYS = 1 << 3

RNP_JSON_PUBLIC_MPIS = 1 << 0
RNP_JSON_SECRET_MPIS = 1 << 1
RNP_JSON_SIGNATURES = 1 << 2
RNP_JSON_SIGNATURE_MPIS = 1 << 3

RNP_KEY_REMOVE_PUBLIC = 1 << 0
RNP_KEY_REMOVE_SECRET = 1 << 1
RNP_KEY_REMOVE_SUBKEYS = 1 << 2

RNP_JSON_DUMP_MPI = 1 << 0
RNP_JSON_DUMP_RAW = 1 << 1
RNP_JSON_DUMP_GRIP = 1 << 2

RNP_KEY_SUBKEYS_ONLY = 1 << 0

RNP_ERROR_KEY_NOT_FOUND = 0x12000005
RNP_ERROR_NO_SUITABLE_KEY = 0x12000006


def _load_lib():
    libnames = []
    if platform in ["win32", "cygin", "msys"]:
        libnames.extend(["rnp.dll", "librnp.dll"])
    elif platform in ["darwin", "macos"]:
        libnames.extend(["rnp.dylib", "librnp.dylib"])
    else:
        libnames.extend(["rnp.so", "librnp.so"])

    for libname in libnames:
        try:
            return CDLL(libname)
        except OSError:
            pass
    raise RnpException("Unable to load rnp native library")


def _errcheck(rc, fn, _args):
    if rc == 0:
        return rc
    raise RnpException("%s failed" % (fn.__name__), rc)


def _setup(lib):
    def define(func, args):
        func.argtypes = args
        func.restype = c_uint32
        func.errcheck = _errcheck

    lib.rnp_result_to_string.argtypes = [c_uint32]
    lib.rnp_result_to_string.restype = c_char_p

    lib.rnp_version_string.argtypes = []
    lib.rnp_version_string.restype = c_char_p

    lib.rnp_version_string_full.argtypes = []
    lib.rnp_version_string_full.restype = c_char_p

    lib.rnp_version.argtypes = []
    lib.rnp_version.restype = c_uint32

    lib.rnp_version_for.argtypes = [c_uint32, c_uint32, c_uint32]
    lib.rnp_version_for.restype = c_uint32

    lib.rnp_version_major.argtypes = []
    lib.rnp_version_major.restype = c_uint32

    lib.rnp_version_minor.argtypes = []
    lib.rnp_version_minor.restype = c_uint32

    lib.rnp_version_patch.argtypes = []
    lib.rnp_version_patch.restype = c_uint32

    lib.rnp_version_commit_timestamp.argtypes = []
    lib.rnp_version_commit_timestamp.restype = c_uint64

    # features/quirks
    lib.features = {
        "have-rnp-signature-get-expiration": lib.rnp_version()
        > lib.rnp_version_for(0, 15, 2)
        or lib.rnp_version_commit_timestamp() > 1629965914,
    }

    lib.rnp_buffer_destroy.argtypes = [c_void_p]
    lib.rnp_buffer_destroy.restype = None

    define(lib.rnp_enable_debug, [c_char_p])
    define(lib.rnp_disable_debug, [])

    define(lib.rnp_ffi_create, [c_void_p, c_char_p, c_char_p])
    define(lib.rnp_ffi_destroy, [c_void_p])

    define(lib.rnp_ffi_set_log_fd, [c_void_p, c_int])

    define(lib.rnp_ffi_set_key_provider, [c_void_p, KEY_PROVIDER, c_void_p])
    define(lib.rnp_ffi_set_pass_provider, [c_void_p, PASS_PROVIDER, c_void_p])

    define(lib.rnp_get_default_homedir, [POINTER(c_char_p)])
    define(
        lib.rnp_detect_homedir_info,
        [
            c_char_p,
            POINTER(c_char_p),
            POINTER(c_char_p),
            POINTER(c_char_p),
            POINTER(c_char_p),
        ],
    )

    define(lib.rnp_detect_key_format, [POINTER(c_uint8), c_size_t, POINTER(c_char_p)])

    define(lib.rnp_calculate_iterations, [c_char_p, c_size_t, POINTER(c_size_t)])

    define(lib.rnp_supports_feature, [c_char_p, c_char_p, POINTER(c_bool)])
    define(lib.rnp_supported_features, [c_char_p, POINTER(c_char_p)])

    define(lib.rnp_guess_contents, [c_void_p, POINTER(c_char_p)])
    define(lib.rnp_enarmor, [c_void_p, c_void_p, c_char_p])
    define(lib.rnp_dearmor, [c_void_p, c_void_p])

    define(lib.rnp_dump_packets_to_json, [c_void_p, c_uint32, POINTER(c_char_p)])

    define(lib.rnp_load_keys, [c_void_p, c_char_p, c_void_p, c_uint32])
    define(lib.rnp_unload_keys, [c_void_p, c_uint32])
    define(lib.rnp_save_keys, [c_void_p, c_char_p, c_void_p, c_uint32])

    define(lib.rnp_import_keys, [c_void_p, c_void_p, c_uint32, POINTER(c_char_p)])
    define(lib.rnp_import_signatures, [c_void_p, c_void_p, c_uint32, POINTER(c_char_p)])

    define(lib.rnp_get_public_key_count, [c_void_p, POINTER(c_size_t)])
    define(lib.rnp_get_secret_key_count, [c_void_p, POINTER(c_size_t)])

    define(lib.rnp_input_from_path, [POINTER(c_void_p), c_char_p])
    define(
        lib.rnp_input_from_memory,
        [POINTER(c_void_p), POINTER(c_uint8), c_size_t, c_bool],
    )
    define(
        lib.rnp_input_from_callback,
        [POINTER(c_void_p), INPUT_READER, INPUT_CLOSER, c_void_p],
    )
    define(lib.rnp_input_destroy, [c_void_p])

    define(lib.rnp_output_to_path, [POINTER(c_void_p), c_char_p])
    define(lib.rnp_output_to_memory, [POINTER(c_void_p), c_size_t])
    define(
        lib.rnp_output_memory_get_buf,
        [c_void_p, POINTER(POINTER(c_uint8)), POINTER(c_size_t), c_bool],
    )
    define(lib.rnp_output_to_null, [POINTER(c_void_p)])
    define(
        lib.rnp_output_to_callback, [c_void_p, OUTPUT_WRITER, OUTPUT_CLOSER, c_void_p]
    )
    define(lib.rnp_output_destroy, [c_void_p])

    define(lib.rnp_locate_key, [c_void_p, c_char_p, c_char_p, POINTER(c_void_p)])

    define(lib.rnp_generate_key_json, [c_void_p, c_char_p, POINTER(c_char_p)])
    define(
        lib.rnp_generate_key_rsa,
        [c_void_p, c_uint32, c_uint32, c_char_p, c_char_p, POINTER(c_void_p)],
    )
    define(
        lib.rnp_generate_key_dsa_eg,
        [c_void_p, c_uint32, c_uint32, c_char_p, c_char_p, POINTER(c_void_p)],
    )
    define(
        lib.rnp_generate_key_ec,
        [c_void_p, c_char_p, c_char_p, c_char_p, POINTER(c_void_p)],
    )
    define(
        lib.rnp_generate_key_25519, [c_void_p, c_char_p, c_char_p, POINTER(c_void_p)]
    )
    define(lib.rnp_generate_key_sm2, [c_void_p, c_char_p, c_char_p, POINTER(c_void_p)])
    define(
        lib.rnp_generate_key_ex,
        [
            c_void_p,
            c_char_p,
            c_char_p,
            c_uint32,
            c_uint32,
            c_char_p,
            c_char_p,
            c_char_p,
            c_char_p,
            POINTER(c_void_p),
        ],
    )

    define(lib.rnp_ffi_set_pass_provider, [c_void_p, PASS_PROVIDER, c_void_p])

    define(lib.rnp_decrypt, [c_void_p, c_void_p, c_void_p])

    define(lib.rnp_key_handle_destroy, [c_void_p])
    define(lib.rnp_key_get_keyid, [c_void_p, POINTER(c_char_p)])
    define(lib.rnp_key_get_fprint, [c_void_p, POINTER(c_char_p)])
    define(lib.rnp_key_get_grip, [c_void_p, POINTER(c_char_p)])
    define(lib.rnp_key_get_primary_grip, [c_void_p, POINTER(c_char_p)])
    define(lib.rnp_key_get_primary_fprint, [c_void_p, POINTER(c_char_p)])
    define(lib.rnp_key_get_uid_count, [c_void_p, POINTER(c_size_t)])
    define(lib.rnp_key_get_uid_at, [c_void_p, c_size_t, POINTER(c_char_p)])
    define(lib.rnp_key_get_uid_handle_at, [c_void_p, c_size_t, POINTER(c_void_p)])
    define(lib.rnp_key_get_primary_uid, [c_void_p, POINTER(c_char_p)])
    define(lib.rnp_key_get_alg, [c_void_p, POINTER(c_char_p)])
    define(lib.rnp_key_get_bits, [c_void_p, POINTER(c_uint32)])
    define(lib.rnp_key_get_dsa_qbits, [c_void_p, POINTER(c_uint32)])
    define(lib.rnp_key_get_curve, [c_void_p, POINTER(c_char_p)])
    define(
        lib.rnp_key_add_uid, [c_void_p, c_char_p, c_char_p, c_uint32, c_uint8, c_bool]
    )
    define(lib.rnp_key_export, [c_void_p, c_void_p, c_uint32])
    define(
        lib.rnp_key_export_autocrypt, [c_void_p, c_void_p, c_char_p, c_void_p, c_uint32]
    )
    define(
        lib.rnp_key_export_revocation,
        [c_void_p, c_void_p, c_uint32, c_char_p, c_char_p, c_char_p],
    )
    define(lib.rnp_key_remove, [c_void_p, c_uint32])
    define(lib.rnp_key_is_primary, [c_void_p, POINTER(c_bool)])
    define(lib.rnp_key_is_sub, [c_void_p, POINTER(c_bool)])
    define(lib.rnp_key_have_secret, [c_void_p, POINTER(c_bool)])
    define(lib.rnp_key_have_public, [c_void_p, POINTER(c_bool)])
    define(lib.rnp_key_to_json, [c_void_p, c_uint32, POINTER(c_char_p)])
    define(lib.rnp_key_is_revoked, [c_void_p, POINTER(c_bool)])
    define(lib.rnp_key_get_revocation_reason, [c_void_p, POINTER(c_char_p)])
    define(lib.rnp_key_get_revocation_signature, [c_void_p, POINTER(c_void_p)])
    define(lib.rnp_key_is_superseded, [c_void_p, POINTER(c_bool)])
    define(lib.rnp_key_is_compromised, [c_void_p, POINTER(c_bool)])
    define(lib.rnp_key_is_retired, [c_void_p, POINTER(c_bool)])
    define(lib.rnp_key_allows_usage, [c_void_p, c_char_p, POINTER(c_bool)])
    define(lib.rnp_key_get_creation, [c_void_p, POINTER(c_uint32)])
    define(lib.rnp_key_get_expiration, [c_void_p, POINTER(c_uint32)])
    define(lib.rnp_key_set_expiration, [c_void_p, c_uint32])
    define(lib.rnp_key_get_signature_count, [c_void_p, POINTER(c_size_t)])
    define(lib.rnp_key_get_signature_at, [c_void_p, c_size_t, POINTER(c_void_p)])
    define(lib.rnp_key_get_subkey_count, [c_void_p, POINTER(c_size_t)])
    define(lib.rnp_key_get_subkey_at, [c_void_p, c_size_t, POINTER(c_void_p)])
    define(lib.rnp_key_lock, [c_void_p])
    define(lib.rnp_key_unlock, [c_void_p, c_char_p])
    define(lib.rnp_key_is_locked, [c_void_p, POINTER(c_bool)])
    define(
        lib.rnp_key_protect,
        [c_void_p, c_char_p, c_char_p, c_char_p, c_char_p, c_size_t],
    )
    define(lib.rnp_key_unprotect, [c_void_p, c_char_p])
    define(lib.rnp_key_is_protected, [c_void_p, POINTER(c_bool)])
    define(lib.rnp_key_packets_to_json, [c_void_p, c_bool, c_uint32, POINTER(c_char_p)])
    define(lib.rnp_key_revoke, [c_void_p, c_uint32, c_char_p, c_char_p, c_char_p])
    define(
        lib.rnp_get_public_key_data,
        [c_void_p, POINTER(POINTER(c_uint8)), POINTER(c_size_t)],
    )
    define(
        lib.rnp_get_secret_key_data,
        [c_void_p, POINTER(POINTER(c_uint8)), POINTER(c_size_t)],
    )
    define(lib.rnp_key_is_valid, [c_void_p, POINTER(c_bool)])
    define(lib.rnp_key_get_protection_cipher, [c_void_p, POINTER(c_char_p)])
    define(lib.rnp_key_get_protection_hash, [c_void_p, POINTER(c_char_p)])
    define(lib.rnp_key_get_protection_mode, [c_void_p, POINTER(c_char_p)])
    define(lib.rnp_key_get_protection_type, [c_void_p, POINTER(c_char_p)])
    define(lib.rnp_key_get_protection_iterations, [c_void_p, POINTER(c_size_t)])
    define(lib.rnp_key_valid_till64, [c_void_p, POINTER(c_uint64)])
    lib.rnp_key_get_default_key.argtypes = [
        c_void_p,
        c_char_p,
        c_uint32,
        POINTER(c_void_p),
    ]
    lib.rnp_key_get_default_key.restype = c_uint32

    define(lib.rnp_uid_get_type, [c_void_p, POINTER(c_uint32)])
    define(lib.rnp_uid_get_data, [c_void_p, POINTER(c_void_p), POINTER(c_size_t)])
    define(lib.rnp_uid_is_primary, [c_void_p, POINTER(c_bool)])
    define(lib.rnp_uid_is_valid, [c_void_p, POINTER(c_bool)])
    define(lib.rnp_uid_is_revoked, [c_void_p, POINTER(c_bool)])
    define(lib.rnp_uid_get_revocation_signature, [c_void_p, POINTER(c_void_p)])
    define(lib.rnp_uid_get_signature_count, [c_void_p, POINTER(c_size_t)])
    define(lib.rnp_uid_get_signature_at, [c_void_p, c_size_t, POINTER(c_void_p)])
    define(lib.rnp_uid_remove, [c_void_p, c_void_p])
    define(lib.rnp_uid_handle_destroy, [c_void_p])

    define(lib.rnp_identifier_iterator_create, [c_void_p, POINTER(c_void_p), c_char_p])
    define(lib.rnp_identifier_iterator_next, [c_void_p, POINTER(c_char_p)])
    define(lib.rnp_identifier_iterator_destroy, [c_void_p])

    define(lib.rnp_signature_handle_destroy, [c_void_p])
    define(lib.rnp_signature_get_type, [c_void_p, POINTER(c_char_p)])
    define(lib.rnp_signature_get_alg, [c_void_p, POINTER(c_char_p)])
    define(lib.rnp_signature_get_hash_alg, [c_void_p, POINTER(c_char_p)])
    define(lib.rnp_signature_get_keyid, [c_void_p, POINTER(c_char_p)])
    define(lib.rnp_signature_get_creation, [c_void_p, POINTER(c_uint32)])
    if lib.features["have-rnp-signature-get-expiration"]:
        define(lib.rnp_signature_get_expiration, [c_void_p, POINTER(c_uint32)])
    define(lib.rnp_signature_get_signer, [c_void_p, POINTER(c_void_p)])
    define(lib.rnp_signature_packet_to_json, [c_void_p, c_uint32, POINTER(c_char_p)])
    lib.rnp_signature_is_valid.argtypes = [c_void_p, c_uint32]
    lib.rnp_signature_is_valid.restype = c_uint32

    define(lib.rnp_op_sign_create, [POINTER(c_void_p), c_void_p, c_void_p, c_void_p])
    define(
        lib.rnp_op_sign_cleartext_create,
        [POINTER(c_void_p), c_void_p, c_void_p, c_void_p],
    )
    define(
        lib.rnp_op_sign_detached_create,
        [POINTER(c_void_p), c_void_p, c_void_p, c_void_p],
    )
    define(lib.rnp_op_sign_destroy, [c_void_p])
    define(lib.rnp_op_sign_set_armor, [c_void_p, c_bool])
    define(lib.rnp_op_sign_set_hash, [c_void_p, c_char_p])
    define(lib.rnp_op_sign_set_compression, [c_void_p, c_char_p])
    define(lib.rnp_op_sign_set_creation_time, [c_void_p, c_uint32])
    define(lib.rnp_op_sign_set_expiration_time, [c_void_p, c_uint32])
    define(lib.rnp_op_sign_add_signature, [c_void_p, c_void_p, POINTER(c_void_p)])
    define(lib.rnp_op_sign_signature_set_hash, [c_void_p, c_char_p])
    define(lib.rnp_op_sign_signature_set_creation_time, [c_void_p, c_uint32])
    define(lib.rnp_op_sign_signature_set_expiration_time, [c_void_p, c_uint32])
    define(lib.rnp_op_sign_execute, [c_void_p])
    define(lib.rnp_op_sign_set_file_mtime, [c_void_p, c_uint32])
    define(lib.rnp_op_sign_set_file_name, [c_void_p, c_char_p])

    define(lib.rnp_op_verify_create, [POINTER(c_void_p), c_void_p, c_void_p, c_void_p])
    define(
        lib.rnp_op_verify_detached_create,
        [POINTER(c_void_p), c_void_p, c_void_p, c_void_p],
    )
    define(lib.rnp_op_verify_destroy, [c_void_p])
    define(lib.rnp_op_verify_execute, [c_void_p])
    define(lib.rnp_op_verify_get_signature_count, [c_void_p, POINTER(c_size_t)])
    define(lib.rnp_op_verify_get_signature_at, [c_void_p, c_size_t, POINTER(c_void_p)])
    define(lib.rnp_op_verify_signature_get_handle, [c_void_p, POINTER(c_void_p)])
    define(
        lib.rnp_op_verify_get_file_info,
        [c_void_p, POINTER(c_char_p), POINTER(c_uint32)],
    )
    define(
        lib.rnp_op_verify_get_protection_info,
        [c_void_p, POINTER(c_char_p), POINTER(c_char_p), POINTER(c_bool)],
    )
    lib.rnp_op_verify_signature_get_status.argtypes = [c_void_p]
    lib.rnp_op_verify_signature_get_status.restype = c_uint32

    define(lib.rnp_op_generate_create, [POINTER(c_void_p), c_void_p, c_char_p])
    define(lib.rnp_op_generate_execute, [c_void_p])
    define(lib.rnp_op_generate_destroy, [c_void_p])
    define(
        lib.rnp_op_generate_subkey_create,
        [POINTER(c_void_p), c_void_p, c_void_p, c_char_p],
    )
    define(lib.rnp_op_generate_set_bits, [c_void_p, c_uint32])
    define(lib.rnp_op_generate_set_hash, [c_void_p, c_char_p])
    define(lib.rnp_op_generate_set_dsa_qbits, [c_void_p, c_uint32])
    define(lib.rnp_op_generate_set_curve, [c_void_p, c_char_p])
    define(lib.rnp_op_generate_set_protection_password, [c_void_p, c_char_p])
    define(lib.rnp_op_generate_set_protection_cipher, [c_void_p, c_char_p])
    define(lib.rnp_op_generate_set_protection_hash, [c_void_p, c_char_p])
    define(lib.rnp_op_generate_set_protection_mode, [c_void_p, c_char_p])
    define(lib.rnp_op_generate_set_protection_iterations, [c_void_p, c_uint32])
    define(lib.rnp_op_generate_add_usage, [c_void_p, c_char_p])
    define(lib.rnp_op_generate_clear_usage, [c_void_p])
    define(lib.rnp_op_generate_set_userid, [c_void_p, c_char_p])
    define(lib.rnp_op_generate_set_expiration, [c_void_p, c_uint32])
    define(lib.rnp_op_generate_add_pref_hash, [c_void_p, c_char_p])
    define(lib.rnp_op_generate_clear_pref_hashes, [c_void_p])
    define(lib.rnp_op_generate_add_pref_compression, [c_void_p, c_char_p])
    define(lib.rnp_op_generate_clear_pref_compression, [c_void_p])
    define(lib.rnp_op_generate_add_pref_cipher, [c_void_p, c_char_p])
    define(lib.rnp_op_generate_clear_pref_ciphers, [c_void_p])
    define(lib.rnp_op_generate_set_pref_keyserver, [c_void_p, c_char_p])
    define(lib.rnp_op_generate_get_key, [c_void_p, POINTER(c_void_p)])

    define(lib.rnp_op_encrypt_create, [POINTER(c_void_p), c_void_p, c_void_p, c_void_p])
    define(lib.rnp_op_encrypt_destroy, [c_void_p])
    define(lib.rnp_op_encrypt_execute, [c_void_p])
    define(
        lib.rnp_op_encrypt_add_password,
        [c_void_p, c_char_p, c_char_p, c_size_t, c_char_p],
    )
    define(lib.rnp_op_encrypt_add_recipient, [c_void_p, c_void_p])
    define(lib.rnp_op_encrypt_add_signature, [c_void_p, c_void_p, POINTER(c_void_p)])
    define(lib.rnp_op_encrypt_set_aead, [c_void_p, c_char_p])
    define(lib.rnp_op_encrypt_set_aead_bits, [c_void_p, c_int])
    define(lib.rnp_op_encrypt_set_armor, [c_void_p, c_bool])
    define(lib.rnp_op_encrypt_set_cipher, [c_void_p, c_char_p])
    define(lib.rnp_op_encrypt_set_hash, [c_void_p, c_char_p])
    define(lib.rnp_op_encrypt_set_compression, [c_void_p, c_char_p, c_int])
    define(lib.rnp_op_encrypt_set_creation_time, [c_void_p, c_uint32])
    define(lib.rnp_op_encrypt_set_expiration_time, [c_void_p, c_uint32])
    define(lib.rnp_op_encrypt_set_file_mtime, [c_void_p, c_uint32])
    define(lib.rnp_op_encrypt_set_file_name, [c_void_p, c_char_p])


def _encode(value):
    if isinstance(value, str):
        return value.encode("utf-8")
    return value


def _obj(value):
    if value is not None:
        return value.obj()


def _flags(flags):
    from functools import reduce
    import operator

    return reduce(
        operator.or_,
        map(operator.itemgetter(1), filter(operator.itemgetter(0), flags)),
        0,
    )


def _inp(inp):
    from rnp import Input

    if isinstance(inp, (bytes, bytearray)):
        inp = Input.from_bytes(inp)
    elif isinstance(inp, str):
        inp = Input.from_bytes(str.encode("utf-8"))
    elif isinstance(inp, io.IOBase):
        inp = Input.from_io(inp)

    return inp


_lib = _load_lib()
_setup(_lib)
