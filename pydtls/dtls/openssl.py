# OpenSSL library wrapper: provide access to both OpenSSL dynamic libraries
# through ctypes.

# Copyright 2012 Ray Brown
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# The License is also distributed with this work in the file named "LICENSE."
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""OpenSSL Wrapper

This module provides run-time access to the OpenSSL cryptographic and
protocols libraries. It is designed for use with "from openssl import *". For
this reason, the module variable __all__ contains all of this module's
integer constants, OpenSSL library functions, and wrapper functions.

Constants and functions are not documented here. See the OpenSSL library
documentation.

Exceptions:

  OpenSSLError -- exception raised when errors occur in the OpenSSL library
"""

import sys
import array
import socket
from logging import getLogger
from os import path
from datetime import timedelta
from err import openssl_error
from err import SSL_ERROR_NONE
from util import _EC_KEY, _BIO
import ctypes
from ctypes import CDLL
from ctypes import CFUNCTYPE
from ctypes import c_void_p, c_int, c_long, c_uint, c_ulong, c_char_p, c_size_t
from ctypes import c_short, c_ushort, c_ubyte, c_char
from ctypes import byref, POINTER, addressof
from ctypes import Structure, Union
from ctypes import create_string_buffer, sizeof, memmove, cast

#
# Module initialization
#
_logger = getLogger(__name__)

#
# Library loading
#
if sys.platform.startswith('win'):
    dll_path = path.abspath(path.dirname(__file__))
    cryptodll_path = path.join(dll_path, "libeay32.dll")
    ssldll_path = path.join(dll_path, "ssleay32.dll")
    libcrypto = CDLL(cryptodll_path)
    libssl = CDLL(ssldll_path)
else:
    libcrypto = CDLL("libcrypto.so.1.0.0")
    libssl = CDLL("libssl.so.1.0.0")

#
# Integer constants - exported
#
BIO_NOCLOSE = 0x00
BIO_CLOSE = 0x01
SSLEAY_VERSION = 0
SSL_OP_NO_QUERY_MTU = 0x00001000
SSL_OP_NO_COMPRESSION = 0x00020000
SSL_VERIFY_NONE = 0x00
SSL_VERIFY_PEER = 0x01
SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02
SSL_VERIFY_CLIENT_ONCE = 0x04
SSL_SESS_CACHE_OFF = 0x0000
SSL_SESS_CACHE_CLIENT = 0x0001
SSL_SESS_CACHE_SERVER = 0x0002
SSL_SESS_CACHE_BOTH = SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_SERVER
SSL_SESS_CACHE_NO_AUTO_CLEAR = 0x0080
SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 0x0100
SSL_SESS_CACHE_NO_INTERNAL_STORE = 0x0200
SSL_SESS_CACHE_NO_INTERNAL = \
  SSL_SESS_CACHE_NO_INTERNAL_LOOKUP | SSL_SESS_CACHE_NO_INTERNAL_STORE
SSL_BUILD_CHAIN_FLAG_NONE = 0x0
SSL_BUILD_CHAIN_FLAG_UNTRUSTED = 0x1
SSL_BUILD_CHAIN_FLAG_NO_ROOT = 0x2
SSL_BUILD_CHAIN_FLAG_CHECK = 0x4
SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR = 0x8
SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR = 0x10
SSL_FILE_TYPE_PEM = 1
GEN_DIRNAME = 4
NID_subject_alt_name = 85
CRYPTO_LOCK = 1

SSL_ST_MASK = 0x0FFF
SSL_ST_CONNECT = 0x1000
SSL_ST_ACCEPT = 0x2000
SSL_ST_INIT = (SSL_ST_CONNECT | SSL_ST_ACCEPT)
SSL_ST_BEFORE = 0x4000

SSL_ST_OK = 0x03
SSL_ST_RENEGOTIATE = (0x04 | SSL_ST_INIT)
SSL_ST_ERR = 0x05

SSL_CB_LOOP = 0x01
SSL_CB_EXIT = 0x02
SSL_CB_READ = 0x04
SSL_CB_WRITE = 0x08

SSL_CB_ALERT = 0x4000
SSL_CB_READ_ALERT = (SSL_CB_ALERT | SSL_CB_READ)
SSL_CB_WRITE_ALERT = (SSL_CB_ALERT | SSL_CB_WRITE)
SSL_CB_ACCEPT_LOOP = (SSL_ST_ACCEPT | SSL_CB_LOOP)
SSL_CB_ACCEPT_EXIT = (SSL_ST_ACCEPT | SSL_CB_EXIT)
SSL_CB_CONNECT_LOOP = (SSL_ST_CONNECT | SSL_CB_LOOP)
SSL_CB_CONNECT_EXIT = (SSL_ST_CONNECT | SSL_CB_EXIT)
SSL_CB_HANDSHAKE_START = 0x10
SSL_CB_HANDSHAKE_DONE = 0x20

#
# Integer constants - internal
#
SSL_CTRL_SET_TMP_ECDH = 4
SSL_CTRL_SET_MTU = 17
SSL_CTRL_OPTIONS = 32
SSL_CTRL_SET_READ_AHEAD = 41
SSL_CTRL_SET_SESS_CACHE_MODE = 44
SSL_CTRL_CLEAR_OPTIONS = 77
SSL_CTRL_GET_CURVES = 90
SSL_CTRL_SET_CURVES = 91
SSL_CTRL_SET_CURVES_LIST = 92
SSL_CTRL_GET_SHARED_CURVE = 93
SSL_CTRL_SET_ECDH_AUTO = 94
SSL_CTRL_SET_SIGALGS = 97
SSL_CTRL_SET_SIGALGS_LIST = 98
SSL_CTRL_SET_CLIENT_SIGALGS = 101
SSL_CTRL_SET_CLIENT_SIGALGS_LIST = 102
SSL_CTRL_BUILD_CERT_CHAIN = 105

BIO_CTRL_INFO = 3
BIO_CTRL_DGRAM_SET_CONNECTED = 32
BIO_CTRL_DGRAM_SET_PEER = 44
BIO_CTRL_DGRAM_GET_PEER = 46

BIO_C_SET_NBIO = 102

DTLS_CTRL_GET_TIMEOUT = 73
DTLS_CTRL_HANDLE_TIMEOUT = 74
DTLS_CTRL_LISTEN = 75
DTLS_CTRL_SET_LINK_MTU = 120

X509_NAME_MAXLEN = 256
GETS_MAXLEN = 2048


class _EllipticCurve(object):
    _curves = None

    @classmethod
    def _get_elliptic_curves(cls):
        if cls._curves is None:
            # Load once
            cls._curves = cls._load_elliptic_curves()
        return cls._curves

    @classmethod
    def _load_elliptic_curves(cls):
        num_curves = EC_get_builtin_curves(None, 0)
        if num_curves > 0:
            builtin_curves = create_string_buffer(sizeof(EC_builtin_curve) * num_curves)
            EC_get_builtin_curves(cast(builtin_curves, POINTER(EC_builtin_curve)), num_curves)
            return [cls(c.nid, OBJ_nid2sn(c.nid)) for c in cast(builtin_curves, POINTER(EC_builtin_curve))[:num_curves]]
        return []

    def __init__(self, nid, name):
        self.nid = nid
        self.name = name

    def __repr__(self):
        return "<Curve %d %r>" % (self.nid, self.name)

    def to_EC_KEY(self):
        key = _EC_KEY(EC_KEY_new_by_curve_name(self.nid))
        return key if bool(key.value) else None


def get_elliptic_curves():
    u''' Return the available curves. If not yet loaded, then load them once.

    :rtype: list
    '''
    return _EllipticCurve._get_elliptic_curves()


def get_elliptic_curve(name):
    u''' Return the curve from the given name.

    :rtype: _EllipticCurve
    '''
    for curve in get_elliptic_curves():
        if curve.name == name:
            return curve
    raise ValueError("unknown curve name", name)


#
# Parameter data types
#
class c_long_parm(object):
    """Long integer paramter class

    c_long must be distinguishable from c_int, as the latter is associated
    with a default error checking routine, while the former is not.
    """


class FuncParam(object):
    """Function parameter or return type"""
    @classmethod
    def from_param(cls, value):
        if not isinstance(value, cls):
            _logger.error("Parameter type mismatch: %s not of type %s",
                          value, cls)
            raise TypeError(repr(value) + " is not of type " + repr(cls))
        return value._as_parameter

    def __init__(self, value):
        self._as_parameter = c_void_p(value)

    def __nonzero__(self):
        return bool(self._as_parameter)

    @property
    def raw(self):
        return self._as_parameter.value


class DTLS_Method(FuncParam):
    def __init__(self, value):
        super(DTLS_Method, self).__init__(value)


class BIO_METHOD(FuncParam):
    def __init__(self, value):
        super(BIO_METHOD, self).__init__(value)


class SSLCTX(FuncParam):
    def __init__(self, value):
        super(SSLCTX, self).__init__(value)


class SSL(FuncParam):
    def __init__(self, value):
        super(SSL, self).__init__(value)


class BIO(FuncParam):
    def __init__(self, value):
        super(BIO, self).__init__(value)


class EC_KEY(FuncParam):
    def __init__(self, value):
        super(EC_KEY, self).__init__(value)


class X509(FuncParam):
    def __init__(self, value):
        super(X509, self).__init__(value)


class X509_val_st(Structure):
    _fields_ = [("notBefore", c_void_p),
                ("notAfter", c_void_p)]


class X509_cinf_st(Structure):
    _fields_ = [("version", c_void_p),
                ("serialNumber", c_void_p),
                ("signature", c_void_p),
                ("issuer", c_void_p),
                ("validity", POINTER(X509_val_st))]  # remaining fields omitted


class X509_st(Structure):
    _fields_ = [("cert_info", POINTER(X509_cinf_st),)]  # remainder omitted


class X509_name_st(Structure):
    _fields_ = [("entries", c_void_p)]  # remaining fields omitted


class ASN1_OBJECT(FuncParam):
    def __init__(self, value):
        super(ASN1_OBJECT, self).__init__(value)


class ASN1_STRING(FuncParam):
    def __init__(self, value):
        super(ASN1_STRING, self).__init__(value)


class ASN1_TIME(FuncParam):
    def __init__(self, value):
        super(ASN1_TIME, self).__init__(value)


class SSL_CIPHER(FuncParam):
    def __init__(self, value):
        super(SSL_CIPHER, self).__init__(value)


class GENERAL_NAME_union_d(Union):
    _fields_ = [("ptr", c_char_p),
                # entries omitted
                ("directoryName", POINTER(X509_name_st))]
                # remaining fields omitted


class STACK(FuncParam):
    def __init__(self, value):
        super(STACK, self).__init__(value)


class GENERAL_NAME(Structure):
    _fields_ = [("type", c_int),
                ("d", GENERAL_NAME_union_d)]


class GENERAL_NAMES(STACK):
    stack_element_type = GENERAL_NAME

    def __init__(self, value):
        super(GENERAL_NAMES, self).__init__(value)


class STACK_OF_X509(STACK):
    stack_element_type = X509

    def __init__(self, value):
        super(STACK_OF_X509, self).__init__(value)


class X509_NAME_ENTRY(Structure):
    _fields_ = [("object", c_void_p),
                ("value", c_void_p),
                ("set", c_int),
                ("size", c_int)]


class ASN1_OCTET_STRING(Structure):
    _fields_ = [("length", c_int),
                ("type", c_int),
                ("data", POINTER(c_ubyte)),
                ("flags", c_long)]


class X509_EXTENSION(Structure):
    _fields_ = [("object", c_void_p),
                ("critical", c_int),
                ("value", POINTER(ASN1_OCTET_STRING))]


class X509V3_EXT_METHOD(Structure):
    _fields_ = [("ext_nid", c_int),
                ("ext_flags", c_int),
                ("it", c_void_p),
                ("ext_new", c_int),
                ("ext_free", c_int),
                ("d2i", c_int),
                ("i2d", c_int)]  # remaining fields omitted


class TIMEVAL(Structure):
    _fields_ = [("tv_sec", c_long),
                ("tv_usec", c_long)]


class EC_builtin_curve(Structure):
    _fields_ = [("nid", c_int),
                ("comment", c_char_p)]


#
# Socket address conversions
#
class sockaddr_storage(Structure):
    _fields_ = [("ss_family", c_short),
                ("pad", c_char * 126)]

class sockaddr_in(Structure):
    _fields_ = [("sin_family", c_short),
                ("sin_port", c_ushort),
                ("sin_addr", c_uint * 1),
                ("sin_zero", c_char * 8)]

class sockaddr_in6(Structure):
    _fields_ = [("sin6_family", c_short),
                ("sin6_port", c_ushort),
                ("sin6_flowinfo", c_uint),
                ("sin6_addr", c_uint * 4),
                ("sin6_scope_id", c_uint)]

class sockaddr_u(Union):
    _fields_ = [("ss", sockaddr_storage),
                ("s4", sockaddr_in),
                ("s6", sockaddr_in6)]

py_inet_ntop = getattr(socket, "inet_ntop", None)
if not py_inet_ntop:
    windll = getattr(ctypes, "windll", None)
    if windll:
        wsa_inet_ntop = getattr(windll.ws2_32, "inet_ntop", None)
    else:
        wsa_inet_ntop = None

py_inet_pton = getattr(socket, "inet_pton", None)
if not py_inet_pton:
    windll = getattr(ctypes, "windll", None)
    if windll:
        wsa_inet_pton = getattr(windll.ws2_32, "inet_pton", None)
    else:
        wsa_inet_pton = None

def inet_ntop(address_family, packed_ip):
    if py_inet_ntop:
        return py_inet_ntop(address_family,
                            array.array('I', packed_ip).tostring())
    if wsa_inet_ntop:
        string_buf = create_string_buffer(47)
        wsa_inet_ntop(address_family, packed_ip,
                      string_buf, sizeof(string_buf))
        if not string_buf.value:
            raise ValueError("wsa_inet_ntop failed with: %s" %
                             array.array('I', packed_ip).tostring())
        return string_buf.value
    if address_family == socket.AF_INET6:
        raise ValueError("Platform does not support IPv6")
    return socket.inet_ntoa(array.array('I', packed_ip).tostring())

def inet_pton(address_family, string_ip):
    if address_family == socket.AF_INET6:
        ret_packed_ip = (c_uint * 4)()
    else:
        ret_packed_ip = (c_uint * 1)()
    if py_inet_pton:
        ret_string = py_inet_pton(address_family, string_ip)
        ret_packed_ip[:] = array.array('I', ret_string)
    elif wsa_inet_pton:
        if wsa_inet_pton(address_family, string_ip, ret_packed_ip) != 1:
            raise ValueError("wsa_inet_pton failed with: %s" % string_ip)
    else:
        if address_family == socket.AF_INET6:
            raise ValueError("Platform does not support IPv6")
        ret_string = socket.inet_aton(string_ip)
        ret_packed_ip[:] = array.array('I', ret_string)
    return ret_packed_ip

def addr_tuple_from_sockaddr_u(su):
    if su.ss.ss_family == socket.AF_INET6:
        return (inet_ntop(socket.AF_INET6, su.s6.sin6_addr),
                socket.ntohs(su.s6.sin6_port),
                socket.ntohl(su.s6.sin6_flowinfo),
                socket.ntohl(su.s6.sin6_scope_id))
    assert su.ss.ss_family == socket.AF_INET
    return inet_ntop(socket.AF_INET, su.s4.sin_addr), \
      socket.ntohs(su.s4.sin_port)

def sockaddr_u_from_addr_tuple(address):
    su = sockaddr_u()
    if len(address) > 2:
        su.ss.ss_family = socket.AF_INET6
        su.s6.sin6_addr[:] = inet_pton(socket.AF_INET6, address[0])
        su.s6.sin6_port = socket.htons(address[1])
        su.s6.sin6_flowinfo = socket.htonl(address[2])
        su.s6.sin6_scope_id = socket.htonl(address[3])
    else:
        su.ss.ss_family = socket.AF_INET
        su.s4.sin_addr[:] = inet_pton(socket.AF_INET, address[0])
        su.s4.sin_port = socket.htons(address[1])
    return su

#
# Error handling
#
def raise_ssl_error(result, func, args, ssl):
    if not ssl:
        ssl_error = SSL_ERROR_NONE
    else:
        ssl_error = _SSL_get_error(ssl, result)
    errqueue = []
    while True:
        err = _ERR_get_error()
        if not err:
            break
        buf = create_string_buffer(512)
        _ERR_error_string_n(err, buf, sizeof(buf))
        errqueue.append((err, buf.value))
    _logger.debug("SSL error raised: ssl_error: %d, result: %d, " +
                  "errqueue: %s, func_name: %s",
                  ssl_error, result, errqueue, func.func_name)
    raise openssl_error()(ssl_error, errqueue, result, func, args)

def find_ssl_arg(args):
    for arg in args:
        if isinstance(arg, SSL):
            return arg

def errcheck_ord(result, func, args):
    if result <= 0:
        raise_ssl_error(result, func, args, find_ssl_arg(args))
    return args

def errcheck_p(result, func, args):
    if not result:
        raise_ssl_error(result, func, args, None)
    return args

def errcheck_FuncParam(result, func, args):
    if not result:
        raise_ssl_error(result, func, args, None)
    return func.ret_type(result)

#
# Function prototypes
#
def _make_function(name, lib, args, export=True, errcheck="default"):
    assert len(args)

    def type_subst(map_type):
        if _subst.has_key(map_type):
            return _subst[map_type]
        return map_type

    sig = tuple(type_subst(i[0]) for i in args)
    # Handle pointer return values (width is architecture-dependent)
    if isinstance(sig[0], type) and issubclass(sig[0], FuncParam):
        sig = (c_void_p,) + sig[1:]
        pointer_return = True
    else:
        pointer_return = False
    if not _sigs.has_key(sig):
        _sigs[sig] = CFUNCTYPE(*sig)
    if export:
        glbl_name = name
        __all__.append(name)
    else:
        glbl_name = "_" + name
    func = _sigs[sig]((name, lib), tuple((i[2] if len(i) > 2 else 1,
                                          i[1],
                                          i[3] if len(i) > 3 else None)
                                         [:3 if len(i) > 3 else 2]
                                         for i in args[1:]))
    func.func_name = name
    if pointer_return:
        func.ret_type = args[0][0]  # for fix-up during error checking protocol
    if errcheck == "default":
        # Assign error checker based on return type
        if args[0][0] in (c_int,):
            errcheck = errcheck_ord
        elif args[0][0] in (c_void_p, c_char_p):
            errcheck = errcheck_p
        elif pointer_return:
            errcheck = errcheck_FuncParam
        else:
            errcheck = None
    if errcheck:
        func.errcheck = errcheck
    globals()[glbl_name] = func

_subst = {c_long_parm: c_long}
_sigs = {}
__all__ = [
    # Constants
    "BIO_NOCLOSE", "BIO_CLOSE",
    "SSLEAY_VERSION",
    "SSL_OP_NO_QUERY_MTU", "SSL_OP_NO_COMPRESSION",
    "SSL_VERIFY_NONE", "SSL_VERIFY_PEER",
    "SSL_VERIFY_FAIL_IF_NO_PEER_CERT", "SSL_VERIFY_CLIENT_ONCE",
    "SSL_SESS_CACHE_OFF", "SSL_SESS_CACHE_CLIENT",
    "SSL_SESS_CACHE_SERVER", "SSL_SESS_CACHE_BOTH",
    "SSL_SESS_CACHE_NO_AUTO_CLEAR", "SSL_SESS_CACHE_NO_INTERNAL_LOOKUP",
    "SSL_SESS_CACHE_NO_INTERNAL_STORE", "SSL_SESS_CACHE_NO_INTERNAL",
    "SSL_ST_MASK", "SSL_ST_CONNECT", "SSL_ST_ACCEPT", "SSL_ST_INIT", "SSL_ST_BEFORE", "SSL_ST_OK",
    "SSL_ST_RENEGOTIATE", "SSL_ST_ERR", "SSL_CB_LOOP", "SSL_CB_EXIT", "SSL_CB_READ", "SSL_CB_WRITE",
    "SSL_CB_ALERT", "SSL_CB_READ_ALERT", "SSL_CB_WRITE_ALERT",
    "SSL_CB_ACCEPT_LOOP", "SSL_CB_ACCEPT_EXIT",
    "SSL_CB_CONNECT_LOOP", "SSL_CB_CONNECT_EXIT",
    "SSL_CB_HANDSHAKE_START", "SSL_CB_HANDSHAKE_DONE",
    "SSL_BUILD_CHAIN_FLAG_NONE", "SSL_BUILD_CHAIN_FLAG_UNTRUSTED", "SSL_BUILD_CHAIN_FLAG_NO_ROOT",
    "SSL_BUILD_CHAIN_FLAG_CHECK", "SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR", "SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR",
    "SSL_FILE_TYPE_PEM",
    "GEN_DIRNAME", "NID_subject_alt_name",
    "CRYPTO_LOCK",
    # Methods
    "CRYPTO_set_locking_callback",
    "DTLSv1_get_timeout", "DTLSv1_handle_timeout",
    "DTLSv1_listen",
    "DTLS_set_link_mtu",
    "BIO_gets", "BIO_read", "BIO_get_mem_data",
    "BIO_dgram_set_connected",
    "BIO_dgram_get_peer", "BIO_dgram_set_peer",
    "BIO_set_nbio",
    "SSL_CTX_set_session_cache_mode", "SSL_CTX_set_read_ahead",
    "SSL_CTX_set_options", "SSL_CTX_clear_options", "SSL_CTX_get_options",
    "SSL_CTX_set1_client_sigalgs_list", "SSL_CTX_set1_client_sigalgs",
    "SSL_CTX_set1_sigalgs_list", "SSL_CTX_set1_sigalgs",
    "SSL_CTX_set1_curves", "SSL_CTX_set1_curves_list",
    "SSL_CTX_set_info_callback",
    "SSL_CTX_build_cert_chain",
    "SSL_CTX_set_ecdh_auto",
    "SSL_CTX_set_tmp_ecdh",
    "SSL_read", "SSL_write",
    "SSL_set_options", "SSL_clear_options", "SSL_get_options",
    "SSL_set1_client_sigalgs_list", "SSL_set1_client_sigalgs",
    "SSL_set1_sigalgs_list", "SSL_set1_sigalgs",
    "SSL_get1_curves", "SSL_get_shared_curve",
    "SSL_set1_curves", "SSL_set1_curves_list",
    "SSL_set_mtu",
    "SSL_state_string_long", "SSL_alert_type_string_long", "SSL_alert_desc_string_long",
    "SSL_get_peer_cert_chain",
    "SSL_CTX_set_cookie_cb",
    "OBJ_obj2txt", "decode_ASN1_STRING", "ASN1_TIME_print",
    "OBJ_nid2sn",
    "X509_get_notAfter",
    "ASN1_item_d2i", "GENERAL_NAME_print",
    "sk_value",
    "sk_pop_free",
    "i2d_X509",
    "get_elliptic_curves",
]  # note: the following map adds to this list

map(lambda x: _make_function(*x), (
    ("SSL_library_init", libssl,
     ((c_int, "ret"),)),
    ("SSL_load_error_strings", libssl,
     ((None, "ret"),)),
    ("SSLeay", libcrypto,
     ((c_long_parm, "ret"),)),
    ("SSLeay_version", libcrypto,
     ((c_char_p, "ret"), (c_int, "t"))),
    ("CRYPTO_set_locking_callback", libcrypto,
     ((None, "ret"), (c_void_p, "func")), False),
    ("CRYPTO_get_id_callback", libcrypto,
     ((c_void_p, "ret"),), True, None),
    ("CRYPTO_num_locks", libcrypto,
     ((c_int, "ret"),)),
    ("DTLS_server_method", libssl,
     ((DTLS_Method, "ret"),)),
    ("DTLSv1_server_method", libssl,
     ((DTLS_Method, "ret"),)),
    ("DTLSv1_2_server_method", libssl,
     ((DTLS_Method, "ret"),)),
    ("DTLSv1_client_method", libssl,
     ((DTLS_Method, "ret"),)),
    ("DTLSv1_2_client_method", libssl,
     ((DTLS_Method, "ret"),)),
    ("SSL_CTX_new", libssl,
     ((SSLCTX, "ret"), (DTLS_Method, "meth"))),
    ("SSL_CTX_free", libssl,
     ((None, "ret"), (SSLCTX, "ctx"))),
    ("SSL_CTX_set_cookie_generate_cb", libssl,
     ((None, "ret"), (SSLCTX, "ctx"), (c_void_p, "app_gen_cookie_cb")), False),
    ("SSL_CTX_set_cookie_verify_cb", libssl,
     ((None, "ret"), (SSLCTX, "ctx"), (c_void_p, "app_verify_cookie_cb")), False),
    ("SSL_CTX_set_info_callback", libssl,
     ((None, "ret"), (SSLCTX, "ctx"), (c_void_p, "app_info_cb")), False),
    ("SSL_new", libssl,
     ((SSL, "ret"), (SSLCTX, "ctx"))),
    ("SSL_free", libssl,
     ((None, "ret"), (SSL, "ssl"))),
    ("SSL_set_bio", libssl,
     ((None, "ret"), (SSL, "ssl"), (BIO, "rbio"), (BIO, "wbio"))),
    ("BIO_new", libcrypto,
     ((BIO, "ret"), (BIO_METHOD, "type"))),
    ("BIO_s_mem", libcrypto,
     ((BIO_METHOD, "ret"),)),
    ("BIO_new_file", libcrypto,
     ((BIO, "ret"), (c_char_p, "filename"), (c_char_p, "mode"))),
    ("BIO_new_dgram", libcrypto,
     ((BIO, "ret"), (c_int, "fd"), (c_int, "close_flag"))),
    ("BIO_free", libcrypto,
     ((c_int, "ret"), (BIO, "a"))),
    ("BIO_gets", libcrypto,
     ((c_int, "ret"), (BIO, "b"), (POINTER(c_char), "buf"), (c_int, "size")), False),
    ("BIO_read", libcrypto,
     ((c_int, "ret"), (BIO, "b"), (c_void_p, "buf"), (c_int, "len")), False),
    ("SSL_CTX_ctrl", libssl,
     ((c_long_parm, "ret"), (SSLCTX, "ctx"), (c_int, "cmd"), (c_long, "larg"), (c_void_p, "parg")), False),
    ("BIO_ctrl", libcrypto,
     ((c_long_parm, "ret"), (BIO, "bp"), (c_int, "cmd"), (c_long, "larg"), (c_void_p, "parg")), False),
    ("SSL_ctrl", libssl,
     ((c_long_parm, "ret"), (SSL, "ssl"), (c_int, "cmd"), (c_long, "larg"), (c_void_p, "parg")), False),
    ("ERR_get_error", libcrypto,
     ((c_long_parm, "ret"),), False),
    ("ERR_error_string_n", libcrypto,
     ((None, "ret"), (c_ulong, "e"), (c_char_p, "buf"), (c_size_t, "len")), False),
    ("SSL_get_error", libssl,
     ((c_int, "ret"), (SSL, "ssl"), (c_int, "ret")), False, None),
    ("SSL_state_string_long", libssl,
     ((c_char_p, "ret"), (SSL, "ssl")), False),
    ("SSL_alert_type_string_long", libssl,
     ((c_char_p, "ret"), (c_int, "value")), False),
    ("SSL_alert_desc_string_long", libssl,
     ((c_char_p, "ret"), (c_int, "value")), False),
    ("SSL_CTX_set_cipher_list", libssl,
     ((c_int, "ret"), (SSLCTX, "ctx"), (c_char_p, "str"))),
    ("SSL_CTX_use_certificate_file", libssl,
     ((c_int, "ret"), (SSLCTX, "ctx"), (c_char_p, "file"), (c_int, "type"))),
    ("SSL_CTX_use_certificate_chain_file", libssl,
     ((c_int, "ret"), (SSLCTX, "ctx"), (c_char_p, "file"))),
    ("SSL_CTX_use_PrivateKey_file", libssl,
     ((c_int, "ret"), (SSLCTX, "ctx"), (c_char_p, "file"), (c_int, "type"))),
    ("SSL_CTX_load_verify_locations", libssl,
     ((c_int, "ret"), (SSLCTX, "ctx"), (c_char_p, "CAfile"), (c_char_p, "CApath"))),
    ("SSL_CTX_set_verify", libssl,
     ((None, "ret"), (SSLCTX, "ctx"), (c_int, "mode"), (c_void_p, "verify_callback", 1, None))),
    ("SSL_accept", libssl,
     ((c_int, "ret"), (SSL, "ssl"))),
    ("SSL_connect", libssl,
     ((c_int, "ret"), (SSL, "ssl"))),
    ("SSL_set_connect_state", libssl,
     ((None, "ret"), (SSL, "ssl"))),
    ("SSL_set_accept_state", libssl,
     ((None, "ret"), (SSL, "ssl"))),
    ("SSL_do_handshake", libssl,
     ((c_int, "ret"), (SSL, "ssl"))),
    ("SSL_get_peer_certificate", libssl,
     ((X509, "ret"), (SSL, "ssl"))),
    ("SSL_get_peer_cert_chain", libssl,
     ((STACK_OF_X509, "ret"), (SSL, "ssl")), False),
    ("SSL_read", libssl,
     ((c_int, "ret"), (SSL, "ssl"), (c_void_p, "buf"), (c_int, "num")), False),
    ("SSL_write", libssl,
     ((c_int, "ret"), (SSL, "ssl"), (c_void_p, "buf"), (c_int, "num")), False),
    ("SSL_pending", libssl,
     ((c_int, "ret"), (SSL, "ssl")), True, None),
    ("SSL_shutdown", libssl,
     ((c_int, "ret"), (SSL, "ssl"))),
    ("SSL_set_read_ahead", libssl,
     ((None, "ret"), (SSL, "ssl"), (c_int, "yes"))),
    ("X509_free", libcrypto,
     ((None, "ret"), (X509, "a"))),
    ("PEM_read_bio_X509_AUX", libcrypto,
     ((X509, "ret"), (BIO, "bp"), (c_void_p, "x", 1, None), (c_void_p, "cb", 1, None), (c_void_p, "u", 1, None))),
    ("OBJ_obj2txt", libcrypto,
     ((c_int, "ret"), (POINTER(c_char), "buf"), (c_int, "buf_len"), (ASN1_OBJECT, "a"), (c_int, "no_name")), False),
    ("OBJ_nid2sn", libcrypto,
     ((c_char_p, "ret"), (c_int, "n")), False),
    ("CRYPTO_free", libcrypto,
     ((None, "ret"), (c_void_p, "ptr"))),
    ("ASN1_STRING_to_UTF8", libcrypto,
     ((c_int, "ret"), (POINTER(POINTER(c_ubyte)), "out"), (ASN1_STRING, "in")), False),
    ("X509_NAME_entry_count", libcrypto,
     ((c_int, "ret"), (POINTER(X509_name_st), "name")), True, None),
    ("X509_NAME_get_entry", libcrypto,
     ((POINTER(X509_NAME_ENTRY), "ret"), (POINTER(X509_name_st), "name"),
      (c_int, "loc")), True, errcheck_p),
    ("X509_NAME_ENTRY_get_object", libcrypto,
     ((ASN1_OBJECT, "ret"), (POINTER(X509_NAME_ENTRY), "ne"))),
    ("X509_NAME_ENTRY_get_data", libcrypto,
     ((ASN1_STRING, "ret"), (POINTER(X509_NAME_ENTRY), "ne"))),
    ("X509_get_subject_name", libcrypto,
     ((POINTER(X509_name_st), "ret"), (X509, "a")), True, errcheck_p),
    ("ASN1_TIME_print", libcrypto,
     ((c_int, "ret"), (BIO, "fp"), (ASN1_TIME, "a")), False),
    ("X509_get_ext_by_NID", libcrypto,
     ((c_int, "ret"), (X509, "x"), (c_int, "nid"), (c_int, "lastpos")), True, None),
    ("X509_get_ext", libcrypto,
     ((POINTER(X509_EXTENSION), "ret"), (X509, "x"), (c_int, "loc")), True, errcheck_p),
    ("X509V3_EXT_get", libcrypto,
     ((POINTER(X509V3_EXT_METHOD), "ret"), (POINTER(X509_EXTENSION), "ext")), True, errcheck_p),
    ("ASN1_item_d2i", libcrypto,
     ((c_void_p, "ret"), (c_void_p, "val"), (POINTER(POINTER(c_ubyte)), "in"), (c_long, "len"), (c_void_p, "it")), False, None),
    ("sk_num", libcrypto,
     ((c_int, "ret"), (STACK, "stack")), True, None),
    ("sk_value", libcrypto,
     ((c_void_p, "ret"), (STACK, "stack"), (c_int, "loc")), False),
    ("GENERAL_NAME_print", libcrypto,
     ((c_int, "ret"), (BIO, "out"), (POINTER(GENERAL_NAME), "gen")), False),
    ("sk_pop_free", libcrypto,
     ((None, "ret"), (STACK, "st"), (c_void_p, "func")), False),
    ("i2d_X509_bio", libcrypto,
     ((c_int, "ret"), (BIO, "bp"), (X509, "x")), False),
    ("SSL_get_current_cipher", libssl,
     ((SSL_CIPHER, "ret"), (SSL, "ssl"))),
    ("SSL_CIPHER_get_name", libssl,
     ((c_char_p, "ret"), (SSL_CIPHER, "cipher"))),
    ("SSL_CIPHER_get_version", libssl,
     ((c_char_p, "ret"), (SSL_CIPHER, "cipher"))),
    ("SSL_CIPHER_get_bits", libssl,
     ((c_int, "ret"), (SSL_CIPHER, "cipher"), (POINTER(c_int), "alg_bits", 1, None)), True, None),
    ("EC_get_builtin_curves", libcrypto,
     ((c_int, "ret"), (POINTER(EC_builtin_curve), "r"), (c_int, "nitems"))),
    ("EC_KEY_new_by_curve_name", libcrypto,
     ((EC_KEY, "ret"), (c_int, "nid"))),
    ("EC_KEY_free", libcrypto,
     ((None, "ret"), (EC_KEY, "key"))),
    ("EC_curve_nist2nid", libcrypto,
     ((c_int, "ret"), (POINTER(c_char), "name")), True, None),
    ("EC_curve_nid2nist", libcrypto,
     ((c_char_p, "ret"), (c_int, "nid")), True, None),
    ))

#
# Wrappers - functions generally equivalent to OpenSSL library macros
#
_rvoid_int_int_charp_int = CFUNCTYPE(None, c_int, c_int, c_char_p, c_int)

def CRYPTO_set_locking_callback(locking_function):
    def py_locking_function(mode, n, file, line):
        try:
            locking_function(mode, n, file, line)
        except:
            _logger.exception("Thread locking failed")

    global _locking_cb  # for keep-alive
    _locking_cb = _rvoid_int_int_charp_int(py_locking_function)
    _CRYPTO_set_locking_callback(_locking_cb)

def SSL_CTX_set_session_cache_mode(ctx, mode):
    # Returns the previous value of mode
    return _SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_MODE, mode, None)

def SSL_CTX_set_read_ahead(ctx, m):
    # Returns the previous value of m
    return _SSL_CTX_ctrl(ctx, SSL_CTRL_SET_READ_AHEAD, m, None)

def SSL_CTX_set_options(ctx, options):
    # Returns the new option bitmaks after adding the given options
    return _SSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS, options, None)

def SSL_CTX_clear_options(ctx, options):
    return _SSL_CTX_ctrl(ctx, SSL_CTRL_CLEAR_OPTIONS, options, None)

def SSL_CTX_get_options(ctx):
    return _SSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS, 0, None)

def SSL_CTX_set1_client_sigalgs(ctx, slist, slistlen):
    _slist = (c_int * len(slist))(*slist)
    return _SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CLIENT_SIGALGS, len(_slist), _slist)

def SSL_CTX_set1_client_sigalgs_list(ctx, s):
    _s = cast(s, POINTER(c_char))
    return _SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CLIENT_SIGALGS_LIST, 0, _s)

def SSL_CTX_set1_sigalgs(ctx, slist, slistlen):
    _slist = (c_int * len(slist))(*slist)
    return _SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SIGALGS, len(_slist), _slist)

def SSL_CTX_set1_sigalgs_list(ctx, s):
    _s = cast(s, POINTER(c_char))
    return _SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SIGALGS_LIST, 0, _s)

def SSL_CTX_set1_curves(ctx, clist, clistlen):
    _curves = (c_int * len(clist))(*clist)
    return _SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CURVES, len(_curves), _curves)

def SSL_CTX_set1_curves_list(ctx, s):
    _s = cast(s, POINTER(c_char))
    return _SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CURVES_LIST, 0, _s)

_rvoid_voidp_int_int = CFUNCTYPE(None, c_void_p, c_int, c_int)

_info_callback = dict()

def SSL_CTX_set_info_callback(ctx, app_info_cb):
    """
    Set the info callback

    :param callback: The Python callback to use
    :return: None
    """
    def py_info_callback(ssl, where, ret):
        try:
            app_info_cb(SSL(ssl), where, ret)
        except:
            pass
        return

    global _info_callback
    _info_callback[ctx] = _rvoid_voidp_int_int(py_info_callback)
    _SSL_CTX_set_info_callback(ctx, _info_callback[ctx])

def SSL_CTX_build_cert_chain(ctx, flags):
    return _SSL_CTX_ctrl(ctx, SSL_CTRL_BUILD_CERT_CHAIN, flags, None)

def SSL_CTX_set_ecdh_auto(ctx, onoff):
    return _SSL_CTX_ctrl(ctx, SSL_CTRL_SET_ECDH_AUTO, onoff, None)

def SSL_CTX_set_tmp_ecdh(ctx, ec_key):
    # return 1 on success and 0 on failure
    _ec_key_p = cast(ec_key.raw, c_void_p)
    return _SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_ECDH, 0, _ec_key_p)

_rint_voidp_ubytep_uintp = CFUNCTYPE(c_int, c_void_p, POINTER(c_ubyte),
                                     POINTER(c_uint))
_rint_voidp_ubytep_uint = CFUNCTYPE(c_int, c_void_p, POINTER(c_ubyte), c_uint)

def SSL_CTX_set_cookie_cb(ctx, generate, verify):
    def py_generate_cookie_cb(ssl, cookie, cookie_len):
        try:
            ret_cookie = generate(SSL(ssl))
        except:
            _logger.exception("Cookie generation failed")
            return 0
        cookie_len[0] = len(ret_cookie)
        memmove(cookie, ret_cookie, cookie_len[0])
        _logger.debug("Returning cookie: %s", cookie[:cookie_len[0]])
        return 1

    def py_verify_cookie_cb(ssl, cookie, cookie_len):
        _logger.debug("Verifying cookie: %s", cookie[:cookie_len])
        try:
            verify(SSL(ssl), ''.join([chr(i) for i in cookie[:cookie_len]]))
        except:
            _logger.debug("Cookie verification failed")
            return 0
        return 1

    gen_cb = _rint_voidp_ubytep_uintp(py_generate_cookie_cb)
    ver_cb = _rint_voidp_ubytep_uint(py_verify_cookie_cb)
    _SSL_CTX_set_cookie_generate_cb(ctx, gen_cb)
    _SSL_CTX_set_cookie_verify_cb(ctx, ver_cb)
    return gen_cb, ver_cb

def BIO_dgram_set_connected(bio, peer_address):
    su = sockaddr_u_from_addr_tuple(peer_address)
    return _BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, byref(su))

def BIO_dgram_get_peer(bio):
    su = sockaddr_u()
    _BIO_ctrl(bio, BIO_CTRL_DGRAM_GET_PEER, 0, byref(su))
    return addr_tuple_from_sockaddr_u(su)

def BIO_dgram_set_peer(bio, peer_address):
    su = sockaddr_u_from_addr_tuple(peer_address)
    return _BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_PEER, 0, byref(su))

def BIO_set_nbio(bio, n):
    return _BIO_ctrl(bio, BIO_C_SET_NBIO, 1 if n else 0, None)

def DTLSv1_get_timeout(ssl):
    tv = TIMEVAL()
    ret = _SSL_ctrl(ssl, DTLS_CTRL_GET_TIMEOUT, 0, byref(tv))
    if ret != 1:
        return
    return timedelta(seconds=tv.tv_sec, microseconds=tv.tv_usec)

def DTLSv1_handle_timeout(ssl):
    ret = _SSL_ctrl(ssl, DTLS_CTRL_HANDLE_TIMEOUT, 0, None)
    if ret == 0:
        # It was too early to call: no timer had yet expired
        return False
    if ret == 1:
        # Buffered messages were retransmitted
        return True
    # There was an error: either too many timeouts have occurred or a
    # retransmission failed
    assert ret < 0
    if ret > 0:
        ret = -10
    return errcheck_p(ret, _SSL_ctrl, (ssl, DTLS_CTRL_HANDLE_TIMEOUT, 0, None))

def DTLSv1_listen(ssl):
    su = sockaddr_u()
    ret = _SSL_ctrl(ssl, DTLS_CTRL_LISTEN, 0, byref(su))
    errcheck_ord(ret, _SSL_ctrl, (ssl, DTLS_CTRL_LISTEN, 0, byref(su)))
    return addr_tuple_from_sockaddr_u(su)

def DTLS_set_link_mtu(ssl, mtu):
    return _SSL_ctrl(ssl, DTLS_CTRL_SET_LINK_MTU, mtu, None)

def SSL_read(ssl, length, buffer):
    if buffer:
        length = min(length, len(buffer))
        buf = (c_char * length).from_buffer(buffer)
    else:
        buf = create_string_buffer(length)
    res_len = _SSL_read(ssl, buf, length)
    if buffer:
        return res_len
    return buf.raw[:res_len]

def SSL_write(ssl, data):
    if isinstance(data, str):
        str_data = data
    elif hasattr(data, "tobytes") and callable(data.tobytes):
        str_data = data.tobytes()
    elif isinstance(data, ctypes.Array):
        str_data = data.raw
    else:
        str_data = str(data)
    return _SSL_write(ssl, str_data, len(str_data))

def SSL_set_options(ssl, op):
    return _SSL_ctrl(ssl, SSL_CTRL_OPTIONS, op, None)

def SSL_clear_options(ssl, op):
    return _SSL_ctrl(ssl, SSL_CTRL_CLEAR_OPTIONS, op, None)

def SSL_get_options(ssl):
    return _SSL_ctrl(ssl, SSL_CTRL_OPTIONS, 0, None)

def SSL_set1_client_sigalgs(ssl, slist, slistlen):
    _slist = (c_int * len(slist))(*slist)
    return _SSL_ctrl(ssl, SSL_CTRL_SET_CLIENT_SIGALGS, len(_slist), _slist)

def SSL_set1_client_sigalgs_list(ssl, s):
    _s = cast(s, POINTER(c_char))
    return _SSL_ctrl(ssl, SSL_CTRL_SET_CLIENT_SIGALGS_LIST, 0, _s)

def SSL_set1_sigalgs(ssl, slist, slistlen):
    _slist = (c_int * len(slist))(*slist)
    return _SSL_ctrl(ssl, SSL_CTRL_SET_SIGALGS, len(_slist), _slist)

def SSL_set1_sigalgs_list(ssl, s):
    _s = cast(s, POINTER(c_char))
    return _SSL_ctrl(ssl, SSL_CTRL_SET_SIGALGS_LIST, 0, _s)

def SSL_get1_curves(ssl, curves=None):
    assert curves is None or isinstance(curves, list)
    if curves is not None:
        cnt = SSL_get1_curves(ssl, None)
        if cnt:
            mem = create_string_buffer(sizeof(POINTER(c_int)) * cnt)
            _SSL_ctrl(ssl, SSL_CTRL_GET_CURVES, 0, mem)
            for x in cast(mem, POINTER(c_int))[:cnt]:
                curves.append(x)
        return cnt
    else:
        return _SSL_ctrl(ssl, SSL_CTRL_GET_CURVES, 0, None)

def SSL_get_shared_curve(ssl, n):
    return _SSL_ctrl(ssl, SSL_CTRL_GET_SHARED_CURVE, n, 0)

def SSL_set1_curves(ssl, clist, clistlen):
    _curves = (c_int * len(clist))(*clist)
    return _SSL_ctrl(ssl, SSL_CTRL_SET_CURVES, len(_curves), _curves)

def SSL_set1_curves_list(ssl, s):
    _s = cast(s, POINTER(c_char))
    return _SSL_ctrl(ssl, SSL_CTRL_SET_CURVES_LIST, 0, _s)

def SSL_set_mtu(ssl, mtu):
    return _SSL_ctrl(ssl, SSL_CTRL_SET_MTU, mtu, None)

def SSL_state_string_long(ssl):
    try:
        ret = _SSL_state_string_long(ssl)
    except:
        pass
    return ret

def SSL_alert_type_string_long(value):
    try:
        ret = _SSL_alert_type_string_long(value)
    except:
        pass
    return ret

def SSL_alert_desc_string_long(value):
    try:
        ret = _SSL_alert_desc_string_long(value)
    except:
        pass
    return ret

def OBJ_obj2txt(asn1_object, no_name):
    buf = create_string_buffer(X509_NAME_MAXLEN)
    res_len = _OBJ_obj2txt(buf, sizeof(buf), asn1_object, 1 if no_name else 0)
    return buf.raw[:res_len]

def OBJ_nid2sn(nid):
    _name = _OBJ_nid2sn(nid)
    return cast(_name, c_char_p).value.decode("ascii")

def decode_ASN1_STRING(asn1_string):
    utf8_buf_ptr = POINTER(c_ubyte)()
    res_len = _ASN1_STRING_to_UTF8(byref(utf8_buf_ptr), asn1_string)
    try:
        return unicode(''.join([chr(i) for i in utf8_buf_ptr[:res_len]]),
                       'utf-8')
    finally:
        CRYPTO_free(utf8_buf_ptr)

def X509_get_notAfter(x509):
    x509_raw = X509.from_param(x509)
    x509_ptr = cast(x509_raw, POINTER(X509_st))
    notAfter = x509_ptr.contents.cert_info.contents.validity.contents.notAfter
    return ASN1_TIME(notAfter)

def BIO_gets(bio):
    buf = create_string_buffer(GETS_MAXLEN)
    res_len = _BIO_gets(bio, buf, sizeof(buf) - 1)
    return buf.raw[:res_len]

def BIO_read(bio, length):
    buf = create_string_buffer(length)
    res_len = _BIO_read(bio, buf, sizeof(buf))
    return buf.raw[:res_len]

def BIO_get_mem_data(bio):
    buf = POINTER(c_ubyte)()
    res_len = _BIO_ctrl(bio, BIO_CTRL_INFO, 0, byref(buf))
    return ''.join([chr(i) for i in buf[:res_len]])

def ASN1_TIME_print(asn1_time):
    bio = _BIO(BIO_new(BIO_s_mem()))
    _ASN1_TIME_print(bio.value, asn1_time)
    return BIO_gets(bio.value)

_rvoidp = CFUNCTYPE(c_void_p)

def _ASN1_ITEM_ptr(item):
    if sys.platform.startswith('win'):
        func_ptr = _rvoidp(item)
        return func_ptr()
    return item

_rvoidp_voidp_ubytepp_long = CFUNCTYPE(c_void_p, c_void_p,
                                       POINTER(POINTER(c_ubyte)), c_long)

def ASN1_item_d2i(method, asn1_octet_string):
    data_in = POINTER(c_ubyte)(asn1_octet_string.data.contents)
    if method.it:
        return GENERAL_NAMES(_ASN1_item_d2i(None, byref(data_in),
                                            asn1_octet_string.length,
                                            _ASN1_ITEM_ptr(method.it)))
    func_ptr = _rvoidp_voidp_ubytepp_long(method.d2i)
    return GENERAL_NAMES(func_ptr(None, byref(data_in),
                                  asn1_octet_string.length))

def sk_value(stack, loc):
    return cast(_sk_value(stack, loc), POINTER(stack.stack_element_type))

def GENERAL_NAME_print(general_name):
    bio = _BIO(BIO_new(BIO_s_mem()))
    _GENERAL_NAME_print(bio.value, general_name)
    return BIO_gets(bio.value)

_free_func = addressof(c_void_p.in_dll(libcrypto, "sk_free"))

def sk_pop_free(stack):
    _sk_pop_free(stack, _free_func)

def i2d_X509(x509):
    bio = _BIO(BIO_new(BIO_s_mem()))
    _i2d_X509_bio(bio.value, x509)
    return BIO_get_mem_data(bio.value)

def SSL_get_peer_cert_chain(ssl):
    stack = _SSL_get_peer_cert_chain(ssl)
    num = sk_num(stack)
    certs = []
    if num:
        # why not use sk_value(): because it doesn't cast correct in this case?!
        # certs = [(sk_value(stack, i)) for i in xrange(num)]
        certs = [X509(_sk_value(stack, i)) for i in xrange(num)]
    return stack, num, certs
