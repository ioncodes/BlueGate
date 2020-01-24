# Patch: patching of the Python stadard library's ssl module for transparent
# use of datagram sockets.

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

"""Patch

This module is used to patch the Python standard library's ssl module. Patching
has the following effects:

    * The constant PROTOCOL_DTLSv1 is added at ssl module level
    * DTLSv1's protocol name is added to the ssl module's id-to-name dictionary
    * The constants DTLS_OPENSSL_VERSION* are added at the ssl module level
    * Instantiation of ssl.SSLSocket with sock.type == socket.SOCK_DGRAM is
      supported and leads to substitution of this module's DTLS code paths for
      that SSLSocket instance
    * Direct instantiation of SSLSocket as well as instantiation through
      ssl.wrap_socket are supported
    * Invocation of the function get_server_certificate with a value of
      PROTOCOL_DTLSv1 for the parameter ssl_version is supported
"""

from socket import socket, getaddrinfo, _delegate_methods, error as socket_error
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM
from ssl import PROTOCOL_SSLv23, CERT_NONE
from types import MethodType
from weakref import proxy
import errno

from sslconnection import SSLConnection, PROTOCOL_DTLS, PROTOCOL_DTLSv1, PROTOCOL_DTLSv1_2
from sslconnection import DTLS_OPENSSL_VERSION_NUMBER, DTLS_OPENSSL_VERSION, DTLS_OPENSSL_VERSION_INFO
from sslconnection import SSL_BUILD_CHAIN_FLAG_NONE, SSL_BUILD_CHAIN_FLAG_UNTRUSTED, \
    SSL_BUILD_CHAIN_FLAG_NO_ROOT, SSL_BUILD_CHAIN_FLAG_CHECK, SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR, SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR
from err import raise_as_ssl_module_error, patch_ssl_errors


def do_patch():
    import ssl as _ssl  # import to be avoided if ssl module is never patched
    global _orig_SSLSocket_init, _orig_get_server_certificate
    global ssl
    ssl = _ssl
    if hasattr(ssl, "PROTOCOL_DTLSv1"):
        return
    _orig_wrap_socket = ssl.wrap_socket
    ssl.wrap_socket = _wrap_socket
    ssl.PROTOCOL_DTLS = PROTOCOL_DTLS
    ssl.PROTOCOL_DTLSv1 = PROTOCOL_DTLSv1
    ssl.PROTOCOL_DTLSv1_2 = PROTOCOL_DTLSv1_2
    ssl._PROTOCOL_NAMES[PROTOCOL_DTLS] = "DTLS"
    ssl._PROTOCOL_NAMES[PROTOCOL_DTLSv1] = "DTLSv1"
    ssl._PROTOCOL_NAMES[PROTOCOL_DTLSv1_2] = "DTLSv1.2"
    ssl.DTLS_OPENSSL_VERSION_NUMBER = DTLS_OPENSSL_VERSION_NUMBER
    ssl.DTLS_OPENSSL_VERSION = DTLS_OPENSSL_VERSION
    ssl.DTLS_OPENSSL_VERSION_INFO = DTLS_OPENSSL_VERSION_INFO
    ssl.SSL_BUILD_CHAIN_FLAG_NONE = SSL_BUILD_CHAIN_FLAG_NONE
    ssl.SSL_BUILD_CHAIN_FLAG_UNTRUSTED = SSL_BUILD_CHAIN_FLAG_UNTRUSTED
    ssl.SSL_BUILD_CHAIN_FLAG_NO_ROOT = SSL_BUILD_CHAIN_FLAG_NO_ROOT
    ssl.SSL_BUILD_CHAIN_FLAG_CHECK = SSL_BUILD_CHAIN_FLAG_CHECK
    ssl.SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR = SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR
    ssl.SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR = SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR
    _orig_SSLSocket_init = ssl.SSLSocket.__init__
    _orig_get_server_certificate = ssl.get_server_certificate
    ssl.SSLSocket.__init__ = _SSLSocket_init
    ssl.get_server_certificate = _get_server_certificate
    patch_ssl_errors()
    raise_as_ssl_module_error()

def _wrap_socket(sock, keyfile=None, certfile=None,
                 server_side=False, cert_reqs=CERT_NONE,
                 ssl_version=PROTOCOL_DTLS, ca_certs=None,
                 do_handshake_on_connect=True,
                 suppress_ragged_eofs=True,
                 ciphers=None,
                 cb_user_config_ssl_ctx=None,
                 cb_user_config_ssl=None):

    return ssl.SSLSocket(sock, keyfile=keyfile, certfile=certfile,
                         server_side=server_side, cert_reqs=cert_reqs,
                         ssl_version=ssl_version, ca_certs=ca_certs,
                         do_handshake_on_connect=do_handshake_on_connect,
                         suppress_ragged_eofs=suppress_ragged_eofs,
                         ciphers=ciphers,
                         cb_user_config_ssl_ctx=cb_user_config_ssl_ctx,
                         cb_user_config_ssl=cb_user_config_ssl)

def _get_server_certificate(addr, ssl_version=PROTOCOL_SSLv23, ca_certs=None):
    """Retrieve a server certificate

    Retrieve the certificate from the server at the specified address,
    and return it as a PEM-encoded string.
    If 'ca_certs' is specified, validate the server cert against it.
    If 'ssl_version' is specified, use it in the connection attempt.
    """

    if ssl_version not in (PROTOCOL_DTLS, PROTOCOL_DTLSv1, PROTOCOL_DTLSv1_2):
        return _orig_get_server_certificate(addr, ssl_version, ca_certs)

    if ca_certs is not None:
        cert_reqs = ssl.CERT_REQUIRED
    else:
        cert_reqs = ssl.CERT_NONE
    af = getaddrinfo(addr[0], addr[1])[0][0]
    s = ssl.wrap_socket(socket(af, SOCK_DGRAM),
                        ssl_version=ssl_version,
                        cert_reqs=cert_reqs, ca_certs=ca_certs)
    s.connect(addr)
    dercert = s.getpeercert(True)
    s.close()
    return ssl.DER_cert_to_PEM_cert(dercert)

def _SSLSocket_init(self, sock=None, keyfile=None, certfile=None,
                    server_side=False, cert_reqs=CERT_NONE,
                    ssl_version=PROTOCOL_DTLS, ca_certs=None,
                    do_handshake_on_connect=True,
                    family=AF_INET, type=SOCK_STREAM, proto=0, fileno=None,
                    suppress_ragged_eofs=True, npn_protocols=None, ciphers=None,
                    server_hostname=None,
                    _context=None,
                    cb_user_config_ssl_ctx=None,
                    cb_user_config_ssl=None):
    is_connection = is_datagram = False
    if isinstance(sock, SSLConnection):
        is_connection = True
    elif hasattr(sock, "type") and sock.type == SOCK_DGRAM:
        is_datagram = True
    if not is_connection and not is_datagram:
        # Non-DTLS code path
        return _orig_SSLSocket_init(self, sock=sock, keyfile=keyfile,
                                    certfile=certfile, server_side=server_side,
                                    cert_reqs=cert_reqs,
                                    ssl_version=ssl_version, ca_certs=ca_certs,
                                    do_handshake_on_connect=
                                    do_handshake_on_connect,
                                    family=family, type=type, proto=proto,
                                    fileno=fileno,
                                    suppress_ragged_eofs=suppress_ragged_eofs,
                                    npn_protocols=npn_protocols,
                                    ciphers=ciphers,
                                    server_hostname=server_hostname,
                                    _context=_context)
    # DTLS code paths: datagram socket and newly accepted DTLS connection
    if is_datagram:
        socket.__init__(self, _sock=sock._sock)
    else:
        socket.__init__(self, _sock=sock.get_socket(True)._sock)
    # Copy instance initialization from SSLSocket class
    for attr in _delegate_methods:
        try:
            delattr(self, attr)
        except AttributeError:
            pass

    if certfile and not keyfile:
        keyfile = certfile
    if is_datagram:
        # see if it's connected
        try:
            socket.getpeername(self)
        except socket_error, e:
            if e.errno != errno.ENOTCONN:
                raise
            # no, no connection yet
            self._connected = False
            self._sslobj = None
        else:
            # yes, create the SSL object
            self._connected = True
            self._sslobj = SSLConnection(sock, keyfile, certfile,
                                         server_side, cert_reqs,
                                         ssl_version, ca_certs,
                                         do_handshake_on_connect,
                                         suppress_ragged_eofs, ciphers,
                                         cb_user_config_ssl_ctx=cb_user_config_ssl_ctx,
                                         cb_user_config_ssl=cb_user_config_ssl)
    else:
        self._connected = True
        self._sslobj = sock

    class FakeContext(object):
        check_hostname = False

    self._context = FakeContext()
    self.keyfile = keyfile
    self.certfile = certfile
    self.cert_reqs = cert_reqs
    self.ssl_version = ssl_version
    self.ca_certs = ca_certs
    self.ciphers = ciphers
    self.do_handshake_on_connect = do_handshake_on_connect
    self.suppress_ragged_eofs = suppress_ragged_eofs
    self._makefile_refs = 0
    self._user_config_ssl_ctx = cb_user_config_ssl_ctx
    self._user_config_ssl = cb_user_config_ssl

    # Perform method substitution and addition (without reference cycle)
    self._real_connect = MethodType(_SSLSocket_real_connect, proxy(self))
    self.listen = MethodType(_SSLSocket_listen, proxy(self))
    self.accept = MethodType(_SSLSocket_accept, proxy(self))
    self.get_timeout = MethodType(_SSLSocket_get_timeout, proxy(self))
    self.handle_timeout = MethodType(_SSLSocket_handle_timeout, proxy(self))

    # Extra
    self.getpeercertchain = MethodType(_getpeercertchain, proxy(self))

def _getpeercertchain(self, binary_form=False):
    return self._sslobj.getpeercertchain(binary_form)

def _SSLSocket_listen(self, ignored):
    if self._connected:
        raise ValueError("attempt to listen on connected SSLSocket!")
    if self._sslobj:
        return
    self._sslobj = SSLConnection(socket(_sock=self._sock),
                                 self.keyfile, self.certfile, True,
                                 self.cert_reqs, self.ssl_version,
                                 self.ca_certs,
                                 self.do_handshake_on_connect,
                                 self.suppress_ragged_eofs, self.ciphers,
                                 cb_user_config_ssl_ctx=self._user_config_ssl_ctx,
                                 cb_user_config_ssl=self._user_config_ssl)

def _SSLSocket_accept(self):
    if self._connected:
        raise ValueError("attempt to accept on connected SSLSocket!")
    if not self._sslobj:
        raise ValueError("attempt to accept on SSLSocket prior to listen!")
    acc_ret = self._sslobj.accept()
    if not acc_ret:
        return
    new_conn, addr = acc_ret
    new_ssl_sock = ssl.SSLSocket(new_conn, self.keyfile, self.certfile, True,
                                 self.cert_reqs, self.ssl_version,
                                 self.ca_certs,
                                 self.do_handshake_on_connect,
                                 self.suppress_ragged_eofs, self.ciphers,
                                 cb_user_config_ssl_ctx=self._user_config_ssl_ctx,
                                 cb_user_config_ssl=self._user_config_ssl)
    return new_ssl_sock, addr

def _SSLSocket_real_connect(self, addr, return_errno):
    if self._connected:
        raise ValueError("attempt to connect already-connected SSLSocket!")
    self._sslobj = SSLConnection(socket(_sock=self._sock),
                                 self.keyfile, self.certfile, False,
                                 self.cert_reqs, self.ssl_version,
                                 self.ca_certs,
                                 self.do_handshake_on_connect,
                                 self.suppress_ragged_eofs, self.ciphers,
                                 cb_user_config_ssl_ctx=self._user_config_ssl_ctx,
                                 cb_user_config_ssl=self._user_config_ssl)
    try:
        self._sslobj.connect(addr)
    except socket_error as e:
        if return_errno:
            return e.errno
        else:
            self._sslobj = None
            raise e
    self._connected = True
    return 0


if __name__ == "__main__":
    do_patch()

def _SSLSocket_get_timeout(self):
    return self._sslobj.get_timeout()

def _SSLSocket_handle_timeout(self):
    return self._sslobj.handle_timeout()
