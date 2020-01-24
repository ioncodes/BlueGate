# SSL connection: state and behavior associated with the connection between
# the OpenSSL library and an individual peer.

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

"""SSL Connection

This module encapsulates the state and behavior associated with the connection
between the OpenSSL library and an individual peer when using the DTLS
protocol. It defines the application side of the interface of a client with a
DTLS server, and of a server with a DTLS client.

Classes:

  SSLConnection -- DTLS peer association

Integer constants:

  PROTOCOL_DTLSv1

The cert group must coincide in meaning and value with the one of the standard
library's ssl module, since its values can be passed to this module.

  CERT_NONE
  CERT_OPTIONAL
  CERT_REQUIRED
"""

import sys
import errno
import socket
import hmac
import datetime
from logging import getLogger
from os import urandom
from select import select
from weakref import proxy

from err import openssl_error, InvalidSocketError
from err import raise_ssl_error
from err import SSL_ERROR_WANT_READ, SSL_ERROR_SYSCALL
from err import ERR_WRONG_VERSION_NUMBER, ERR_COOKIE_MISMATCH, ERR_NO_SHARED_CIPHER
from err import ERR_NO_CIPHER, ERR_HANDSHAKE_TIMEOUT, ERR_PORT_UNREACHABLE
from err import ERR_READ_TIMEOUT, ERR_WRITE_TIMEOUT
from err import ERR_BOTH_KEY_CERT_FILES, ERR_BOTH_KEY_CERT_FILES_SVR, ERR_NO_CERTS
from x509 import _X509, decode_cert
from tlock import tlock_init
from openssl import *
from util import _Rsrc, _BIO

_logger = getLogger(__name__)

PROTOCOL_DTLSv1 = 256
PROTOCOL_DTLSv1_2 = 258
PROTOCOL_DTLS = 259
CERT_NONE = 0
CERT_OPTIONAL = 1
CERT_REQUIRED = 2

#
# One-time global OpenSSL library initialization
#
SSL_library_init()
SSL_load_error_strings()
tlock_init()
DTLS_OPENSSL_VERSION_NUMBER = SSLeay()
DTLS_OPENSSL_VERSION = SSLeay_version(SSLEAY_VERSION)
DTLS_OPENSSL_VERSION_INFO = (
    DTLS_OPENSSL_VERSION_NUMBER >> 28 & 0xFF,  # major
    DTLS_OPENSSL_VERSION_NUMBER >> 20 & 0xFF,  # minor
    DTLS_OPENSSL_VERSION_NUMBER >> 12 & 0xFF,  # fix
    DTLS_OPENSSL_VERSION_NUMBER >> 4  & 0xFF,  # patch
    DTLS_OPENSSL_VERSION_NUMBER       & 0xF)   # status


def _ssl_logging_cb(conn, where, return_code):
    _state = where & ~SSL_ST_MASK
    state = "SSL"
    if _state & SSL_ST_INIT == SSL_ST_INIT:
        if _state & SSL_ST_RENEGOTIATE == SSL_ST_RENEGOTIATE:
            state += "_renew"
        else:
            state += "_init"
    elif _state & SSL_ST_CONNECT:
        state += "_connect"
    elif _state & SSL_ST_ACCEPT:
        state += "_accept"
    elif _state == 0:
        if where & SSL_CB_HANDSHAKE_START:
            state += "_handshake_start"
        elif where & SSL_CB_HANDSHAKE_DONE:
            state += "_handshake_done"

    if where & SSL_CB_LOOP:
        state += '_loop'
        _logger.debug("%s:%s:%d" % (state,
                                    SSL_state_string_long(conn),
                                    return_code))

    elif where & SSL_CB_ALERT:
        state += '_alert'
        state += "_read" if where & SSL_CB_READ else "_write"
        _logger.debug("%s:%s:%s" % (state,
                                    SSL_alert_type_string_long(return_code),
                                    SSL_alert_desc_string_long(return_code)))

    elif where & SSL_CB_EXIT:
        state += '_exit'
        if return_code == 0:
            _logger.debug("%s:%s:%d(failed)" % (state,
                                                SSL_state_string_long(conn),
                                                return_code))
        elif return_code < 0:
            _logger.debug("%s:%s:%d(error)" % (state,
                                               SSL_state_string_long(conn),
                                               return_code))
        else:
            _logger.debug("%s:%s:%d" % (state,
                                        SSL_state_string_long(conn),
                                        return_code))

    else:
        _logger.debug("%s:%s:%d" % (state,
                                    SSL_state_string_long(conn),
                                    return_code))


class _CTX(_Rsrc):
    """SSL_CTX wrapper"""
    def __init__(self, value):
        super(_CTX, self).__init__(value)

    def __del__(self):
        _logger.debug("Freeing SSL CTX: %d", self.raw)
        SSL_CTX_free(self._value)
        self._value = None


class _SSL(_Rsrc):
    """SSL structure wrapper"""
    def __init__(self, value):
        super(_SSL, self).__init__(value)

    def __del__(self):
        _logger.debug("Freeing SSL: %d", self.raw)
        SSL_free(self._value)
        self._value = None


class _CallbackProxy(object):
    """Callback gateway to an SSLConnection object

    This class forms a weak connection between a callback method and
    an SSLConnection object. It can be passed as a callback callable
    without creating a strong reference through bound methods of
    the SSLConnection.
    """

    def __init__(self, cbm):
        self.ssl_connection = proxy(cbm.im_self)
        self.ssl_func = cbm.im_func

    def __call__(self, *args, **kwargs):
        return self.ssl_func(self.ssl_connection, *args, **kwargs)


class SSLContext(object):

    def __init__(self, ctx):
        self._ctx = ctx

    def set_ciphers(self, ciphers):
        u'''
        s.a. https://www.openssl.org/docs/man1.1.0/apps/ciphers.html

        :param str ciphers: Example "AES256-SHA:ECDHE-ECDSA-AES256-SHA", ...
        :return: 1 for success and 0 for failure
        '''
        retVal = SSL_CTX_set_cipher_list(self._ctx, ciphers)
        return retVal

    def set_sigalgs(self, sigalgs):
        u'''
        s.a. https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_set1_sigalgs_list.html

        :param str sigalgs: Example "RSA+SHA256", "ECDSA+SHA256", ...
        :return: 1 for success and 0 for failure
        '''
        retVal = SSL_CTX_set1_sigalgs_list(self._ctx, sigalgs)
        return retVal

    def set_curves(self, curves):
        u''' Set supported curves by name, nid or nist.

        :param str | tuple(int) curves: Example "secp384r1:secp256k1", (715, 714), "P-384", "K-409:B-409:K-571", ...
        :return: 1 for success and 0 for failure
        '''
        retVal = None
        if isinstance(curves, str):
            retVal = SSL_CTX_set1_curves_list(self._ctx, curves)
        elif isinstance(curves, tuple):
            retVal = SSL_CTX_set1_curves(self._ctx, curves, len(curves))
        return retVal

    @staticmethod
    def get_ec_nist2nid(nist):
        if not isinstance(nist, tuple):
            nist = nist.split(":")
        nid = tuple(EC_curve_nist2nid(x) for x in nist)
        return nid

    @staticmethod
    def get_ec_nid2nist(nid):
        if not isinstance(nid, tuple):
            nid = (nid, )
        nist = ":".join([EC_curve_nid2nist(x) for x in nid])
        return nist

    @staticmethod
    def get_ec_available(bAsName=True):
        curves = get_elliptic_curves()
        return sorted([x.name for x in curves] if bAsName else [x.nid for x in curves])

    def set_ecdh_curve(self, curve_name=None):
        u''' Select a curve to use for ECDH(E) key exchange or set it to auto mode

        Used for server only!

        s.a. openssl.exe ecparam -list_curves

        :param None | str curve_name: None = Auto-mode, "secp256k1", "secp384r1", ...
        :return: 1 for success and 0 for failure
        '''
        if curve_name:
            retVal = SSL_CTX_set_ecdh_auto(self._ctx, 0)
            avail_curves = get_elliptic_curves()
            key = [curve for curve in avail_curves if curve.name == curve_name][0].to_EC_KEY()
            retVal &= SSL_CTX_set_tmp_ecdh(self._ctx, key)
        else:
            retVal = SSL_CTX_set_ecdh_auto(self._ctx, 1)
        return retVal

    def build_cert_chain(self, flags=SSL_BUILD_CHAIN_FLAG_NONE):
        u'''
        Used for server side only!

        :param flags:
        :return: 1 for success and 0 for failure
        '''
        retVal = SSL_CTX_build_cert_chain(self._ctx, flags)
        return retVal

    def set_ssl_logging(self, enable=False, func=_ssl_logging_cb):
        u''' Enable or disable SSL logging

        :param True | False enable: Enable or disable SSL logging
        :param func: Callback function for logging
        '''
        if enable:
            SSL_CTX_set_info_callback(self._ctx, func)
        else:
            SSL_CTX_set_info_callback(self._ctx, 0)


class SSL(object):

    def __init__(self, ssl):
        self._ssl = ssl

    def set_mtu(self, mtu=None):
        if mtu:
            SSL_set_options(self._ssl, SSL_OP_NO_QUERY_MTU)
            SSL_set_mtu(self._ssl, mtu)
        else:
            SSL_clear_options(self._ssl, SSL_OP_NO_QUERY_MTU)

    def set_link_mtu(self, mtu=None):
        if mtu:
            SSL_set_options(self._ssl, SSL_OP_NO_QUERY_MTU)
            DTLS_set_link_mtu(self._ssl, mtu)
        else:
            SSL_clear_options(self._ssl, SSL_OP_NO_QUERY_MTU)


class SSLConnection(object):
    """DTLS peer association

    This class associates two DTLS peer instances, wrapping OpenSSL library
    state including SSL (struct ssl_st), SSL_CTX, and BIO instances.
    """

    _rnd_key = urandom(16)

    def _init_server(self, peer_address):
        if self._sock.type != socket.SOCK_DGRAM:
            raise InvalidSocketError("sock must be of type SOCK_DGRAM")

        self._wbio = _BIO(BIO_new_dgram(self._sock.fileno(), BIO_NOCLOSE))
        if peer_address:
            # Connect directly to this client peer, bypassing the demux
            rsock = self._sock
            BIO_dgram_set_connected(self._wbio.value, peer_address)
        else:
            from demux import UDPDemux
            self._udp_demux = UDPDemux(self._sock)
            rsock = self._udp_demux.get_connection(None)
        if rsock is self._sock:
            self._rbio = self._wbio
        else:
            self._rsock = rsock
            self._rbio = _BIO(BIO_new_dgram(self._rsock.fileno(), BIO_NOCLOSE))
        server_method = DTLS_server_method
        if self._ssl_version == PROTOCOL_DTLSv1_2:
            server_method = DTLSv1_2_server_method
        elif self._ssl_version == PROTOCOL_DTLSv1:
            server_method = DTLSv1_server_method
        self._ctx = _CTX(SSL_CTX_new(server_method()))
        self._intf_ssl_ctx = SSLContext(self._ctx.value)
        SSL_CTX_set_session_cache_mode(self._ctx.value, SSL_SESS_CACHE_OFF)
        if self._cert_reqs == CERT_NONE:
            verify_mode = SSL_VERIFY_NONE
        elif self._cert_reqs == CERT_OPTIONAL:
            verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE
        else:
            verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE | \
              SSL_VERIFY_FAIL_IF_NO_PEER_CERT
        self._config_ssl_ctx(verify_mode)
        if not peer_address:
            # Configure UDP listening socket
            self._listening = False
            self._listening_peer_address = None
            self._pending_peer_address = None
            self._cb_keepalive = SSL_CTX_set_cookie_cb(
                self._ctx.value,
                _CallbackProxy(self._generate_cookie_cb),
                _CallbackProxy(self._verify_cookie_cb))
        self._ssl = _SSL(SSL_new(self._ctx.value))
        self._intf_ssl = SSL(self._ssl.value)
        SSL_set_accept_state(self._ssl.value)
        if peer_address and self._do_handshake_on_connect:
            return lambda: self.do_handshake()

    def _init_client(self, peer_address):
        if self._sock.type != socket.SOCK_DGRAM:
            raise InvalidSocketError("sock must be of type SOCK_DGRAM")

        self._wbio = _BIO(BIO_new_dgram(self._sock.fileno(), BIO_NOCLOSE))
        self._rbio = self._wbio
        client_method = DTLSv1_2_client_method  # no "any" exists, therefore use v1_2 (highest possible)
        if self._ssl_version == PROTOCOL_DTLSv1_2:
            client_method = DTLSv1_2_client_method
        elif self._ssl_version == PROTOCOL_DTLSv1:
            client_method = DTLSv1_client_method
        self._ctx = _CTX(SSL_CTX_new(client_method()))
        self._intf_ssl_ctx = SSLContext(self._ctx.value)
        if self._cert_reqs == CERT_NONE:
            verify_mode = SSL_VERIFY_NONE
        else:
            verify_mode = SSL_VERIFY_PEER
        self._config_ssl_ctx(verify_mode)
        self._ssl = _SSL(SSL_new(self._ctx.value))
        self._intf_ssl = SSL(self._ssl.value)
        SSL_set_connect_state(self._ssl.value)
        if peer_address:
            return lambda: self.connect(peer_address)

    def _config_ssl_ctx(self, verify_mode):
        SSL_CTX_set_verify(self._ctx.value, verify_mode)
        SSL_CTX_set_read_ahead(self._ctx.value, 1)
        # Compression occurs at the stream layer now, leading to datagram
        # corruption when packet loss occurs
        SSL_CTX_set_options(self._ctx.value, SSL_OP_NO_COMPRESSION)
        if self._certfile:
            SSL_CTX_use_certificate_chain_file(self._ctx.value, self._certfile)
        if self._keyfile:
            SSL_CTX_use_PrivateKey_file(self._ctx.value, self._keyfile,
                                        SSL_FILE_TYPE_PEM)
        if self._ca_certs:
            SSL_CTX_load_verify_locations(self._ctx.value, self._ca_certs, None)
        if self._ciphers:
            try:
                SSL_CTX_set_cipher_list(self._ctx.value, self._ciphers)
            except openssl_error() as err:
                raise_ssl_error(ERR_NO_CIPHER, err)
        if self._user_config_ssl_ctx:
            self._user_config_ssl_ctx(self._intf_ssl_ctx)

    def _copy_server(self):
        source = self._sock
        self._udp_demux = source._udp_demux
        rsock = self._udp_demux.get_connection(source._pending_peer_address)
        self._ctx = source._ctx
        self._ssl = source._ssl
        new_source_wbio = _BIO(BIO_new_dgram(source._sock.fileno(),
                                             BIO_NOCLOSE))
        if hasattr(source, "_rsock"):
            self._sock = source._sock
            self._rsock = rsock
            self._wbio = _BIO(BIO_new_dgram(self._sock.fileno(), BIO_NOCLOSE))
            self._rbio = _BIO(BIO_new_dgram(rsock.fileno(), BIO_NOCLOSE))
            new_source_rbio = _BIO(BIO_new_dgram(source._rsock.fileno(),
                                                 BIO_NOCLOSE))
            BIO_dgram_set_peer(self._wbio.value, source._pending_peer_address)
        else:
            self._sock = rsock
            self._wbio = _BIO(BIO_new_dgram(self._sock.fileno(), BIO_NOCLOSE))
            self._rbio = self._wbio
            new_source_rbio = new_source_wbio
            BIO_dgram_set_connected(self._wbio.value,
                                    source._pending_peer_address)
        source._ssl = _SSL(SSL_new(self._ctx.value))
        self._intf_ssl = SSL(source._ssl.value)
        SSL_set_accept_state(source._ssl.value)
        if self._user_config_ssl:
            self._user_config_ssl(self._intf_ssl)
        source._rbio = new_source_rbio
        source._wbio = new_source_wbio
        SSL_set_bio(source._ssl.value,
                    new_source_rbio.value,
                    new_source_wbio.value)
        new_source_rbio.disown()
        new_source_wbio.disown()

    def _reconnect_unwrapped(self):
        source = self._sock
        self._sock = source._wsock
        self._udp_demux = source._demux
        self._rsock = source._rsock
        self._ctx = source._ctx
        self._wbio = _BIO(BIO_new_dgram(self._sock.fileno(), BIO_NOCLOSE))
        self._rbio = _BIO(BIO_new_dgram(self._rsock.fileno(), BIO_NOCLOSE))
        BIO_dgram_set_peer(self._wbio.value, source._peer_address)
        self._ssl = _SSL(SSL_new(self._ctx.value))
        self._intf_ssl = SSL(self._ssl.value)
        SSL_set_accept_state(self._ssl.value)
        if self._user_config_ssl:
            self._user_config_ssl(self._intf_ssl)
        if self._do_handshake_on_connect:
            return lambda: self.do_handshake()

    def _check_nbio(self):
        timeout = self._sock.gettimeout()
        if self._wbio_nb != timeout is not None:
            BIO_set_nbio(self._wbio.value, timeout is not None)
            self._wbio_nb = timeout is not None
        if self._wbio is not self._rbio:
            timeout = self._rsock.gettimeout()
            if self._rbio_nb != timeout is not None:
                BIO_set_nbio(self._rbio.value, timeout is not None)
                self._rbio_nb = timeout is not None
        return timeout  # read channel timeout

    def _wrap_socket_library_call(self, call, timeout_error):
        timeout_sec_start = timeout_sec = self._check_nbio()
        # Pass the call if the socket is blocking or non-blocking
        if not timeout_sec:  # None (blocking) or zero (non-blocking)
            return call()
        start_time = datetime.datetime.now()
        read_sock = self.get_socket(True)
        need_select = False
        while timeout_sec > 0:
            if need_select:
                if not select([read_sock], [], [], timeout_sec)[0]:
                    break
                timeout_sec = timeout_sec_start - \
                  (datetime.datetime.now() - start_time).total_seconds()
            try:
                return call()
            except openssl_error() as err:
                if err.ssl_error == SSL_ERROR_WANT_READ:
                    need_select = True
                    continue
                raise
        raise_ssl_error(timeout_error)

    def _get_cookie(self, ssl):
        assert self._listening
        assert self._ssl.raw == ssl.raw
        if self._listening_peer_address:
            peer_address = self._listening_peer_address
        else:
            peer_address = BIO_dgram_get_peer(self._rbio.value)
        cookie_hmac = hmac.new(self._rnd_key, str(peer_address))
        return cookie_hmac.digest()

    def _generate_cookie_cb(self, ssl):
        return self._get_cookie(ssl)

    def _verify_cookie_cb(self, ssl, cookie):
        if self._get_cookie(ssl) != cookie:
            raise Exception("DTLS cookie mismatch")

    def __init__(self, sock, keyfile=None, certfile=None,
                 server_side=False, cert_reqs=CERT_NONE,
                 ssl_version=PROTOCOL_DTLS, ca_certs=None,
                 do_handshake_on_connect=True,
                 suppress_ragged_eofs=True, ciphers=None,
                 cb_user_config_ssl_ctx=None,
                 cb_user_config_ssl=None):
        """Constructor

        Arguments:
        these arguments match the ones of the SSLSocket class in the
        standard library's ssl module
        """

        if keyfile and not certfile or certfile and not keyfile:
            raise_ssl_error(ERR_BOTH_KEY_CERT_FILES)
        if server_side and not keyfile:
            raise_ssl_error(ERR_BOTH_KEY_CERT_FILES_SVR)
        if cert_reqs != CERT_NONE and not ca_certs:
            raise_ssl_error(ERR_NO_CERTS)

        if not ciphers:
            ciphers = "DEFAULT"

        self._sock = sock
        self._keyfile = keyfile
        self._certfile = certfile
        self._cert_reqs = cert_reqs
        self._ssl_version = ssl_version
        self._ca_certs = ca_certs
        self._do_handshake_on_connect = do_handshake_on_connect
        self._suppress_ragged_eofs = suppress_ragged_eofs
        self._ciphers = ciphers
        self._handshake_done = False
        self._wbio_nb = self._rbio_nb = False

        self._user_config_ssl_ctx = cb_user_config_ssl_ctx
        self._intf_ssl_ctx = None
        self._user_config_ssl = cb_user_config_ssl
        self._intf_ssl = None

        if isinstance(sock, SSLConnection):
            post_init = self._copy_server()
        elif isinstance(sock, _UnwrappedSocket):
            post_init = self._reconnect_unwrapped()
        else:
            try:
                peer_address = sock.getpeername()
            except socket.error:
                peer_address = None
            if server_side:
                post_init = self._init_server(peer_address)
            else:
                post_init = self._init_client(peer_address)

        if self._user_config_ssl:
            self._user_config_ssl(self._intf_ssl)

        if sys.platform.startswith('win') and \
           not (SSL_get_options(self._ssl.value) & SSL_OP_NO_QUERY_MTU):
            SSL_set_options(self._ssl.value, SSL_OP_NO_QUERY_MTU)
            DTLS_set_link_mtu(self._ssl.value, 576)

        SSL_set_bio(self._ssl.value, self._rbio.value, self._wbio.value)
        self._rbio.disown()
        self._wbio.disown()
        if post_init:
            post_init()
    def get_socket(self, inbound):
        """Retrieve a socket used by this connection

        When inbound is True, then the socket from which this connection reads
        data is retrieved. Otherwise the socket to which this connection writes
        data is retrieved.

        Read and write sockets differ depending on whether this is a server- or
        a client-side connection, and on whether a routing demux is in use.
        """

        if inbound and hasattr(self, "_rsock"):
            return self._rsock
        return self._sock

    def listen(self):
        """Server-side cookie exchange

        This method reads datagrams from the socket and initiates cookie
        exchange, upon whose successful conclusion one can then proceed to
        the accept method. Alternatively, accept can be called directly, in
        which case it will call this method. In order to prevent denial-of-
        service attacks, only a small, constant set of computing resources
        are used during the listen phase.

        On some platforms, listen must be called so that packets will be
        forwarded to accepted connections. Doing so is therefore recommened
        in all cases for portable code.

        Return value: a peer address if a datagram from a new peer was
        encountered, None if a datagram for a known peer was forwarded
        """

        if not hasattr(self, "_listening"):
            raise InvalidSocketError("listen called on non-listening socket")

        self._pending_peer_address = None
        try:
            peer_address = self._udp_demux.service()
        except socket.timeout:
            peer_address = None
        except socket.error as sock_err:
            if sock_err.errno != errno.EWOULDBLOCK:
                _logger.exception("Unexpected socket error in listen")
                raise
            peer_address = None

        if not peer_address:
            _logger.debug("Listen returning without peer")
            return

        # The demux advises that a datagram from a new peer may have arrived
        if type(peer_address) is tuple:
            # For this type of demux, the write BIO must be pointed at the peer
            BIO_dgram_set_peer(self._wbio.value, peer_address)
            self._udp_demux.forward()
            self._listening_peer_address = peer_address

        self._check_nbio()
        self._listening = True
        try:
            _logger.debug("Invoking DTLSv1_listen for ssl: %d",
                          self._ssl.raw)
            dtls_peer_address = DTLSv1_listen(self._ssl.value)
        except openssl_error() as err:
            if err.ssl_error == SSL_ERROR_WANT_READ:
                # This method must be called again to forward the next datagram
                _logger.debug("DTLSv1_listen must be resumed")
                return
            elif err.errqueue and err.errqueue[0][0] == ERR_WRONG_VERSION_NUMBER:
                _logger.debug("Wrong version number; aborting handshake")
                raise
            elif err.errqueue and err.errqueue[0][0] == ERR_COOKIE_MISMATCH:
                _logger.debug("Mismatching cookie received; aborting handshake")
                raise
            elif err.errqueue and err.errqueue[0][0] == ERR_NO_SHARED_CIPHER:
                _logger.debug("No shared cipher; aborting handshake")
                raise
            _logger.exception("Unexpected error in DTLSv1_listen")
            raise
        finally:
            self._listening = False
            self._listening_peer_address = None
        if type(peer_address) is tuple:
            _logger.debug("New local peer: %s", dtls_peer_address)
            self._pending_peer_address = peer_address
        else:
            self._pending_peer_address = dtls_peer_address
        _logger.debug("New peer: %s", self._pending_peer_address)
        return self._pending_peer_address

    def accept(self):
        """Server-side UDP connection establishment

        This method returns a server-side SSLConnection object, connected to
        that peer most recently returned from the listen method and not yet
        connected. If there is no such peer, then the listen method is invoked.

        Return value: SSLConnection connected to a new peer, None if packet
        forwarding only to an existing peer occurred.
        """

        if not self._pending_peer_address:
            if not self.listen():
                _logger.debug("Accept returning without connection")
                return
        new_conn = SSLConnection(self, self._keyfile, self._certfile, True,
                                 self._cert_reqs, self._ssl_version,
                                 self._ca_certs, self._do_handshake_on_connect,
                                 self._suppress_ragged_eofs, self._ciphers,
                                 cb_user_config_ssl_ctx=self._user_config_ssl_ctx,
                                 cb_user_config_ssl=self._user_config_ssl)
        new_peer = self._pending_peer_address
        self._pending_peer_address = None
        if self._do_handshake_on_connect:
            # Note that since that connection's socket was just created in its
            # constructor, the following operation must be blocking; hence
            # handshake-on-connect can only be used with a routing demux if
            # listen is serviced by a separate application thread, or else we
            # will hang in this call
            new_conn.do_handshake()
        _logger.debug("Accept returning new connection for new peer")
        return new_conn, new_peer

    def connect(self, peer_address):
        """Client-side UDP connection establishment

        This method connects this object's underlying socket. It subsequently
        performs a handshake if do_handshake_on_connect was set during
        initialization.

        Arguments:
        peer_address - address tuple of server peer
        """

        self._sock.connect(peer_address)
        peer_address = self._sock.getpeername()  # substituted host addrinfo
        BIO_dgram_set_connected(self._wbio.value, peer_address)
        assert self._wbio is self._rbio
        if self._do_handshake_on_connect:
            self.do_handshake()

    def do_handshake(self):
        """Perform a handshake with the peer

        This method forces an explicit handshake to be performed with either
        the client or server peer.
        """

        _logger.debug("Initiating handshake...")
        try:
            self._wrap_socket_library_call(
                lambda: SSL_do_handshake(self._ssl.value),
                ERR_HANDSHAKE_TIMEOUT)
        except openssl_error() as err:
            if err.ssl_error == SSL_ERROR_SYSCALL and err.result == -1:
                raise_ssl_error(ERR_PORT_UNREACHABLE, err)
            raise
        self._handshake_done = True
        _logger.debug("...completed handshake")

    def read(self, len=1024, buffer=None):
        """Read data from connection

        Read up to len bytes and return them.
        Arguments:
        len -- maximum number of bytes to read

        Return value:
        string containing read bytes
        """

        try:
            return self._wrap_socket_library_call(
                lambda: SSL_read(self._ssl.value, len, buffer), ERR_READ_TIMEOUT)
        except openssl_error() as err:
            if err.ssl_error == SSL_ERROR_SYSCALL and err.result == -1:
                raise_ssl_error(ERR_PORT_UNREACHABLE, err)
            raise

    def write(self, data):
        """Write data to connection

        Write data as string of bytes.

        Arguments:
        data -- buffer containing data to be written

        Return value:
        number of bytes actually transmitted
        """

        try:
            ret = self._wrap_socket_library_call(
                lambda: SSL_write(self._ssl.value, data), ERR_WRITE_TIMEOUT)
        except openssl_error() as err:
            if err.ssl_error == SSL_ERROR_SYSCALL and err.result == -1:
                raise_ssl_error(ERR_PORT_UNREACHABLE, err)
            raise
        if ret:
            self._handshake_done = True
        return ret

    def shutdown(self):
        """Shut down the DTLS connection

        This method attemps to complete a bidirectional shutdown between
        peers. For non-blocking sockets, it should be called repeatedly until
        it no longer raises continuation request exceptions.
        """

        if hasattr(self, "_listening"):
            # Listening server-side sockets cannot be shut down
            return

        try:
            self._wrap_socket_library_call(
                lambda: SSL_shutdown(self._ssl.value), ERR_READ_TIMEOUT)
        except openssl_error() as err:
            if err.result == 0:
                # close-notify alert was just sent; wait for same from peer
                # Note: while it might seem wise to suppress further read-aheads
                # with SSL_set_read_ahead here, doing so causes a shutdown
                # failure (ret: -1, SSL_ERROR_SYSCALL) on the DTLS shutdown
                # initiator side. And test_starttls does pass.
                self._wrap_socket_library_call(
                    lambda: SSL_shutdown(self._ssl.value), ERR_READ_TIMEOUT)
            else:
                raise
        if hasattr(self, "_rsock"):
            # Return wrapped connected server socket (non-listening)
            return _UnwrappedSocket(self._sock, self._rsock, self._udp_demux,
                                    self._ctx,
                                    BIO_dgram_get_peer(self._wbio.value))
        # Return unwrapped client-side socket or unwrapped server-side socket
        # for single-socket servers
        return self._sock

    def getpeercert(self, binary_form=False):
        """Retrieve the peer's certificate

        When binary form is requested, the peer's DER-encoded certficate is
        returned if it was transmitted during the handshake.

        When binary form is not requested, and the peer's certificate has been
        validated, then a certificate dictionary is returned. If the certificate
        was not validated, an empty dictionary is returned.

        In all cases, None is returned if no certificate was received from the
        peer.
        """

        try:
            peer_cert = _X509(SSL_get_peer_certificate(self._ssl.value))
        except openssl_error():
            return

        if binary_form:
            return i2d_X509(peer_cert.value)
        if self._cert_reqs == CERT_NONE:
            return {}
        return decode_cert(peer_cert)

    peer_certificate = getpeercert  # compatibility with _ssl call interface

    def getpeercertchain(self, binary_form=False):
        try:
            stack, num, certs = SSL_get_peer_cert_chain(self._ssl.value)
        except openssl_error():
            return

        peer_cert_chain = [_Rsrc(cert) for cert in certs]
        ret = []
        if binary_form:
            ret = [i2d_X509(x.value) for x in peer_cert_chain]
        elif len(peer_cert_chain):
            ret = [decode_cert(x) for x in peer_cert_chain]

        return ret

    def cipher(self):
        """Retrieve information about the current cipher

        Return a triple consisting of cipher name, SSL protocol version defining
        its use, and the number of secret bits. Return None if handshaking
        has not been completed.
        """

        if not self._handshake_done:
            return

        current_cipher = SSL_get_current_cipher(self._ssl.value)
        cipher_name = SSL_CIPHER_get_name(current_cipher)
        cipher_version = SSL_CIPHER_get_version(current_cipher)
        cipher_bits = SSL_CIPHER_get_bits(current_cipher)
        return cipher_name, cipher_version, cipher_bits

    def pending(self):
        """Retrieve number of buffered bytes

        Return the number of bytes that have been read from the socket and
        buffered by this connection. Return 0 if no bytes have been buffered.
        """

        return SSL_pending(self._ssl.value)

    def get_timeout(self):
        """Retrieve the retransmission timedelta

        Since datagrams are subject to packet loss, DTLS will perform
        packet retransmission if a response is not received after a certain
        time interval during the handshaking phase. When using non-blocking
        sockets, the application must call back after that time interval to
        allow for the retransmission to occur. This method returns the
        timedelta after which to perform the call to handle_timeout, or None
        if no such callback is needed given the current handshake state.
        """

        return DTLSv1_get_timeout(self._ssl.value)

    def handle_timeout(self):
        """Perform datagram retransmission, if required

        This method should be called after the timedelta retrieved from
        get_timeout has expired, and no datagrams were received in the
        meantime. If datagrams were received, a new timeout needs to be
        requested.

        Return value:
        True -- retransmissions were performed successfully
        False -- a timeout was not in effect or had not yet expired

        Exceptions:
        Raised when retransmissions fail or too many timeouts occur.
        """

        return DTLSv1_handle_timeout(self._ssl.value)


class _UnwrappedSocket(socket.socket):
    """Unwrapped server-side socket

    Depending on UDP demux implementation, there may not be single socket
    that can be used for both reading and writing to the client socket with
    which it is associated. An object of this type is therefore returned from
    the SSLSocket's unwrap method to allow for unencrypted communication over
    the established channels, including the demux.
    """

    def __init__(self, wsock, rsock, demux, ctx, peer_address):
        socket.socket.__init__(self, _sock=rsock._sock)
        for attr in "send", "sendto", "sendall":
            try:
                delattr(self, attr)
            except AttributeError:
                pass
        self._wsock = wsock
        self._rsock = rsock  # continue to reference to hold in demux map
        self._demux = demux
        self._ctx = ctx
        self._peer_address = peer_address

    def send(self, data, flags=0):
        __doc__ = self._wsock.send.__doc__
        return self._wsock.sendto(data, flags, self._peer_address)

    def sendto(self, data, flags_or_addr, addr=None):
        __doc__ = self._wsock.sendto.__doc__
        return self._wsock.sendto(data, flags_or_addr, addr)

    def sendall(self, data, flags=0):
        __doc__ = self._wsock.sendall.__doc__
        amount = len(data)
        count = 0
        while (count < amount):
            v = self.send(data[count:], flags)
            count += v
        return amount

    def getpeername(self):
        __doc__ = self._wsock.getpeername.__doc__
        return self._peer_address

    def connect(self, addr):
        __doc__ = self._wsock.connect.__doc__
        raise ValueError("Cannot connect already connected unwrapped socket")

    connect_ex = connect
