# -*- coding: utf-8 -*-

# DTLS Socket: A wrapper for a server and client using a DTLS connection.

# Copyright 2017 Björn Freise
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

"""DTLS Socket

This wrapper encapsulates the state and behavior associated with the connection
between the OpenSSL library and an individual peer when using the DTLS
protocol.

Classes:

  DtlsSocket -- DTLS Socket wrapper for use as a client or server
"""

import select

from logging import getLogger

import ssl
import socket
from patch import do_patch
do_patch()
from sslconnection import SSLContext, SSL
import err as err_codes

_logger = getLogger(__name__)


def wrap_client(sock, keyfile=None, certfile=None,
                cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_DTLSv1_2, ca_certs=None,
                do_handshake_on_connect=True, suppress_ragged_eofs=True,
                ciphers=None, curves=None, sigalgs=None, user_mtu=None):

    return DtlsSocket(sock=sock, keyfile=keyfile, certfile=certfile, server_side=False,
                      cert_reqs=cert_reqs, ssl_version=ssl_version, ca_certs=ca_certs,
                      do_handshake_on_connect=do_handshake_on_connect, suppress_ragged_eofs=suppress_ragged_eofs,
                      ciphers=ciphers, curves=curves, sigalgs=sigalgs, user_mtu=user_mtu,
                      server_key_exchange_curve=None, server_cert_options=ssl.SSL_BUILD_CHAIN_FLAG_NONE)


def wrap_server(sock, keyfile=None, certfile=None,
                cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_DTLS, ca_certs=None,
                do_handshake_on_connect=False, suppress_ragged_eofs=True,
                ciphers=None, curves=None, sigalgs=None, user_mtu=None,
                server_key_exchange_curve=None, server_cert_options=ssl.SSL_BUILD_CHAIN_FLAG_NONE):

    return DtlsSocket(sock=sock, keyfile=keyfile, certfile=certfile, server_side=True,
                      cert_reqs=cert_reqs, ssl_version=ssl_version, ca_certs=ca_certs,
                      do_handshake_on_connect=do_handshake_on_connect, suppress_ragged_eofs=suppress_ragged_eofs,
                      ciphers=ciphers, curves=curves, sigalgs=sigalgs, user_mtu=user_mtu,
                      server_key_exchange_curve=server_key_exchange_curve, server_cert_options=server_cert_options)


class DtlsSocket(object):

    class _ClientSession(object):

        def __init__(self, host, port, handshake_done=False, timeout=None):
            self.host = host
            self.port = int(port)
            self.handshake_done = handshake_done
            self.timeout = timeout
            self.updateTimestamp()

        def getAddr(self):
            return self.host, self.port
        
        def updateTimestamp(self):
            if self.timeout != None:
                self.last_update = time.time()

        def expired(self):
            if self.timeout == None:
                return False
            else:
                return (time.time() - self.last_update) > self.timeout
        

    def __init__(self,
                 sock=None,
                 keyfile=None,
                 certfile=None,
                 server_side=False,
                 cert_reqs=ssl.CERT_NONE,
                 ssl_version=ssl.PROTOCOL_DTLSv1_2,
                 ca_certs=None,
                 do_handshake_on_connect=False,
                 suppress_ragged_eofs=True,
                 ciphers=None,
                 curves=None,
                 sigalgs=None,
                 user_mtu=None,
                 server_key_exchange_curve=None,
                 server_cert_options=ssl.SSL_BUILD_CHAIN_FLAG_NONE,
                 client_timeout=None):

        if server_cert_options is None:
            server_cert_options = ssl.SSL_BUILD_CHAIN_FLAG_NONE

        self._ssl_logging = False
        self._server_side = server_side
        self._ciphers = ciphers
        self._curves = curves
        self._sigalgs = sigalgs
        self._user_mtu = user_mtu
        self._server_key_exchange_curve = server_key_exchange_curve
        self._server_cert_options = server_cert_options
        self._client_timeout = client_timeout

        # Default socket creation
        _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if isinstance(sock, socket.socket):
            _sock = sock

        self._sock = ssl.wrap_socket(_sock,
                                     keyfile=keyfile,
                                     certfile=certfile,
                                     server_side=self._server_side,
                                     cert_reqs=cert_reqs,
                                     ssl_version=ssl_version,
                                     ca_certs=ca_certs,
                                     do_handshake_on_connect=do_handshake_on_connect,
                                     suppress_ragged_eofs=suppress_ragged_eofs,
                                     ciphers=self._ciphers,
                                     cb_user_config_ssl_ctx=self.user_config_ssl_ctx,
                                     cb_user_config_ssl=self.user_config_ssl)

        if self._server_side:
            self._clients = {}
            self._timeout = None

    def __getattr__(self, item):
        if hasattr(self, "_sock") and hasattr(self._sock, item):
            return getattr(self._sock, item)
        raise AttributeError

    def user_config_ssl_ctx(self, _ctx):
        """

        :param SSLContext _ctx:
        """
        _ctx.set_ssl_logging(self._ssl_logging)
        if self._ciphers:
            _ctx.set_ciphers(self._ciphers)
        if self._curves:
            _ctx.set_curves(self._curves)
        if self._sigalgs:
            _ctx.set_sigalgs(self._sigalgs)
        if self._server_side:
            _ctx.build_cert_chain(flags=self._server_cert_options)
            _ctx.set_ecdh_curve(curve_name=self._server_key_exchange_curve)

    def user_config_ssl(self, _ssl):
        """

        :param SSL _ssl:
        """
        if self._user_mtu:
            _ssl.set_link_mtu(self._user_mtu)

    def settimeout(self, t):
        if self._server_side:
            self._timeout = t
        else:
            self._sock.settimeout(t)

    def close(self):
        if self._server_side:
            for cli in self._clients.keys():
                cli.close()
        else:
            try:
                self._sock.unwrap()
            except:
                pass
        self._sock.close()

    def recvfrom(self, bufsize, flags=0):
        if self._server_side:
            return self._recvfrom_on_server_side(bufsize, flags=flags)
        else:
            return self._recvfrom_on_client_side(bufsize, flags=flags)

    def _recvfrom_on_server_side(self, bufsize, flags):
        try:
            r, _, _ = select.select(self._getAllReadingSockets(), [], [], self._timeout)

        except socket.timeout:
            # __Nothing__ received from any client
            raise socket.timeout

        try:
            for conn in r:
                _last_peer = conn.getpeername() if conn._connected else None
                if self._sockIsServerSock(conn):
                    # Connect
                    self._clientAccept(conn)
                else:
                    # Handshake
                    if not self._clientHandshakeDone(conn):
                        self._clientDoHandshake(conn)
                    # Normal read
                    else:
                        buf = self._clientRead(conn, bufsize)
                        if buf:
                            self._clients[conn].updateTimestamp()
                            if conn in self._clients:
                                return buf, self._clients[conn].getAddr()
                            else:
                                _logger.debug('Received data from an already disconnected client!')

        except Exception as e:
            setattr(e, 'peer', _last_peer)
            raise e

        try:
            for conn in self._getClientReadingSockets():
                if conn.get_timeout():
                    ret = conn.handle_timeout()
                    _logger.debug('Retransmission triggered for %s: %d' % (str(self._clients[conn].getAddr()), ret))

                if self._clients[conn].expired() == True:
                    _logger.debug('Found expired session')
                    self._clientDrop(conn)

        except Exception as e:
            raise e

        # __No_data__ received from any client
        raise socket.timeout

    def _recvfrom_on_client_side(self, bufsize, flags):
        try:
            buf = self._sock.recv(bufsize, flags)

        except ssl.SSLError as e:
            if e.errno == ssl.ERR_READ_TIMEOUT or e.args[0] == ssl.SSL_ERROR_WANT_READ:
                pass
            else:
                raise e

        else:
            if buf:
                return buf, self._sock.getpeername()

        # __No_data__ received from any client
        raise socket.timeout

    def sendto(self, buf, address):
        if self._server_side:
            return self._sendto_from_server_side(buf, address)
        else:
            return self._sendto_from_client_side(buf, address)

    def _sendto_from_server_side(self, buf, address):
        for conn, client in self._clients.iteritems():
            if client.getAddr() == address:
                return self._clientWrite(conn, buf)
        return 0

    def _sendto_from_client_side(self, buf, address):
        try:
            if not self._sock._connected:
                self._sock.connect(address)
            bytes_sent = self._sock.send(buf)

        except ssl.SSLError as e:
            raise e

        return bytes_sent

    def _getClientReadingSockets(self):
        return [x for x in self._clients.keys()]

    def _getAllReadingSockets(self):
        return [self._sock] + self._getClientReadingSockets()

    def _sockIsServerSock(self, conn):
        return conn is self._sock

    def _clientHandshakeDone(self, conn):
        return conn in self._clients and self._clients[conn].handshake_done is True

    def _clientAccept(self, conn):
        _logger.debug('+' * 60)
        ret = None

        try:
            ret = conn.accept()
            _logger.debug('Accept returned with ... %s' % (str(ret)))

        except Exception as e:
            raise e

        else:
            if ret:
                client, addr = ret
                host, port = addr
                if client in self._clients:
                    _logger.debug('Client already connected %s' % str(client))
                    raise ValueError
                self._clients[client] = self._ClientSession(host=host, port=port)

                self._clientDoHandshake(client)

    def _clientDoHandshake(self, conn):
        _logger.debug('-' * 60)
        conn.setblocking(False)

        try:
            conn.do_handshake()
            _logger.debug('Connection from %s successful' % (str(self._clients[conn].getAddr())))

            self._clients[conn].handshake_done = True

        except ssl.SSLError as e:
            if e.errno == err_codes.ERR_HANDSHAKE_TIMEOUT or e.args[0] == ssl.SSL_ERROR_WANT_READ:
                pass
            else:
                self._clientDrop(conn, error=e)
                raise e

    def _clientRead(self, conn, bufsize=4096):
        _logger.debug('*' * 60)
        ret = None

        try:
            ret = conn.recv(bufsize)
            _logger.debug('From client %s ... bytes received %s' % (str(self._clients[conn].getAddr()), str(len(ret))))

        except ssl.SSLError as e:
            if e.args[0] == ssl.SSL_ERROR_WANT_READ:
                pass
            else:
                self._clientDrop(conn, error=e)

        return ret

    def _clientWrite(self, conn, data):
        _logger.debug('#' * 60)
        ret = None

        try:
            _data = data
            if False:
                _data = data.raw
            ret = conn.send(_data)
            _logger.debug('To client %s ... bytes sent %s' % (str(self._clients[conn].getAddr()), str(ret)))

        except Exception as e:
            raise e

        return ret

    def _clientDrop(self, conn, error=None):
        _logger.debug('$' * 60)

        try:
            if error:
                _logger.debug('Drop client %s ... with error: %s' % (self._clients[conn].getAddr(), error))
            else:
                _logger.debug('Drop client %s' % str(self._clients[conn].getAddr()))

            if conn in self._clients:
                del self._clients[conn]
            try:
                conn.unwrap()
            except:
                pass
            conn.close()

        except Exception as e:
            pass
