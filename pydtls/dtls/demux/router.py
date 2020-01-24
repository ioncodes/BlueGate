# Routing demux: forwards datagrams from the root socket to connected
# sockets bound to ephemeral ports.

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

"""Routing UDP Demux

This module implements an explicitly routing UDP demux. New connections create
datagram sockets bound to ephemeral ports on the loopback interface and
connected to a forwarding socket. The demux services incoming datagrams by
receiving them from the root socket and sending them to the socket belonging to
the connection that is associated with the sending peer.

A routing UDP demux can be used on any platform.

Classes:

  UDPDemux -- an explicitly routing UDP demux

Exceptions:

  InvalidSocketError -- exception raised for improper socket objects
  KeyError -- raised for unknown peer addresses
"""

import socket
from logging import getLogger
from weakref import WeakValueDictionary
from ..err import InvalidSocketError

_logger = getLogger(__name__)

UDP_MAX_DGRAM_LENGTH = 65527


class UDPDemux(object):
    """Explicitly routing UDP demux

    This class implements a demux that forwards packets from the root
    socket to sockets belonging to connections. It does this whenever its
    service method is invoked.

    Methods:

      remove_connection -- remove an existing connection
      service -- distribute datagrams from the root socket to connections
      forward -- forward a stored datagram to a connection
    """

    _forwarding_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _forwarding_socket.bind(('127.0.0.1', 0))

    def __init__(self, datagram_socket):
        """Constructor

        Arguments:
        datagram_socket -- the root socket; this must be a bound, unconnected
                           datagram socket
        """

        if datagram_socket.type != socket.SOCK_DGRAM:
            raise InvalidSocketError("datagram_socket is not of " +
                                     "type SOCK_DGRAM")
        try:
            datagram_socket.getsockname()
        except:
            raise InvalidSocketError("datagram_socket is unbound")
        try:
            datagram_socket.getpeername()
        except:
            pass
        else:
            raise InvalidSocketError("datagram_socket is connected")

        self.datagram_socket = datagram_socket
        self.payload = ""
        self.payload_peer_address = None
        self.connections = WeakValueDictionary()

    def get_connection(self, address):
        """Create or retrieve a muxed connection

        Arguments:
        address -- a peer endpoint in IPv4/v6 address format; None refers
                   to the connection for unknown peers

        Return:
        a bound, connected datagram socket instance
        """

        if self.connections.has_key(address):
            return self.connections[address]
        
        # We need a new datagram socket on a dynamically assigned ephemeral port
        conn = socket.socket(self._forwarding_socket.family,
                             self._forwarding_socket.type,
                             self._forwarding_socket.proto)
        conn.bind((self._forwarding_socket.getsockname()[0], 0))
        conn.connect(self._forwarding_socket.getsockname())
        if not address:
            conn.setblocking(0)
        self.connections[address] = conn
        _logger.debug("Created new connection for address: %s", address)
        return conn

    def remove_connection(self, address):
        """Remove a muxed connection

        Arguments:
        address -- an address that was previously returned by the service
                   method and whose connection has not yet been removed

        Return:
        the socket object whose connection has been removed
        """

        return self.connections.pop(address)

    def service(self):
        """Service the root socket

        Read from the root socket and forward one datagram to a
        connection. The call will return without forwarding data
        if any of the following occurs:

          * An error is encountered while reading from the root socket
          * Reading from the root socket times out
          * The root socket is non-blocking and has no data available
          * An empty payload is received
          * A non-empty payload is received from an unknown peer (a peer
            for which get_connection has not yet been called); in this case,
            the payload is held by this instance and will be forwarded when
            the forward method is called

        Return:
        if the datagram received was from a new peer, then the peer's
        address; otherwise None
        """

        self.payload, self.payload_peer_address = \
          self.datagram_socket.recvfrom(UDP_MAX_DGRAM_LENGTH)
        _logger.debug("Received datagram from peer: %s",
                      self.payload_peer_address)
        if not self.payload:
            self.payload_peer_address = None
            return
        if self.connections.has_key(self.payload_peer_address):
            self.forward()
        else:
            return self.payload_peer_address

    def forward(self):
        """Forward a stored datagram

        When the service method returns the address of a new peer, it holds
        the datagram from that peer in this instance. In this case, this
        method will perform the forwarding step. The target connection is the
        one associated with address None if get_connection has not been called
        since the service method returned the new peer's address, and the
        connection associated with the new peer's address if it has.
        """

        assert self.payload
        assert self.payload_peer_address
        if self.connections.has_key(self.payload_peer_address):
            conn = self.connections[self.payload_peer_address]
            default = False
        else:
            conn = self.connections[None]  # propagate exception if not created
            default = True
        _logger.debug("Forwarding datagram from peer: %s, default: %s",
                      self.payload_peer_address, default)
        self._forwarding_socket.sendto(self.payload, conn.getsockname())
        self.payload = ""
        self.payload_peer_address = None
