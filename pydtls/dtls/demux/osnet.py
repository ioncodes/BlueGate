# OSNet demux: uses the OS network stack to demultiplex incoming datagrams
# among sockets bound to the same ports.

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

"""OS Network UDP Demux

This module implements a demux that uses the OS network stack to demultiplex
datagrams coming from different peers among datagram sockets that are all bound
to the port at which these datagrams are being received. The network stack is
instructed as to which socket an incoming datagram should be sent to by
connecting the destination socket to the peer endpoint.

The OSNet demux requires operating system functionality that exists in the
Linux kernel, but not in the Windows network stack.

Classes:

  UDPDemux -- a network stack configuring UDP demux

Exceptions:

  InvalidSocketError -- exception raised for improper socket objects
  KeyError -- raised for unknown peer addresses
"""

import socket
from logging import getLogger
from ..err import InvalidSocketError

_logger = getLogger(__name__)


class UDPDemux(object):
    """OS network stack configuring demux

    This class implements a demux that creates sockets connected to peer
    network endpoints, configuring the network stack to demultiplex
    incoming datagrams from these endpoints among these sockets.

    Methods:

      get_connection -- create a new connection or retrieve an existing one
      service -- this method does nothing for this type of demux
    """

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

        datagram_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._datagram_socket = datagram_socket

    def get_connection(self, address):
        """Create or retrieve a muxed connection

        Arguments:
        address -- a peer endpoint in IPv4/v6 address format; None refers
                   to the connection for unknown peers

        Return:
        a bound, connected datagram socket instance, or the root socket
        in case address was None
        """

        if not address:
            return self._datagram_socket

        # Create a new datagram socket bound to the same interface and port as
        # the root socket, but connected to the given peer
        conn = socket.socket(self._datagram_socket.family,
                             self._datagram_socket.type,
                             self._datagram_socket.proto)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        conn.bind(self._datagram_socket.getsockname())
        conn.connect(address)
        _logger.debug("Created new connection for address: %s", address)
        return conn

    @staticmethod
    def service():
        """Service the root socket

        This type of demux performs no servicing work on the root socket,
        and instead advises the caller to proceed to listening on the root
        socket.
        """

        return True
