# PyDTLS sequential echo.

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

"""PyDTLS sequential echo

This script runs a sequential echo server. It is sequential in that it will
respond without error only to a single sclient that invokes the following steps
in order:
    * DTLS cookie exchange on port 28000 of localhost
    * DTLS handshake (application-default ciphers)
    * Write and receive echo back for an arbitrary number of datagrams
    * Isue shutdown notification and receive the shutdown notification response

Note that this script's operation is slow and inefficient on purpose: it
invokes the demux without socket select, but with 5-second timeouts after
the cookie exchange; this is done so that one can follow the debug logs when
operating this server from a client shell interactively.
"""

import socket
from os import path
from logging import basicConfig, DEBUG
basicConfig(level=DEBUG)  # set now for dtls import code
from dtls.sslconnection import SSLConnection
from dtls.err import SSLError, SSL_ERROR_WANT_READ, SSL_ERROR_ZERO_RETURN


def main():
    sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sck.bind(("127.0.0.1", 28000))
    sck.settimeout(30)
    cert_path = path.join(path.abspath(path.dirname(__file__)), "certs")
    scn = SSLConnection(
        sck,
        keyfile=path.join(cert_path, "keycert.pem"),
        certfile=path.join(cert_path, "keycert.pem"),
        server_side=True,
        ca_certs=path.join(cert_path, "ca-cert.pem"),
        do_handshake_on_connect=False)
    cnt = 0

    while True:
        cnt += 1
        print "Listen invocation: %d" % cnt
        peer_address = scn.listen()
        if peer_address:
            print "Completed listening for peer: %s" % str(peer_address)
            break

    print "Accepting..."
    conn = scn.accept()[0]
    sck.settimeout(5)
    conn.get_socket(True).settimeout(5)

    cnt = 0
    while True:
        cnt += 1
        print "Listen invocation: %d" % cnt
        peer_address = scn.listen()
        assert not peer_address
        print "Handshake invocation: %d" % cnt
        try:
            conn.do_handshake()
        except SSLError as err:
            if err.errno == 504:
                continue
            raise
        print "Completed handshaking with peer"
        break

    cnt = 0
    while True:
        cnt += 1
        print "Listen invocation: %d" % cnt
        peer_address = scn.listen()
        assert not peer_address
        print "Read invocation: %d" % cnt
        try:
            message = conn.read()
        except SSLError as err:
            if err.errno == 502:
                continue
            if err.args[0] == SSL_ERROR_ZERO_RETURN:
                break
            raise
        print message
        conn.write("Back to you: " + message)

    cnt = 0
    while True:
        cnt += 1
        print "Listen invocation: %d" % cnt
        peer_address = scn.listen()
        assert not peer_address
        print "Shutdown invocation: %d" % cnt
        try:
            s = conn.shutdown()
            s.shutdown(socket.SHUT_RDWR)
        except SSLError as err:
            if err.errno == 502:
                continue
            raise
        break

if __name__ == "__main__":
    main()
