import ssl
import struct
import sys
from signal import signal, alarm, SIGALRM
from socket import socket, AF_INET, SOCK_DGRAM
from dtls import do_patch, sslconnection

def open_socket(host, port):
    sock = ssl.wrap_socket(socket(AF_INET, SOCK_DGRAM))
    setattr(sock, "ssl_version", sslconnection.PROTOCOL_DTLSv1)
    sock.connect((host, port))
    return sock

def create_packet(fragment, packet_id, fragment_id, number_of_fragments, fragment_length):
    _buffer = struct.pack("<HHHHH",
        packet_id,           # packet id
        len(fragment) + 6,   # packet length
        fragment_id,         # fragment id
        number_of_fragments, # number of fragments
        fragment_length      # fragment length
    )
    _buffer += fragment
    return _buffer

def check(host, port):
    sock = open_socket(host, port)
    packet = create_packet("\x00", 5, 0, 65, 1)
    sock.write(packet)
    signal(SIGALRM, lambda signum, frame: None)
    alarm(3)
    vulnerable = False
    try:
        response = sock.recv(16)[-4:]
        value = struct.unpack("<L", response)[0]
        vulnerable = value != 0x8000ffff
    except:
        vulnerable = True
    finally:
        alarm(0)
        sock.close()
        return vulnerable

def main():
    do_patch() # applies DTLS patches to openssl
    host = sys.argv[1]
    port = int(sys.argv[2])
    if check(host, port):
        print "Vulnerable!"
    else:
        print "Not vulnerable!"

if __name__ == "__main__":
    main()