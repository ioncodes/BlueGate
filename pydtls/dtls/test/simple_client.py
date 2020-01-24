from os import path
import ssl
from socket import socket, AF_INET, SOCK_DGRAM, SHUT_RDWR
from logging import basicConfig, DEBUG
basicConfig(level=DEBUG)  # set now for dtls import code
from dtls import do_patch
do_patch()

cert_path = path.join(path.abspath(path.dirname(__file__)), "certs")
sock = ssl.wrap_socket(socket(AF_INET, SOCK_DGRAM), cert_reqs=ssl.CERT_REQUIRED, ca_certs=path.join(cert_path, "ca-cert.pem"))
sock.connect(('localhost', 28000))
sock.send('Hi there')
print sock.recv()
sock.unwrap()
sock.shutdown(SHUT_RDWR)
