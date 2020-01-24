# Performance tests for PyDTLS.

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

"""PyDTLS performance tests

This module implements relative performance testing of throughput for the
PyDTLS package. Throughput for the following transports can be compared:

    * Python standard library stream transport (ssl module)
    * PyDTLS datagram transport
    * PyDTLS datagram transport with thread locking callbacks disabled
    * PyDTLS datagram transport with demux type forced to routing demux
"""

import socket
import errno
import ssl
import sys
import time
from argparse import ArgumentParser, ArgumentTypeError
from os import path, urandom
from timeit import timeit
from select import select
from multiprocessing import Process
from multiprocessing.managers import BaseManager
from dtls import do_patch

AF_INET4_6 = socket.AF_INET
CERTFILE = path.join(path.dirname(__file__), "certs", "keycert.pem")
CHUNK_SIZE = 1459
CHUNKS = 150000
CHUNKS_PER_DOT = 500
COMM_KEY = "tronje%T577&kkjLp"

#
# Traffic handler: required for servicing the root socket if the routing demux
#                  is used; only waits for traffic on the data socket with
#                  the osnet demux, as well as streaming sockets
#

def handle_traffic(data_sock, listen_sock, err):
    assert data_sock
    assert err in (ssl.SSL_ERROR_WANT_READ, ssl.SSL_ERROR_WANT_WRITE)
    readers = []
    writers = []
    if listen_sock:
        readers.append(listen_sock)
    if err == ssl.SSL_ERROR_WANT_READ:
        readers.append(data_sock)
    else:
        writers.append(data_sock)
    while True:
        read_ready, write_ready, exc_ready = select(readers, writers, [], 5)
        if not read_ready and not write_ready:
            raise ssl.SSLError("timed out")
        if data_sock in read_ready or data_sock in write_ready:
            break
        assert listen_sock in read_ready
        acc_ret = listen_sock.accept()
        assert acc_ret is None  # test does not attempt multiple connections

#
# Transfer functions: transfer data on non-blocking sockets; written to work
#                     properly for stream as well as message-based protocols
#

fill = urandom(CHUNK_SIZE)

def transfer_out(sock, listen_sock=None, marker=False):
    max_i_len = 10
    start_char = "t" if marker else "s"
    for i in xrange(CHUNKS):
        prefix = start_char + str(i) + ":"
        pad_prefix = prefix + "b" * (max_i_len - len(prefix))
        message = pad_prefix + fill[:CHUNK_SIZE - max_i_len - 1] + "e"
        count = 0
        while count < CHUNK_SIZE:
            try:
                count += sock.send(message[count:])
            except ssl.SSLError as err:
                if err.args[0] in (ssl.SSL_ERROR_WANT_READ,
                                   ssl.SSL_ERROR_WANT_WRITE):
                    handle_traffic(sock, listen_sock, err.args[0])
                else:
                    raise
            except socket.error as err:
                if err.errno == errno.EWOULDBLOCK:
                    handle_traffic(sock, None, ssl.SSL_ERROR_WANT_WRITE)
                else:
                    raise
        if not i % CHUNKS_PER_DOT:
            sys.stdout.write('.')
            sys.stdout.flush()
    print

def transfer_in(sock, listen_sock=None):
    drops = 0
    pack_seq = -1
    i = 0
    try:
        sock.getpeername()
    except:
        peer_set = False
    else:
        peer_set = True
    while pack_seq + 1 < CHUNKS:
        pack = ""
        while len(pack) < CHUNK_SIZE:
            try:
                if isinstance(sock, ssl.SSLSocket):
                    segment = sock.recv(CHUNK_SIZE - len(pack))
                else:
                    segment, addr = sock.recvfrom(CHUNK_SIZE - len(pack))
            except ssl.SSLError as err:
                if err.args[0] in (ssl.SSL_ERROR_WANT_READ,
                                   ssl.SSL_ERROR_WANT_WRITE):
                    try:
                        handle_traffic(sock, listen_sock, err.args[0])
                    except ssl.SSLError as err:
                        if err.message == "timed out":
                            break
                        raise
                else:
                    raise
            except socket.error as err:
                if err.errno == errno.EWOULDBLOCK:
                    try:
                        handle_traffic(sock, None, ssl.SSL_ERROR_WANT_READ)
                    except ssl.SSLError as err:
                        if err.message == "timed out":
                            break
                        raise
                else:
                    raise
            else:
                pack += segment
                if not peer_set:
                    sock.connect(addr)
                    peer_set = True
                # Do not try to assembly packets from datagrams
                if sock.type == socket.SOCK_DGRAM:
                    break
        if len(pack) < CHUNK_SIZE or pack[0] == "t":
            break
        if pack[0] != "s" or pack[-1] != "e":
            raise Exception("Corrupt message received")
        next_seq = int(pack[1:pack.index(':')])
        if next_seq > pack_seq:
            drops += next_seq - pack_seq - 1
            pack_seq = next_seq
        if not i % CHUNKS_PER_DOT:
            sys.stdout.write('.')
            sys.stdout.flush()
        i += 1
    drops += CHUNKS - 1 - pack_seq
    print
    return drops

#
# Single-threaded server
#

def server(sock_type, do_wrap, listen_addr):
    sock = socket.socket(AF_INET4_6, sock_type)
    sock.bind(listen_addr)
    if do_wrap:
        wrap = ssl.wrap_socket(sock, server_side=True, certfile=CERTFILE,
                               do_handshake_on_connect=False,
                               ciphers="NULL")
        wrap.listen(0)
    else:
        wrap = sock
        if sock_type == socket.SOCK_STREAM:
            wrap.listen(0)
    yield wrap.getsockname()
    if do_wrap or sock_type == socket.SOCK_STREAM:
        while True:
            acc_res = wrap.accept()
            if acc_res:
                break
        conn = acc_res[0]
    else:
        conn = wrap
    wrap.setblocking(False)
    conn.setblocking(False)
    class InResult(object): pass
    def _transfer_in():
        InResult.drops = transfer_in(conn, wrap)
    in_time = timeit(_transfer_in, number=1)
    yield in_time, InResult.drops
    out_time = timeit(lambda: transfer_out(conn, wrap), number=1)
    # Inform the client that we are done, in case it has missed the final chunk
    if sock_type == socket.SOCK_DGRAM:
        global CHUNKS, CHUNK_SIZE
        CHUNKS_sav = CHUNKS
        CHUNK_SIZE_sav = CHUNK_SIZE
        try:
            CHUNKS = 5
            CHUNK_SIZE = 10
            for _ in range(10):
                try:
                    transfer_out(conn, wrap, True)
                except ssl.SSLError as err:
                    if err.args[0] == ssl.SSL_ERROR_SYSCALL:
                        break
                    else:
                        raise
                except socket.error as err:
                    if err.errno == errno.ECONNREFUSED:
                        break
                    else:
                        raise
                time.sleep(0.2)
        finally:
            CHUNKS = CHUNKS_sav
            CHUNK_SIZE = CHUNK_SIZE_sav
    conn.shutdown(socket.SHUT_RDWR)
    conn.close()
    wrap.close()
    yield out_time

#
# Client, launched into a separate process
#

def client(sock_type, do_wrap, listen_addr):
    do_patch()  # we might be in a new process
    sock = socket.socket(AF_INET4_6, sock_type)
    if do_wrap:
        wrap = ssl.wrap_socket(sock, ciphers="NULL")
    else:
        wrap = sock
    wrap.connect(listen_addr)
    transfer_out(wrap)
    drops = transfer_in(wrap)
    wrap.shutdown(socket.SHUT_RDWR)
    wrap.close()
    return drops

#
# Client manager - remote clients, run in a separate process
#

def make_client_manager():
    # Create the global client manager class in servers configured as client
    # managers
    class ClientManager(object):
        from Queue import Queue

        queue = Queue()
        clients = -1  # creator does not count

        @classmethod
        def get_queue(cls):
            cls.clients += 1
            return cls.queue

        @classmethod
        def release_clients(cls):
            def wait_queue_empty(fail_return):
                waitcount = 5
                while not cls.queue.empty() and waitcount:
                    time.sleep(1)
                    waitcount -= 1
                if not cls.queue.empty():
                    # Clients are already dead or stuck
                    return fail_return
            # Wait a moment for the queue to empty
            wait_queue_empty("No live clients detected")
            for _ in range(cls.clients):
                cls.queue.put("STOP")
            # Wait for all stop messages to be retrieved
            wait_queue_empty("Not all clients responded to stop signal")
            return "Client release succeeded"
    globals()["ClientManager"] = ClientManager

def get_queue():
    return ClientManager.get_queue()

def release_clients():
    return ClientManager.release_clients()

MANAGER = None
QUEUE = None
class Manager(BaseManager): pass

def start_client_manager(port):
    global MANAGER, QUEUE
    make_client_manager()
    Manager.register("get_queue", get_queue)
    Manager.register("release_clients", release_clients)
    if sys.platform.startswith('win'):
        addr = socket.gethostname(), port
    else:
        addr = '', port
    MANAGER = Manager(addr, COMM_KEY)
    MANAGER.start(make_client_manager)
    QUEUE = MANAGER.get_queue()

def stop_client_manager():
    global MANAGER, QUEUE
    QUEUE = None
    MANAGER.release_clients()
    MANAGER.shutdown()
    MANAGER = None

def remote_client(manager_address):
    Manager.register("get_queue")
    manager = Manager(manager_address, COMM_KEY)
    manager.connect()
    queue = manager.get_queue()
    print "Client connected; waiting for job..."
    while True:
        command = queue.get()
        if command == "STOP":
            break
        command = command[:-1] + [(manager_address[0], command[-1][1])]
        print "Starting job: " + str(command)
        drops = client(*command)
        print "%d drops" % drops
        print "Job completed; waiting for next job..."

#
# Test runner
#

def run_test(server_args, client_args, port):
    if port is None:
        port = 0
    if QUEUE:
        # bind to all interfaces, for remote clients
        listen_addr = '', port
    else:
        # bind to loopback only, for local clients
        listen_addr = 'localhost', port
    svr = iter(server(*server_args, listen_addr=listen_addr))
    listen_addr = svr.next()
    listen_addr = 'localhost', listen_addr[1]
    client_args = list(client_args)
    client_args.append(listen_addr)
    if QUEUE:
        QUEUE.put(client_args)
    else:
        proc = Process(target=client, args=client_args)
        proc.start()
    in_size = CHUNK_SIZE * CHUNKS / 2**20
    out_size = CHUNK_SIZE * CHUNKS / 2**20
    print "Starting inbound: %dMiB" % in_size
    svr_in_time, drops = svr.next()
    print "Inbound: %.3f seconds, %dMiB/s, %d drops" % (
        svr_in_time, in_size / svr_in_time, drops)
    print "Starting outbound: %dMiB" % out_size
    svr_out_time = svr.next()
    print "Outbound: %.3f seconds, %dMiB/s" % (
        svr_out_time, out_size / svr_out_time)
    if not QUEUE:
        proc.join()
    print "Combined: %.3f seconds, %dMiB/s" % (
        svr_out_time + svr_in_time,
        (in_size + out_size) / (svr_in_time + svr_out_time))

#
# Main entry point
#

if __name__ == "__main__":
    def port(string):
        val = int(string)
        if val < 1 or val > 2**16:
            raise ArgumentTypeError("%d is an invalid port number" % val)
        return val
    def endpoint(string):
        addr = string.split(':')
        if len(addr) != 2:
            raise ArgumentTypeError("%s is not a valid host endpoint" % string)
        addr[1] = port(addr[1])
        socket.getaddrinfo(addr[0], addr[1], socket.AF_INET)
        return tuple(addr)
    parser = ArgumentParser()
    parser.add_argument("-s", "--server", type=port, metavar="PORT",
                        help="local server port for remote clients")
    parser.add_argument("-p", "--port", type=port, metavar="SUITEPORT",
                        help="fixed suite port instead of dynamic assignment")
    parser.add_argument("-c", "--client", type=endpoint, metavar="ENDPOINT",
                        help="remote server endpoint for this client")
    args = parser.parse_args()
    if args.client:
        remote_client(args.client)
        sys.exit()
    if args.server:
        start_client_manager(args.server)
    suites = {
        "Raw TCP": (socket.SOCK_STREAM, False),
        "Raw UDP": (socket.SOCK_DGRAM, False),
        "SSL (TCP)": (socket.SOCK_STREAM, True),
        "DTLS (UDP)": (socket.SOCK_DGRAM, True),
        }
    selector = {
        0: "Exit",
        1: "Raw TCP",
        2: "Raw UDP",
        3: "SSL (TCP)",
        4: "DTLS (UDP)",
        }
    do_patch()
    while True:
        print "\nSelect protocol:\n"
        for key in sorted(selector):
            print "\t" + str(key) + ": " + selector[key]
        try:
            choice = raw_input("\nProtocol: ")
            choice = int(choice)
            if choice < 0 or choice >= len(selector):
                raise ValueError("Invalid selection input")
        except (ValueError, OverflowError):
            print "Invalid selection input"
            continue
        except EOFError:
            break
        if not choice:
            break
        run_test(suites[selector[choice]], suites[selector[choice]], args.port)
    if args.server:
        stop_client_manager()
