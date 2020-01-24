# Test the support for DTLS through the SSL module. Adapted from the Python
# standard library's test_ssl.py regression test module by Ray Brown.

import sys
import unittest
import asyncore
import socket
import select
import gc
import os
import errno
import pprint
import urllib, urlparse
import traceback
import weakref
import platform
import threading
import time
import datetime
import SocketServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
from collections import OrderedDict

import ssl
from dtls import do_patch, force_routing_demux, reset_default_demux

HOST = "localhost"
CONNECTION_TIMEOUT = datetime.timedelta(seconds=30)

class TestSupport(object):
    verbose = True

    class Ctx(object):
        def __enter__(self):
            self.server = AsyncoreEchoServer(CERTFILE)
            flag = threading.Event()
            self.server.start(flag)
            flag.wait()
            return self.server.sockname

        def __exit__(self, exc_type, exc_value, traceback):
            self.server.stop()
            self.server = None

    def transient_internet(self):
        return self.Ctx()

test_support = TestSupport()

def handle_error(prefix):
    exc_format = ' '.join(traceback.format_exception(*sys.exc_info()))
    if test_support.verbose:
        sys.stdout.write(prefix + exc_format)


class BasicTests(unittest.TestCase):

    def test_sslwrap_simple(self):
        # A crude test for the legacy API
        try:
            ssl.sslwrap_simple(socket.socket(AF_INET4_6, socket.SOCK_DGRAM))
        except IOError, e:
            if e.errno == 32: # broken pipe when ssl_sock.do_handshake(), this test doesn't care about that
                pass
            else:
                raise
        try:
            ssl.sslwrap_simple(socket.socket(AF_INET4_6,
                                             socket.SOCK_DGRAM)._sock)
        except IOError, e:
            if e.errno == 32: # broken pipe when ssl_sock.do_handshake(), this test doesn't care about that
                pass
            else:
                raise


class BasicSocketTests(unittest.TestCase):

    def test_constants(self):
        ssl.PROTOCOL_SSLv23
        ssl.PROTOCOL_TLSv1
        ssl.PROTOCOL_DTLSv1  # added
        ssl.PROTOCOL_DTLSv1_2  # added
        ssl.PROTOCOL_DTLS  # added
        ssl.CERT_NONE
        ssl.CERT_OPTIONAL
        ssl.CERT_REQUIRED

    def test_dtls_openssl_version(self):
        n = ssl.DTLS_OPENSSL_VERSION_NUMBER
        t = ssl.DTLS_OPENSSL_VERSION_INFO
        s = ssl.DTLS_OPENSSL_VERSION
        self.assertIsInstance(n, (int, long))
        self.assertIsInstance(t, tuple)
        self.assertIsInstance(s, str)
        # Some sanity checks follow
        # >= 1.0.2
        self.assertGreaterEqual(n, 0x10002000)
        # < 2.0
        self.assertLess(n, 0x20000000)
        major, minor, fix, patch, status = t
        self.assertGreaterEqual(major, 1)
        self.assertLess(major, 2)
        self.assertGreaterEqual(minor, 0)
        self.assertLess(minor, 256)
        self.assertGreaterEqual(fix, 2)
        self.assertLess(fix, 256)
        self.assertGreaterEqual(patch, 0)
        self.assertLessEqual(patch, 26)
        self.assertGreaterEqual(status, 0)
        self.assertLessEqual(status, 15)
        # Version string as returned by OpenSSL, the format might change
        self.assertTrue(
            s.startswith("OpenSSL {:d}.{:d}.{:d}".format(major, minor, fix)),
            (s, t))

    def test_ciphers(self):
        server = AsyncoreEchoServer(CERTFILE)
        flag = threading.Event()
        server.start(flag)
        flag.wait()
        remote = (HOST, server.port)
        try:
            s = ssl.wrap_socket(socket.socket(AF_INET4_6, socket.SOCK_DGRAM),
                                cert_reqs=ssl.CERT_NONE, ciphers="ALL")
            s.connect(remote)
            s = ssl.wrap_socket(socket.socket(AF_INET4_6, socket.SOCK_DGRAM),
                                cert_reqs=ssl.CERT_NONE, ciphers="DEFAULT")
            s.connect(remote)
            # Error checking occurs when connecting, because the SSL context
            # isn't created before.
            s = ssl.wrap_socket(socket.socket(AF_INET4_6, socket.SOCK_DGRAM),
                                cert_reqs=ssl.CERT_NONE,
                                ciphers="^$:,;?*'dorothyx")
            with self.assertRaisesRegexp(ssl.SSLError,
                                         "No cipher can be selected"):
                s.connect(remote)
        finally:
            server.stop()

    @unittest.skipIf(platform.python_implementation() != "CPython",
                     "Reference cycle test feasible under CPython only")
    def test_refcycle(self):
        # Issue #7943: an SSL object doesn't create reference cycles with
        # itself.
        s = socket.socket(AF_INET4_6, socket.SOCK_DGRAM)
        ss = ssl.wrap_socket(s)
        wr = weakref.ref(ss)
        del ss
        self.assertEqual(wr(), None)

    def test_wrapped_unconnected(self):
        # The _delegate_methods in socket.py are correctly delegated to by an
        # unconnected SSLSocket, so they will raise a socket.error rather than
        # something unexpected like TypeError.
        s = socket.socket(AF_INET4_6, socket.SOCK_DGRAM)
        ss = ssl.wrap_socket(s)
        if os.name != "posix":
            # On Linux, unconnected, unbound datagram sockets can receive and
            # the following calls will therefore block
            self.assertRaises(socket.error, ss.recv, 1)
            self.assertRaises(socket.error, ss.recv_into, bytearray(b'x'))
            self.assertRaises(socket.error, ss.recvfrom, 1)
            self.assertRaises(socket.error, ss.recvfrom_into, bytearray(b'x'),
                              1)
        self.assertRaises(socket.error, ss.send, b'x')
        self.assertRaises(socket.error, ss.sendto, b'x',
                          ('0.0.0.0', 0) if AF_INET4_6 == socket.AF_INET else
                          ('::', 0))


class NetworkedTests(unittest.TestCase):

    def test_connect(self):
        with test_support.transient_internet() as remote:
            s = ssl.wrap_socket(socket.socket(AF_INET4_6, socket.SOCK_DGRAM),
                                cert_reqs=ssl.CERT_NONE)
            s.connect(remote)
            c = s.getpeercert()
            if c:
                self.fail("Peer cert %s shouldn't be here!")
            s.close()

            # this should fail because we have no verification certs
            s = ssl.wrap_socket(socket.socket(AF_INET4_6, socket.SOCK_DGRAM),
                                cert_reqs=ssl.CERT_REQUIRED)
            try:
                s.connect(remote)
            except ssl.SSLError:
                pass
            finally:
                s.close()

            # this should succeed because we specify the root cert
            s = ssl.wrap_socket(socket.socket(AF_INET4_6, socket.SOCK_DGRAM),
                                cert_reqs=ssl.CERT_REQUIRED,
                                ca_certs=ISSUER_CERTFILE)
            try:
                s.connect(remote)
            finally:
                s.close()

    def test_connect_ex(self):
        # Issue #11326: check connect_ex() implementation
        with test_support.transient_internet() as remote:
            s = ssl.wrap_socket(socket.socket(AF_INET4_6, socket.SOCK_DGRAM),
                                cert_reqs=ssl.CERT_REQUIRED,
                                ca_certs=ISSUER_CERTFILE)
            try:
                self.assertEqual(0, s.connect_ex(remote))
                self.assertTrue(s.getpeercert())
            finally:
                s.close()

    def test_non_blocking_connect_ex(self):
        # Issue #11326: non-blocking connect_ex() should allow handshake
        # to proceed after the socket gets ready.
        with test_support.transient_internet() as remote:
            s = ssl.wrap_socket(socket.socket(AF_INET4_6, socket.SOCK_DGRAM),
                                cert_reqs=ssl.CERT_REQUIRED,
                                ca_certs=ISSUER_CERTFILE,
                                do_handshake_on_connect=False)
            try:
                s.setblocking(False)
                rc = s.connect_ex(remote)
                # EWOULDBLOCK under Windows, EINPROGRESS elsewhere
                self.assertIn(rc, (0, errno.EINPROGRESS, errno.EWOULDBLOCK))
                # Non-blocking handshake
                while True:
                    try:
                        s.do_handshake()
                        break
                    except ssl.SSLError as err:
                        if err.args[0] == ssl.SSL_ERROR_WANT_READ:
                            while True:
                                to = s.get_timeout()
                                to = to.total_seconds() if to else 5.0
                                sel = select.select([s], [], [], to)
                                if sel[0]:
                                    break
                                s.handle_timeout()
                        else:
                            raise
                # SSL established
                self.assertTrue(s.getpeercert())
            finally:
                s.close()

    @unittest.skipIf(os.name == "nt",
                     "Can't use a socket as a file under Windows")
    def test_makefile_close(self):
        # Issue #5238: creating a file-like object with makefile() shouldn't
        # delay closing the underlying "real socket" (here tested with its
        # file descriptor, hence skipping the test under Windows).
        with test_support.transient_internet() as remote:
            ss = ssl.wrap_socket(socket.socket(AF_INET4_6, socket.SOCK_DGRAM))
            ss.connect(remote)
            fd = ss.fileno()
            f = ss.makefile()
            f.close()
            # The fd is still open
            os.read(fd, 0)
            # Closing the SSL socket should close the fd too
            ss.close()
            gc.collect()
            with self.assertRaises(OSError) as e:
                os.read(fd, 0)
            self.assertEqual(e.exception.errno, errno.EBADF)

    def test_non_blocking_handshake(self):
        with test_support.transient_internet() as remote:
            s = socket.socket(AF_INET4_6, socket.SOCK_DGRAM)
            s.connect(remote)
            s.setblocking(False)
            s = ssl.wrap_socket(s,
                                cert_reqs=ssl.CERT_NONE,
                                do_handshake_on_connect=False)
            count = 0
            while True:
                try:
                    count += 1
                    s.do_handshake()
                    break
                except ssl.SSLError, err:
                    if err.args[0] == ssl.SSL_ERROR_WANT_READ:
                        while True:
                            to = s.get_timeout()
                            if to:
                                sel = select.select([s], [], [],
                                                    to.total_seconds())
                                if sel[0]:
                                    break
                                s.handle_timeout()
                                continue
                            select.select([s], [], [])
                            break
                    else:
                        raise
            s.close()
            if test_support.verbose:
                sys.stdout.write(("\nNeeded %d calls to do_handshake() " +
                                  "to establish session.\n") % count)

    def test_get_server_certificate(self):
        for prot in (ssl.PROTOCOL_DTLSv1, ssl.PROTOCOL_DTLSv1_2, ssl.PROTOCOL_DTLS):
            with test_support.transient_internet() as remote:
                pem = ssl.get_server_certificate(remote,
                                                 prot)
                if not pem:
                    self.fail("No server certificate!")

                try:
                    pem = ssl.get_server_certificate(remote,
                                                     prot,
                                                     ca_certs=OTHER_CERTFILE)
                except ssl.SSLError:
                    # should fail
                    pass
                else:
                    self.fail("Got server certificate %s!" % pem)

                pem = ssl.get_server_certificate(remote,
                                                 prot,
                                                 ca_certs=ISSUER_CERTFILE)
                if not pem:
                    self.fail("No server certificate!")
                if test_support.verbose:
                    sys.stdout.write("\nVerified certificate is\n%s\n" % pem)

class ThreadedEchoServer(threading.Thread):

    class ConnectionHandler(threading.Thread):

        """A mildly complicated class, because we want it to work both
        with and without the SSL wrapper around the socket connection, so
        that we can test the STARTTLS functionality."""

        def __init__(self, server, connsock):
            self.server = server
            self.running = False
            self.sock = connsock
            self.sock.settimeout(CONNECTION_TIMEOUT.total_seconds())
            self.sslconn = connsock
            threading.Thread.__init__(self)
            server.register_handler(True)
            self.daemon = True

        def show_conn_details(self):
            if self.server.certreqs == ssl.CERT_REQUIRED:
                cert = self.sslconn.getpeercert()
                if test_support.verbose and self.server.chatty:
                    sys.stdout.write(" client cert is " +
                                     pprint.pformat(cert) + "\n")
                cert_binary = self.sslconn.getpeercert(True)
                if test_support.verbose and self.server.chatty:
                    sys.stdout.write(" cert binary is " +
                                     str(len(cert_binary)) + " bytes\n")
            cipher = self.sslconn.cipher()
            if test_support.verbose and self.server.chatty:
                sys.stdout.write(" server: connection cipher is now " +
                                 str(cipher) + "\n")

        def wrap_conn(self):
            try:
                self.sslconn = ssl.wrap_socket(
                    self.sock, server_side=True,
                    certfile=self.server.certificate,
                    ssl_version=self.server.protocol,
                    ca_certs=self.server.cacerts,
                    cert_reqs=self.server.certreqs,
                    ciphers=self.server.ciphers)
            except ssl.SSLError:
                # XXX Various errors can have happened here, for example
                # a mismatching protocol version, an invalid certificate,
                # or a low-level bug. This should be made more
                # discriminating.
                if self.server.chatty:
                    handle_error("\n server:  bad connection attempt " +
                                 "from " +
                                 str(self.sock.getpeername()) + ":\n")
                self.close()
                self.running = False
                self.server.stop()
                return False
            else:
                return True

        def read(self):
            if self.sslconn:
                return self.sslconn.read()
            else:
                return self.sock.recv(1024)

        def write(self, bytes):
            if self.sslconn:
                return self.sslconn.write(bytes)
            else:
                return self.sock.send(bytes)

        def close(self):
            self.server.register_handler(False)
            if self.sslconn:
                self.sslconn.close()
            else:
                self.sock._sock.close()

        def run(self):
            self.running = True
            # Complete the handshake
            try:
                self.sock.do_handshake()
            except ssl.SSLError:
                if self.server.chatty:
                    handle_error("\n server: failed to handshake with " +
                                 str(self.sock.getpeername()) + ":\n")
                self.close()
                self.running = False
                self.server.stop()
                return
            if self.server.starttls_server:
                self.sock = self.sock.unwrap()
                self.sslconn = None
            else:
                self.show_conn_details()
            while self.running:
                try:
                    msg = self.read()
                    if not msg:
                        # eof, so quit this handler
                        self.running = False
                        self.close()
                    elif msg.strip() == 'over':
                        if test_support.verbose and \
                          self.server.connectionchatty:
                            sys.stdout.write(" server: client closed " +
                                             "connection\n")
                        self.close()
                        return
                    elif self.server.starttls_server and not self.sslconn \
                      and msg.strip() == 'STARTTLS':
                        if test_support.verbose and \
                          self.server.connectionchatty:
                            sys.stdout.write(" server: read STARTTLS " +
                                             "from client, sending OK...\n")
                        self.write("OK\n")
                        if not self.wrap_conn():
                            return
                    elif self.server.starttls_server and self.sslconn and \
                      msg.strip() == 'ENDTLS':
                        if test_support.verbose and \
                          self.server.connectionchatty:
                            sys.stdout.write(" server: read ENDTLS from " +
                                             "client, sending OK...\n")
                        self.write("OK\n")
                        self.sslconn.unwrap()
                        self.sslconn = None
                        if test_support.verbose and \
                          self.server.connectionchatty:
                            sys.stdout.write(" server: connection is now " +
                                             "unencrypted...\n")
                    else:
                        if test_support.verbose and \
                          self.server.connectionchatty:
                            ctype = (self.sslconn and "encrypted") or \
                              "unencrypted"
                            sys.stdout.write((" server: read %s (%s), " +
                                              "sending back %s (%s)...\n")
                                             % (repr(msg), ctype,
                                                repr(msg.lower()), ctype))
                        self.write(msg.lower())
                except ssl.SSLError:
                    if self.server.chatty:
                        handle_error("Test server failure:\n")
                    self.close()
                    self.running = False
                    # normally, we'd just stop here, but for the test
                    # harness, we want to stop the server
                    self.server.stop()

    def __init__(self, certificate, ssl_version=None,
                 certreqs=None, cacerts=None,
                 chatty=True, connectionchatty=False, starttls_server=False,
                 ciphers=None):

        if ssl_version is None:
            ssl_version = ssl.PROTOCOL_DTLSv1
        if certreqs is None:
            certreqs = ssl.CERT_NONE
        self.certificate = certificate
        self.protocol = ssl_version
        self.certreqs = certreqs
        self.cacerts = cacerts
        self.ciphers = ciphers
        self.chatty = chatty
        self.connectionchatty = connectionchatty
        self.starttls_server = starttls_server
        self.sock = socket.socket(AF_INET4_6, socket.SOCK_DGRAM)
        self.flag = None
        self.num_handlers = 0
        self.num_handlers_lock = threading.Lock()
        self.sock = ssl.wrap_socket(self.sock, server_side=True,
                                    certfile=self.certificate,
                                    cert_reqs=self.certreqs,
                                    ca_certs=self.cacerts,
                                    ssl_version=self.protocol,
                                    do_handshake_on_connect=False,
                                    ciphers=self.ciphers)
        if test_support.verbose and self.chatty:
            sys.stdout.write(' server:  wrapped server ' +
                             'socket as %s\n' % str(self.sock))
        self.sock.bind((HOST, 0))
        self.port = self.sock.getsockname()[1]
        self.active = False
        threading.Thread.__init__(self)
        self.daemon = True

    def start(self, flag=None):
        self.flag = flag
        self.starter = threading.current_thread().ident
        threading.Thread.start(self)

    def run(self):
        self.sock.settimeout(0.05)
        self.sock.listen(5)
        self.active = True
        if self.flag:
            # signal an event
            self.flag.set()
        while self.active:
            try:
                acc_ret = self.sock.accept()
                if acc_ret:
                    newconn, connaddr = acc_ret
                    if test_support.verbose and self.chatty:
                        sys.stdout.write(' server:  new connection from '
                                         + str(connaddr) + '\n')
                    handler = self.ConnectionHandler(self, newconn)
                    handler.start()
            except socket.timeout:
                pass
            except ssl.SSLError:
                pass
            except KeyboardInterrupt:
                self.stop()
        self.sock.close()

    def register_handler(self, add):
        with self.num_handlers_lock:
            if add:
                self.num_handlers += 1
            else:
                self.num_handlers -= 1
        assert self.num_handlers >= 0

    def stop(self):
        self.active = False
        if self.starter != threading.current_thread().ident:
            return
        self.join()  # don't allow spawning new handlers after we've checked
        last_msg = datetime.datetime.now()
        while self.num_handlers:
            time.sleep(0.05)
            now = datetime.datetime.now()
            if now > last_msg + datetime.timedelta(seconds=1):
                sys.stdout.write(' server: waiting for connections to close\n')
                last_msg = now

class AsyncoreEchoServer(threading.Thread):

    class EchoServer(asyncore.dispatcher):

        class ConnectionHandler(asyncore.dispatcher):

            def __init__(self, conn, timeout_tracker, server):
                asyncore.dispatcher.__init__(self, conn)
                self._timeout_tracker = timeout_tracker
                self._server = server
                self._ssl_accepting = True
                # Complete the handshake
                self.handle_read_event()

            def __hash__(self):
                return hash(self.socket)

            def readable(self):
                while self.socket.pending() > 0:
                    self.handle_read_event()
                if self._timeout_tracker.has_key(self) and \
                  datetime.datetime.now() >= self._timeout_tracker[self]:
                    self._timeout_tracker.pop(self)
                    try:
                        self.socket.handle_timeout()
                    except:
                        self.handle_close()
                        return False
                return True

            def writable(self):
                return False

            def _do_ssl_handshake(self):
                try:
                    self.socket.do_handshake()
                except ssl.SSLError, err:
                    if err.args[0] in (ssl.SSL_ERROR_WANT_READ,
                                       ssl.SSL_ERROR_WANT_WRITE,
                                       ssl.SSL_ERROR_SSL):
                        return
                    elif err.args[0] == ssl.SSL_ERROR_EOF:
                        return self.handle_close()
                    raise
                except socket.error, err:
                    if err.args[0] == errno.ECONNABORTED:
                        return self.handle_close()
                else:
                    self._ssl_accepting = False

            def handle_read(self):
                if self._ssl_accepting:
                    self._do_ssl_handshake()
                else:
                    data = self.recv(1024)
                    if data and data.strip() != 'over':
                        self.send(data.lower())
                if self.connected:
                    self._server.reset_timeout(self)
                self._server.check_timeout()
                if not self.connected:  # above called handle_close
                    return
                delta = self.socket.get_timeout()
                if delta:
                    self._timeout_tracker[self] = \
                      datetime.datetime.now() + delta

            def handle_close(self):
                if self._timeout_tracker.has_key(self):
                    self._timeout_tracker.pop(self)
                self._server._handlers.pop(self)
                self.close()
                if test_support.verbose:
                    sys.stdout.write(" server:  closed connection %s\n" %
                                     self.socket)

            def handle_error(self):
                raise

        def __init__(self, certfile, timeout_tracker):
            asyncore.dispatcher.__init__(self)
            self._timeout_tracker = timeout_tracker
            self._handlers = OrderedDict()
            sock = socket.socket(AF_INET4_6, socket.SOCK_DGRAM)
            sock.setblocking(False)
            sock.bind((HOST, 0))
            self.sockname = sock.getsockname()
            self.port = self.sockname[1]
            self.set_socket(ssl.wrap_socket(sock, server_side=True,
                                            certfile=certfile,
                                            do_handshake_on_connect=False))
            self.listen(5)

        def writable(self):
            return False

        def handle_accept(self):
            self.check_timeout()
            acc_ret = self.accept()
            if acc_ret:
                sock_obj, addr = acc_ret
                if test_support.verbose:
                    sys.stdout.write(" server:  new connection from " +
                                     "%s:%s\n" % (addr[0], str(addr[1:])))
                self._handlers[self.ConnectionHandler(sock_obj,
                                                      self._timeout_tracker,
                                                      self)] = \
                  datetime.datetime.now()

        def handle_error(self):
            raise

        def reset_timeout(self, handler):
            if self._handlers.has_key(handler):
                self._handlers.pop(handler)
                self._handlers[handler] = datetime.datetime.now()

        def check_timeout(self):
            now = datetime.datetime.now()
            while True:
                try:
                    handler = self._handlers.__iter__().next()  # oldest handler
                except StopIteration:
                    break  # there are no more handlers
                if now > self._handlers[handler] + CONNECTION_TIMEOUT:
                    handler.handle_close()
                else:
                    break  # the oldest handlers has not yet timed out

        def close(self):
            map(lambda x: x.handle_close(), self._handlers.keys())
            assert not self._handlers
            asyncore.dispatcher.close(self)

    def __init__(self, certfile):
        self.flag = None
        self.active = False
        self.timeout_tracker = {}
        self.server = self.EchoServer(certfile, self.timeout_tracker)
        self.sockname = self.server.sockname
        self.port = self.server.port
        threading.Thread.__init__(self)
        self.daemon = True

    def __str__(self):
        return "<%s %s>" % (self.__class__.__name__, self.server)

    def start(self, flag=None):
        self.flag = flag
        threading.Thread.start(self)

    def run(self):
        self.active = True
        if self.flag:
            self.flag.set()
        while self.active:
            now = datetime.datetime.now()
            future_timeouts = filter(lambda x: x > now,
                                     self.timeout_tracker.values())
            future_timeouts.append(now + datetime.timedelta(seconds=0.05))
            first_timeout = min(future_timeouts) - now
            asyncore.loop(first_timeout.total_seconds(), count=1)

    def stop(self):
        self.active = False
        self.join()
        self.server.close()

# Note that this HTTP-over-UDP server does not implement packet recovery and
# reordering, but it's good enough for testing on a loopback interface
class SocketServerHTTPSServer(threading.Thread):

    class HTTPSServerUDP(SocketServer.ThreadingTCPServer):

        def __init__(self, server_address, RequestHandlerClass, certfile):
            SocketServer.ThreadingTCPServer.__init__(self, server_address,
                                                     RequestHandlerClass, False)
            # account for dealing with a datagram socket
            self.socket = ssl.wrap_socket(socket.socket(AF_INET4_6,
                                                        socket.SOCK_DGRAM),
                                          server_side=True,
                                          certfile=certfile,
                                          do_handshake_on_connect=False)
            self.server_bind()
            self.server_activate()

        def __str__(self):
            return ('<%s %s:%s>' %
                    (self.__class__.__name__,
                     self.server_name,
                     self.server_port))

        def server_bind(self):
            """Override server_bind to store the server name."""
            SocketServer.ThreadingTCPServer.server_bind(self)
            host, port = self.socket.getsockname()[:2]
            self.server_name = socket.getfqdn(host)
            self.server_port = port

        def get_request(self):
            # account for the fact that accept can return nothing, and
            # according to BaseServer documentation, we should not block here
            acc_ret = self.socket.accept()
            if not acc_ret:
                raise socket.error("No new connection")
            return acc_ret

        def shutdown_request(self, request):
            # Notify client of termination
            request.unwrap()

    class RootedHTTPRequestHandler(SimpleHTTPRequestHandler):
        # need to override translate_path to get a known root,
        # instead of using os.curdir, since the test could be
        # run from anywhere

        server_version = "TestHTTPS-UDP/1.0"

        root = None

        def translate_path(self, path):
            """Translate a /-separated PATH to the local filename syntax.

            Components that mean special things to the local file system
            (e.g. drive or directory names) are ignored.  (XXX They should
            probably be diagnosed.)

            """
            # abandon query parameters
            path = urlparse.urlparse(path)[2]
            path = os.path.normpath(urllib.unquote(path))
            words = path.split('/')
            words = filter(None, words)
            path = self.root
            for word in words:
                drive, word = os.path.splitdrive(word)
                head, word = os.path.split(word)
                if word in self.root: continue
                path = os.path.join(path, word)
            return path

        def log_message(self, format, *args):
            # we override this to suppress logging unless "verbose"
            if test_support.verbose:
                sys.stdout.write(" server (%s:%d %s):\n   [%s] %s\n" %
                                 (self.server.server_address,
                                  self.server.server_port,
                                  self.request.cipher(),
                                  self.log_date_time_string(),
                                  format%args))


    def __init__(self, certfile):
        self.flag = None
        self.RootedHTTPRequestHandler.root = os.path.split(CERTFILE)[0]
        self.server = self.HTTPSServerUDP(
            (HOST, 0), self.RootedHTTPRequestHandler, certfile)
        self.port = self.server.server_port
        threading.Thread.__init__(self)
        self.daemon = True

    def __str__(self):
        return "<%s %s>" % (self.__class__.__name__, self.server)

    def start(self, flag=None):
        self.flag = flag
        threading.Thread.start(self)

    def run(self):
        if self.flag:
            self.flag.set()
        self.server.serve_forever(0.05)

    def stop(self):
        self.server.shutdown()


def bad_cert_test(certfile):
    """
    Launch a server with CERT_REQUIRED, and check that trying to
    connect to it with the given client certificate fails.
    """
    server = ThreadedEchoServer(CERTFILE,
                                certreqs=ssl.CERT_REQUIRED,
                                cacerts=ISSUER_CERTFILE, chatty=False)
    flag = threading.Event()
    server.start(flag)
    # wait for it to start
    flag.wait()
    # try to connect
    try:
        try:
            s = ssl.wrap_socket(socket.socket(AF_INET4_6, socket.SOCK_DGRAM),
                                certfile=certfile,
                                ssl_version=ssl.PROTOCOL_DTLSv1)
            s.connect((HOST, server.port))
        except ssl.SSLError, x:
            if test_support.verbose:
                sys.stdout.write("\nSSLError is %s\n" % x[1])
        except socket.error, x:
            if test_support.verbose:
                sys.stdout.write("\nsocket.error is %s\n" % x[1])
        else:
            raise AssertionError("Use of invalid cert should have failed!")
    finally:
        server.stop()

def server_params_test(certfile, protocol, certreqs, cacertsfile,
                       client_certfile, client_protocol=None,
                       indata="FOO\n", ciphers=None, chatty=True,
                       connectionchatty=False):
    """
    Launch a server, connect a client to it and try various reads
    and writes.
    """
    server = ThreadedEchoServer(certfile,
                                certreqs=certreqs,
                                ssl_version=protocol,
                                cacerts=cacertsfile,
                                ciphers=ciphers,
                                chatty=chatty,
                                connectionchatty=connectionchatty)
    flag = threading.Event()
    server.start(flag)
    # wait for it to start
    flag.wait()
    # try to connect
    if client_protocol is None:
        client_protocol = protocol
    try:
        s = ssl.wrap_socket(socket.socket(AF_INET4_6, socket.SOCK_DGRAM),
                            certfile=client_certfile,
                            ca_certs=cacertsfile,
                            ciphers=ciphers,
                            cert_reqs=certreqs,
                            ssl_version=client_protocol)
        s.connect((HOST, server.port))
        for arg in [indata, bytearray(indata), memoryview(indata)]:
            if connectionchatty:
                if test_support.verbose:
                    sys.stdout.write(
                        " client:  sending %s...\n" % (repr(arg)))
            s.write(arg)
            outdata = s.read()
            if connectionchatty:
                if test_support.verbose:
                    sys.stdout.write(" client:  read %s\n" % repr(outdata))
            if outdata != indata.lower():
                raise AssertionError(
                    "bad data <<%s>> (%d) received; expected <<%s>> (%d)\n"
                    % (outdata[:min(len(outdata),20)], len(outdata),
                       indata[:min(len(indata),20)].lower(), len(indata)))
        s.write("over\n")
        if connectionchatty:
            if test_support.verbose:
                sys.stdout.write(" client:  closing connection.\n")
        s.close()
    finally:
        server.stop()

def try_protocol_combo(server_protocol,
                       client_protocol,
                       expect_success,
                       certsreqs=None):
    if certsreqs is None:
        certsreqs = ssl.CERT_NONE
    certtype = {
        ssl.CERT_NONE: "CERT_NONE",
        ssl.CERT_OPTIONAL: "CERT_OPTIONAL",
        ssl.CERT_REQUIRED: "CERT_REQUIRED",
    }[certsreqs]
    if test_support.verbose:
        formatstr = (expect_success and " %s->%s %s\n") or " {%s->%s} %s\n"
        sys.stdout.write(formatstr %
                         (ssl.get_protocol_name(client_protocol),
                          ssl.get_protocol_name(server_protocol),
                          certtype))
    try:
        # NOTE: we must enable "ALL" ciphers, otherwise an SSLv23 client
        # will send an SSLv3 hello (rather than SSLv2) starting from
        # OpenSSL 1.0.0 (see issue #8322).
        server_params_test(CERTFILE, server_protocol, certsreqs,
                           ISSUER_CERTFILE, CERTFILE, client_protocol,
                           ciphers="ALL", chatty=False)
    # Protocol mismatch can result in either an SSLError, or a
    # "Connection reset by peer" error.
    except ssl.SSLError:
        if expect_success:
            raise
    except socket.error as e:
        if expect_success or e.errno != errno.ECONNRESET:
            raise
    else:
        if not expect_success:
            raise AssertionError(
                "Client protocol %s succeeded with server protocol %s!"
                % (ssl.get_protocol_name(client_protocol),
                   ssl.get_protocol_name(server_protocol)))


class ThreadedTests(unittest.TestCase):

    def test_unreachable(self):
        server = socket.socket(AF_INET4_6, socket.SOCK_DGRAM)
        server.bind((HOST, 0))
        port = server.getsockname()[1]
        server.close()
        s = ssl.wrap_socket(socket.socket(AF_INET4_6, socket.SOCK_DGRAM))
        self.assertRaisesRegexp(ssl.SSLError,
                                "The peer address is not reachable",
                                s.connect, (HOST, port))

    def test_echo(self):
        """Basic test of an SSL client connecting to a server"""
        if test_support.verbose:
            sys.stdout.write("\n")
        server_params_test(CERTFILE, ssl.PROTOCOL_DTLSv1, ssl.CERT_NONE,
                           CERTFILE, CERTFILE, ssl.PROTOCOL_DTLSv1,
                           chatty=True, connectionchatty=True)

    def test_getpeercert(self):
        if test_support.verbose:
            sys.stdout.write("\n")
        server = ThreadedEchoServer(CERTFILE,
                                    certreqs=ssl.CERT_NONE,
                                    ssl_version=ssl.PROTOCOL_DTLSv1,
                                    cacerts=CERTFILE,
                                    chatty=False)
        flag = threading.Event()
        server.start(flag)
        # wait for it to start
        flag.wait()
        # try to connect
        try:
            s = ssl.wrap_socket(socket.socket(AF_INET4_6, socket.SOCK_DGRAM),
                                certfile=CERTFILE,
                                ca_certs=ISSUER_CERTFILE,
                                cert_reqs=ssl.CERT_REQUIRED,
                                ssl_version=ssl.PROTOCOL_DTLSv1)
            s.connect((HOST, server.port))
            cert = s.getpeercert()
            self.assertTrue(cert, "Can't get peer certificate.")
            cipher = s.cipher()
            if test_support.verbose:
                sys.stdout.write(pprint.pformat(cert) + '\n')
                sys.stdout.write("Connection cipher is " + str(cipher) + '.\n')
            if 'subject' not in cert:
                self.fail("No subject field in certificate: %s." %
                          pprint.pformat(cert))
            if ((('organizationName', 'Ray Srv Inc'),)
                not in cert['subject']):
                self.fail(
                    "Missing or invalid 'organizationName' field in "
                    "certificate subject; should be 'Ray Srv Inc'.")
            s.write("over\n")
            s.close()
        finally:
            server.stop()

    def test_empty_cert(self):
        """Connecting with an empty cert file"""
        bad_cert_test(os.path.join(os.path.dirname(__file__) or os.curdir,
                                   "certs", "nullcert.pem"))
    def test_malformed_cert(self):
        """Connecting with a badly formatted certificate (syntax error)"""
        bad_cert_test(os.path.join(os.path.dirname(__file__) or os.curdir,
                                   "certs", "badcert.pem"))
    def test_nonexisting_cert(self):
        """Connecting with a non-existing cert file"""
        bad_cert_test(os.path.join(os.path.dirname(__file__) or os.curdir,
                                   "certs", "wrongcert.pem"))
    def test_malformed_key(self):
        """Connecting with a badly formatted key (syntax error)"""
        bad_cert_test(os.path.join(os.path.dirname(__file__) or os.curdir,
                                   "certs", "badkey.pem"))

    def test_protocol_dtlsv1(self):
        """Connecting to a DTLSv1 server with various client options"""
        if test_support.verbose:
            sys.stdout.write("\n")
        # server: 1.0 - client: 1.0 -> ok
        try_protocol_combo(ssl.PROTOCOL_DTLSv1, ssl.PROTOCOL_DTLSv1, True)
        try_protocol_combo(ssl.PROTOCOL_DTLSv1, ssl.PROTOCOL_DTLSv1, True,
                           ssl.CERT_OPTIONAL)
        try_protocol_combo(ssl.PROTOCOL_DTLSv1, ssl.PROTOCOL_DTLSv1, True,
                           ssl.CERT_REQUIRED)
        # server: any - client: 1.0 and 1.2(any) -> ok
        try_protocol_combo(ssl.PROTOCOL_DTLS, ssl.PROTOCOL_DTLSv1, True)
        try_protocol_combo(ssl.PROTOCOL_DTLS, ssl.PROTOCOL_DTLSv1, True,
                           ssl.CERT_REQUIRED)
        try_protocol_combo(ssl.PROTOCOL_DTLS, ssl.PROTOCOL_DTLSv1_2, True)
        try_protocol_combo(ssl.PROTOCOL_DTLS, ssl.PROTOCOL_DTLSv1_2, True,
                           ssl.CERT_REQUIRED)
        try_protocol_combo(ssl.PROTOCOL_DTLS, ssl.PROTOCOL_DTLS, True)
        try_protocol_combo(ssl.PROTOCOL_DTLS, ssl.PROTOCOL_DTLS, True,
                           ssl.CERT_REQUIRED)
        # server: 1.0 - client: 1.2 -> fail
        try_protocol_combo(ssl.PROTOCOL_DTLSv1, ssl.PROTOCOL_DTLSv1_2, False)
        try_protocol_combo(ssl.PROTOCOL_DTLSv1, ssl.PROTOCOL_DTLSv1_2, False,
                           ssl.CERT_REQUIRED)
        # server: 1.2 - client: 1.0 -> fail
        try_protocol_combo(ssl.PROTOCOL_DTLSv1_2, ssl.PROTOCOL_DTLSv1, False)
        try_protocol_combo(ssl.PROTOCOL_DTLSv1_2, ssl.PROTOCOL_DTLSv1, False,
                           ssl.CERT_REQUIRED)
        # server: 1.2 - client: 1.2 -> ok
        try_protocol_combo(ssl.PROTOCOL_DTLSv1_2, ssl.PROTOCOL_DTLSv1_2, True)
        try_protocol_combo(ssl.PROTOCOL_DTLSv1_2, ssl.PROTOCOL_DTLSv1_2, True,
                           ssl.CERT_REQUIRED)

    def test_starttls(self):
        """Switching from clear text to encrypted and back again."""
        msgs = ("msg 1", "MSG 2", "STARTTLS", "MSG 3", "msg 4", "ENDTLS",
                "msg 5", "msg 6")

        server = ThreadedEchoServer(CERTFILE,
                                    ssl_version=ssl.PROTOCOL_DTLSv1,
                                    starttls_server=True,
                                    chatty=True,
                                    connectionchatty=True)
        flag = threading.Event()
        server.start(flag)
        # wait for it to start
        flag.wait()
        # try to connect
        wrapped = False
        try:
            s = ssl.wrap_socket(socket.socket(AF_INET4_6, socket.SOCK_DGRAM), ssl_version=ssl.PROTOCOL_DTLSv1)
            s.connect((HOST, server.port))
            s = s.unwrap()
            if test_support.verbose:
                sys.stdout.write("\n")
            for indata in msgs:
                if test_support.verbose:
                    sys.stdout.write(
                        " client:  sending %s...\n" % repr(indata))
                if wrapped:
                    conn.write(indata)
                    outdata = conn.read()
                else:
                    s.send(indata)
                    outdata = s.recv(1024)
                if (indata == "STARTTLS" and
                    outdata.strip().lower().startswith("ok")):
                    # STARTTLS ok, switch to secure mode
                    if test_support.verbose:
                        sys.stdout.write(
                            " client:  read %s from server, starting TLS...\n"
                            % repr(outdata))
                    conn = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_DTLSv1)
                    wrapped = True
                elif (indata == "ENDTLS" and
                    outdata.strip().lower().startswith("ok")):
                    # ENDTLS ok, switch back to clear text
                    if test_support.verbose:
                        sys.stdout.write(
                            " client:  read %s from server, ending TLS...\n"
                            % repr(outdata))
                    s = conn.unwrap()
                    wrapped = False
                else:
                    if test_support.verbose:
                        sys.stdout.write(
                            " client:  read %s from server\n" % repr(outdata))
            if test_support.verbose:
                sys.stdout.write(" client:  closing connection.\n")
            if wrapped:
                conn.write("over\n")
            else:
                s.send("over\n")
            s.close()
        finally:
            server.stop()

    def test_socketserver(self):
        """Using a SocketServer to create and manage SSL connections."""
        server = SocketServerHTTPSServer(CERTFILE)
        flag = threading.Event()
        server.start(flag)
        # wait for it to start
        flag.wait()
        # try to connect
        try:
            if test_support.verbose:
                sys.stdout.write('\n')
            with open(CERTFILE, 'rb') as f:
                d1 = f.read()
            d2 = []
            # now fetch the same data from the HTTPS-UDP server
            s = ssl.wrap_socket(socket.socket(AF_INET4_6, socket.SOCK_DGRAM))
            s.connect((HOST, server.port))
            fl = "/" + os.path.split(CERTFILE)[1]
            s.write("GET " + fl + " HTTP/1.1\r\n" +
                    "Host: " + HOST + "\r\n\r\n")
            content = False
            last_buf = ""
            while True:
                try:
                    buf = last_buf + s.read()
                except ssl.SSLError as err:
                    if err.args[0] == ssl.SSL_ERROR_ZERO_RETURN:
                        s = s.unwrap()  # complete shutdown protocol with server
                        break
                    raise
                if test_support.verbose:
                    sys.stdout.write(
                        " client: read %d bytes from remote server '%s'\n"
                        % (len(buf), server))
                if content:
                    d2.append(buf)
                    continue
                ind = buf.find("\r\n\r\n")
                if ind < 0:
                    last_buf = buf[-3:]  # find double-newline across buffers
                    continue
                d2.append(buf[ind + 4:])
                content = True
                last_buf = ""
            s.close()
            self.assertEqual(d1, ''.join(d2))
        finally:
            server.stop()

    def test_asyncore_server(self):
        """Check the example asyncore integration."""
        indata = "TEST MESSAGE of mixed case\n"

        if test_support.verbose:
            sys.stdout.write("\n")
        server = AsyncoreEchoServer(CERTFILE)
        flag = threading.Event()
        server.start(flag)
        # wait for it to start
        flag.wait()
        # try to connect
        try:
            s = ssl.wrap_socket(socket.socket(AF_INET4_6, socket.SOCK_DGRAM))
            s.connect((HOST, server.port))
            if test_support.verbose:
                sys.stdout.write(
                    " client:  sending %s...\n" % (repr(indata)))
            s.write(indata)
            outdata = s.read()
            if test_support.verbose:
                sys.stdout.write(" client:  read %s\n" % repr(outdata))
            if outdata != indata.lower():
                self.fail(
                    "bad data <<%s>> (%d) received; expected <<%s>> (%d)\n"
                    % (outdata[:min(len(outdata),20)], len(outdata),
                       indata[:min(len(indata),20)].lower(), len(indata)))
            s.write("over\n")
            if test_support.verbose:
                sys.stdout.write(" client:  closing connection.\n")
            s.close()
        finally:
            server.stop()

    def test_recv_send(self):
        """Test recv(), send() and friends."""
        if test_support.verbose:
            sys.stdout.write("\n")

        server = ThreadedEchoServer(CERTFILE,
                                    certreqs=ssl.CERT_NONE,
                                    ssl_version=ssl.PROTOCOL_TLSv1,
                                    cacerts=CERTFILE,
                                    chatty=True,
                                    connectionchatty=False)
        flag = threading.Event()
        server.start(flag)
        # wait for it to start
        flag.wait()
        # try to connect
        s = ssl.wrap_socket(socket.socket(AF_INET4_6, socket.SOCK_DGRAM),
                            server_side=False,
                            certfile=CERTFILE,
                            ca_certs=CERTFILE,
                            cert_reqs=ssl.CERT_NONE,
                            ssl_version=ssl.PROTOCOL_DTLSv1)
        s.connect((HOST, server.port))
        try:
            # helper methods for standardising recv* method signatures
            def _recv_into():
                b = bytearray("\0"*100)
                count = s.recv_into(b)
                return b[:count]

            def _recvfrom_into():
                b = bytearray("\0"*100)
                count, addr = s.recvfrom_into(b)
                return b[:count]

            # (name, method, whether to expect success, *args)
            send_methods = [
                ('send', s.send, True, []),
                ('sendto', s.sendto, False, ["some.address"]),
                ('sendall', s.sendall, True, []),
            ]
            recv_methods = [
                ('recv', s.recv, True, []),
                ('recvfrom', s.recvfrom, False, ["some.address"]),
                ('recv_into', _recv_into, True, []),
                ('recvfrom_into', _recvfrom_into, False, []),
            ]
            data_prefix = u"PREFIX_"

            for meth_name, send_meth, expect_success, args in send_methods:
                indata = data_prefix + meth_name
                try:
                    send_meth(indata.encode('ASCII', 'strict'), *args)
                    outdata = s.read()
                    outdata = outdata.decode('ASCII', 'strict')
                    if outdata != indata.lower():
                        self.fail(
                            "While sending with <<%s>> bad data "
                            "<<%r>> (%d) received; "
                            "expected <<%r>> (%d)\n" % (
                                meth_name, outdata[:20], len(outdata),
                                indata[:20], len(indata)
                            )
                        )
                except ValueError as e:
                    if expect_success:
                        self.fail(
                            "Failed to send with method <<%s>>; "
                            "expected to succeed.\n" % (meth_name,)
                        )
                    if not str(e).startswith(meth_name):
                        self.fail(
                            "Method <<%s>> failed with unexpected "
                            "exception message: %s\n" % (
                                meth_name, e
                            )
                        )

            for meth_name, recv_meth, expect_success, args in recv_methods:
                indata = data_prefix + meth_name
                try:
                    s.send(indata.encode('ASCII', 'strict'))
                    outdata = recv_meth(*args)
                    outdata = outdata.decode('ASCII', 'strict')
                    if outdata != indata.lower():
                        self.fail(
                            "While receiving with <<%s>> bad data "
                            "<<%r>> (%d) received; "
                            "expected <<%r>> (%d)\n" % (
                                meth_name, outdata[:20], len(outdata),
                                indata[:20], len(indata)
                            )
                        )
                except ValueError as e:
                    if expect_success:
                        self.fail(
                            "Failed to receive with method <<%s>>; "
                            "expected to succeed.\n" % (meth_name,)
                        )
                    if not str(e).startswith(meth_name):
                        self.fail(
                            "Method <<%s>> failed with unexpected "
                            "exception message: %s\n" % (
                                meth_name, e
                            )
                        )
                    # consume data
                    s.read()

            s.write("over\n".encode("ASCII", "strict"))
            s.close()
        finally:
            server.stop()

    def test_handshake_timeout(self):
        # Issue #5103: SSL handshake must respect the socket timeout
        server = socket.socket(AF_INET4_6, socket.SOCK_DGRAM)
        server.bind((HOST, 0))
        port = server.getsockname()[1]

        try:
            try:
                c = socket.socket(AF_INET4_6, socket.SOCK_DGRAM)
                c.settimeout(0.2)
                c.connect((HOST, port))
                # Will attempt handshake and time out
                self.assertRaisesRegexp(ssl.SSLError, "timed out",
                                        ssl.wrap_socket, c)
            finally:
                c.close()
            try:
                c = socket.socket(AF_INET4_6, socket.SOCK_DGRAM)
                c.settimeout(0.2)
                c = ssl.wrap_socket(c)
                # Will attempt handshake and time out
                self.assertRaisesRegexp(ssl.SSLError, "timed out",
                                        c.connect, (HOST, port))
            finally:
                c.close()
        finally:
            server.close()


def hostname_for_protocol(protocol):
    global HOST
    # We can't quite predict the content of the hosts file, but we prefer names
    # to numbers in order to test name resolution; if we can't find a name,
    # then fall back to a number for the given protocol
    for name in HOST, "localhost", "ip6-localhost", "127.0.0.1", "::1":
        try:
            socket.getaddrinfo(name, 0, protocol)
        except socket.error:
            pass
        else:
            HOST = name
            return
    # Is the loopback interface enabled along with ipv6 for that interface?
    raise Exception("Failed to select hostname for protocol %d" % protocol)

def test_main(verbose=True):
    global CERTFILE, ISSUER_CERTFILE, OTHER_CERTFILE, AF_INET4_6
    CERTFILE = os.path.join(os.path.dirname(__file__) or os.curdir,
                            "certs", "keycert.pem")
    ISSUER_CERTFILE = os.path.join(os.path.dirname(__file__) or os.curdir,
                                   "certs", "ca-cert.pem")
    OTHER_CERTFILE = os.path.join(os.path.dirname(__file__) or os.curdir,
                                   "certs", "yahoo-cert.pem")

    for fl in CERTFILE, ISSUER_CERTFILE, OTHER_CERTFILE:
        if not os.path.exists(fl):
            raise Exception("Can't read certificate files!")

    TestSupport.verbose = verbose
    reset_default_demux()
    do_patch()
    for demux in "platform-native", "routing":
        for AF_INET4_6 in socket.AF_INET, socket.AF_INET6:
            print "Suite run: demux: %s, protocol: %d" % (demux, AF_INET4_6)
            hostname_for_protocol(AF_INET4_6)
            res = unittest.main(exit=False).result.wasSuccessful()
            if not res:
                print "Suite run failed: demux: %s, protocol: %d" % (
                    demux, AF_INET4_6)
                sys.exit(True)
        if not force_routing_demux():
            break

if __name__ == "__main__":
    verbose = True if len(sys.argv) > 1 and sys.argv[1] == "-v" else False
    test_main(verbose)
