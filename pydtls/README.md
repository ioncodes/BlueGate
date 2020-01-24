# Datagram Transport Layer Security for Python

PyDTLS brings Datagram Transport Layer Security (DTLS - RFC 6347:
http://tools.ietf.org/html/rfc6347) to the Python environment. In a
nutshell, DTLS brings security (encryption, server authentication,
user authentication, and message authentication) to UDP datagram
payloads in a manner equivalent to what SSL/TLS does for TCP stream
content.

DTLS is now very easy to use in Python. If you're familiar with the
ssl module in Python's standard library, you already know how. All it
takes is passing a datagram/UDP socket to the *wrap_socket* function
instead of a stream/TCP socket. Here's how one sets up the client side
of a connection:

```
import ssl
from socket import socket, AF_INET, SOCK_DGRAM
from dtls import do_patch
do_patch()
sock = ssl.wrap_socket(socket(AF_INET, SOCK_DGRAM))
sock.connect(('foo.bar.com', 1234))
sock.send('Hi there')
```

As of version 1.2.0, PyDTLS supports DTLS version 1.2 in addition to
version 1.0. This version also introduces forward secrecy using
elliptic curve cryptography and more fine-grained configuration options.

## Installation

To install from PyPI, on any supported platform enter:

```
pip install Dtls
```

## Design Goals

The primary design goal of PyDTLS is broad availability. It has therefore
been built to be widely compatible with the following:

  * Operating systems: apart from the Python standard library, PyDTLS
    relies on the OpenSSL library only. OpenSSL is widely ported, and
    in fact the Python standard library's *ssl* module also uses it.
  * Python runtime environments: PyDTLS is a package consisting of
    pure Python modules only. It should therefore be portable to many
    interpreters and runtime environments. It interfaces with OpenSSL
    strictly through the standard library's *ctypes* foreign function
    library.
  * The Python standard library: the standard library's *ssl* module is
    Python's de facto interface to SSL/TLS. PyDTLS aims to be compatible
    with the full public interface presented by this module. The ssl
    module ought to behave identically with respect to all of its
    functions and options when used in conjunction with PyDTLS and
    datagram sockets as when used without PyDTLS and stream sockets.
  * Connection-based protocols: as outlined below, layering security
    on top of datagram sockets requires introducing certain
    connection constructs normally absent from datagram
    sockets. These constructs have been added in such a way as to be
    compatible with code that expects to interoperate with
    connection-oriented stream sockets. For example, code that
    expects to go through server-side bind/listen/accept connection
    establishment should be reusable with PyDTLS sockets.

## Distributions

PyDTLS requires version 1.0.0 or higher of the OpenSSL
library. Earlier versions are reported not to offer stable DTLS
support. Since packaged distributions of this version of OpenSSL are
available for many popular operating systems, OpenSSL-1.0.0 is an
installation requirement before PyDTLS functionality can be called.
On Ubuntu 12.04 LTS, for example, the Python interpreter links with
libcrypto.so.1.0.0 and libssl.so.1.0.0, and so use of PyDTLS requires
no further installation steps.

In comparison, installation of OpenSSL on Microsoft Windows operating
systems is inconvenient. For this reason, source distributions of
PyDTLS are available that include OpenSSL dll's for 32-bit and 64-bit
Windows. All dll's have been linked with the Visual Studio 2008
version of the Microsoft C runtime library, msvcr90.dll, the version
used by CPython 2.7. Installation of Microsoft redistributable runtime
packages should therefore not be required on machines with CPython
2.7. The version of OpenSSL distributed with PyDTLS 0.1.0 is 1.0.1c.
The version distributed with PyDTLS 1.2.0 is commit
248cf959672041f38f4d80a4a09ee01d8ab04fe8 (branch OpenSSL_1_0_2-stable,
1.0.2l-dev, containing a desirable fix to DTLSv1_listen not present
in 1.0.2k, the stable version at the time of PyDTLS 1.2.0 release).

The OpenSSL version used by PyDTLS can be determined from the values
of *sslconnection's* DTLS_OPENSSL_VERSION_NUMBER,
DTLS_OPENSSL_VERSION, and DTLS_OPENSSL_VERSION_INFO. These variables
are available through the *ssl* module also if *do_patch* has been
called (see below). Note that the OpenSSL version used by PyDTLS may
differ from the one used by the *ssl* module.

## Interfaces

PyDTLS' top-level package, *dtls*, provides DTLS support through the
**SSLConnection** class of its *sslconnection*
module. **SSLConnection** is in-line documented, and
dtls/test/echo_seq.py demonstrates how to take a simple echo server
through a listen/accept/echo/shutdown sequence using this class. The
corresponding client side can look like the snippet at the top of this
document, followed by a call to the *unwrap* method for shutdown (or a
call to the **SSLConnection** *shutdown* method, if an instance of
this class is used for the client side also). Note that the *dtls*
package does not depend on the standard library's *ssl* module, and
**SSLConnection** can therefore be used in environments where *ssl* is
unavailable or incompatible.

It is expected that with the *ssl* module being an established, familiar
interface to TLS, it will be the preferred module through which to
access DTLS. To do so, one must call the *dtls* package's *do_patch*
function before passing sockets of type SOCK_DGRAM to either *ssl's*
*wrap_socket* function, or *ssl's* **SSLSocket** constructor.

It should be noted that once *do_patch* is called, *dtls* will raise
exceptions of type **ssl.SSLError** instead of its default
**dtls.err.SSLError**. This allows users' error handling code paths to
remain identical when interfacing with *ssl* across stream and
datagram sockets.

## Connection Handling

The DTLS protocol implies a connection as an association between two
network peers where the overall association state is characterized by the
handshake status of each peer endpoint (see RFC 6347). The OpenSSL library
records this handshake status in "SSL" type instances (a.k.a. struct
ssl_st). Datagrams can be securely sent and received by referring to a
unique "SSL" instance after handshaking has been completed with this
instance and its network peer. A connection is implied in that traffic
may be directed to or received from only that network peer with whose
"SSL" instance the handshake has been completed. The fact that the
underlying network protocol, UDP in most cases, is itself connectionless
is immaterial.

Further, in order to prevent denial-of-service attacks on UDP DTLS
servers, clients must undergo a cookie exchange phase early in the
handshaking protocol, and before server-side resources are committed to
a particular client (see section 4.2.1 of RFC 6347). The cookie exchange
proves to the server that a client can indeed receive IP traffic at
the source IP address with which its handshake-initiating ClientHello
datagram is marked.

PyDTLS implements this connection establishment through the *connect*
method on the client side, and the *accept* method on the server side.
The latter returns a new **dtls.SSLConnection** or **ssl.SSLSocket**
object (depending on which interface is used, see above), which is
"connected" to its peer. In addition to the *read* and *write* methods
(at both interface levels), **SSLSocket's** *send* and *recv* methods
can be used; use of *sendto* and *recvfrom* on connected sockets is
prohibited by *ssl*. *accept* returns peer address information, as
expected. Note that when using the *ssl* interface to *dtls*, *listen*
must be called before calling *accept*.

## Demultiplexing

At the network io layer, only datagrams from its connected peer must be
passed to a **SSLConnection** or **SSLSocket** object (unless the object
is unconnected on the server-side, in which case it can be in listening
mode, the initial server-side socket whose role it is to listen for
incoming client connection requests).

The initial server-side listening socket is not useful for performing this
datagram routing function. This is because it must remain unconnected and
ready to receive additional connection requests from new, unknown clients.

The function of passing incoming datagrams to the proper connection is
performed by the *dtls.demux* package. **SSLConnection** requests a new
connection from the demux when a handshake has cleared the cookie
exchange phase. An efficient implementation of this request is provided
by the *osnet* module of the demux package: it creates a new socket that
is bound to the same network interface and port as the listening socket,
but connected to the peer. UDP stacks such as the one included with Linux
route incoming datagrams to such a connected socket in preference to an
unconnected socket bound to the same port.

Unfortunately such is not the behavior on Microsoft Windows. Windows
UDP routes datagrams to whichever currently existing socket bound to
the particular port the earliest (and whether or not that socket is
unconnected, or connected to the datagram's peer, or a different
peer). Other sockets bound to the same port will not receive traffic,
if and until they become the earliest bound socket because another
socket is closed.

The demux package therefore provides and automatically selects the module
*router* on Windows platforms. This module also creates a new socket when
receiving a new connection request; but instead of binding this socket
to the same port as the listening socket, it binds to a new ephemeral
port. *router* then forwards datagrams originating from the peer for which
a connection was requested to the corresponding socket.

For efficiency's sake, no forwarding is performed on outgoing traffic.
Instead, **SSLConnection** directs outgoing traffic from the original
listening socket, using *sendto*. At the OpenSSL level this requires
separate read and write datagram BIO's for an "SSL" instance, one in
"connected" state and one in "peer set" state, respectively, and
associated with two separate network sockets.

From the perspective of a PyDTLS user, this selection of and
difference between demux implementations should be transparent, with
the possible exception of performance deviation. This transparency
does however have some limits: for example, when *router* is in use,
the *accept* methods can return *None*. This happens when
**SSLConnection** detects that the demux has forwarded a datagram to a
known connection instead of initiating a connection to a new peer
through *accept*.  Returning *None* in this case is important whenever
non-blocking sockets or sockets with timeouts are used, since another
socket might now be readable as a result of the forwarded
datagram. *accept* must return so that the application can iterate on
its asynchronous *select* loop.

## Shutdown and Unwrapping

PyDTLS implements the SSL/TLS shutdown protocol as it has been adapted
for DTLS. **SSLConnection's** *shutdown* and **SSLSocket's** *unwrap*
invoke this protocol. As is the case with DTLS handshaking in general,
applications must be prepared to use the *get_timeout* and
*handle_timeout* methods in addition to re-invoking *shutdown* or
*unwrap* when sockets become readable and an exception carried
SSL_ERROR_WANT_READ. (See more on asynchronous IO in the Testing section.)

**SSLConnection's** *shutdown* and **SSLSocket's** *unwrap* return a
(possibly new) socket that can be used for unsecured communication
with the peer, as set forth by the *ssl* module. The demux
infrastructure remains in use for this communication until the
returned socket is cleaned up.  Note that when the *router* demux is
in use, the object returned will be one derived from
*socket.socket*. This is because the send and recv paths must still be
directed to two different OS sockets. In addition, the right thing
happens if secured communication is resumed over such a socket by
passing it to *ssl.wrap_socket* or the **SSLConnection**
constructor. If *osnet* is used, an actual *socket.socket* instance is
returned.

## Framework Compatibility

PyDTLS sockets have been tested under the following usage modes:

  * Using blocking sockets and sockets with timeouts in
    multi-threaded UDP servers
  * Using non-blocking sockets, and in conjunction with the
    asynchronous socket handler, asyncore
  * Using blocking sockets, and in conjunction with the network
    server framework SocketServer - ThreadingTCPServer (this works
    because of PyDTLS's emulation of connection-related calls)

## Multi-thread Support

Using multiple threads with OpenSSL requires implementing a locking
callback. PyDTLS does implement this, and therefore multi-threaded
programming with PyDTLS is safe in any environment. However, being a
pure Python library, these callbacks do carry some overhead. The *ssl*
module implements an equivalent locking callback in its C extension
module. Not requiring interpreter re-entry, this approach can be
expected to perform better. PyDTLS therefore queries OpenSSL as to
whether a locking callback is already in place, and does not overwrite
it if there is. Loading *ssl* can therefore improve performance, even
when only the *sslconnection* interface is used.

Note that loading order does not matter: to obtain the performance
benefit, *ssl* can be loaded before or after the dtls package. This is
because *ssl* does not do an equivalent existing locking callback
check, and will simply overwrite the PyDTLS callback if it has already
been installed. But *ssl* should not be loaded while *dtls* operation
is already in progress, when some locks may be in their acquired
state.

Also note that this performance enhancement is available only on
platforms where PyDTLS loads the same OpenSSL shared object as
*ssl*. On Ubuntu 12.04, for example, this is the case, but on
Microsoft Windows it is not.

## Testing

A simple echo server is available to be executed from the project root
directory with `python -m dtls.test.echo_seq`. The echo server is
reachable using the code snippet at the top of this document, using port
28000 at "localhost".

Unit test suites can be executed from the project root directory with
`python -m dtls.test.unit [-v]` and `python -m dtls.test.unit_wrapper`
(for the client and server wrappers)

Almost all of the Python standard library's *ssl* unit tests from the
module *test_ssl.py* have been ported to *dtls.test.unit.py*. All tests
have been adjusted to operate with datagram sockets. On Linux, each
test is executed four times, varying the address family among IPv4 and
IPv6 and the demux among *osnet* and *router*. On Windows, where
*osnet* is unavailable, each test is run twice, once with IPv4 and once
with IPv6.

The unit test suite includes tests for each of the above-mentioned
compatible frameworks. The class **AsyncoreEchoServer** serves as an
example of how to use non-blocking datagram sockets and implement the
resulting timeout detection requirements. DTLS in general and OpenSSL
in particular require being called back when used with non-blocking
sockets (or sockets with timeout option) after DTLS timeouts expire to
handle packet loss using re-transmission during a
handshake. Handshaking may occur during any read or write operation,
even after an initial handshake completes successfully, in case
renegotiation is requested by a peer.

Running with the -v switch executes all unit tests in verbose mode.

dtls/test/test_perf.py implements an interactive performance test
suite that compares the raw throughput of TCP, UDP, SSL, and DTLS.
It can be executed locally through the loopback interface, or between
remote clients and servers. In the latter case, test jobs are sent to
remote connected clients whenever a suite run is initiated through the
interactive interface. Run test_perf.py -h for more information.

It should be noted that comparing the performance of protocols that
don't offer congestion control (UDP and DTLS) with those that do (TCP
and SSL) is a difficult undertaking. Raw throughput even across
gigabit network links can be expected to suffer without congestion
control and peers that generate data as fast as possible without
throttling (as this test does): the link's throughput will drop
significantly as it enters congestion collapse. Similarly, loopback is
an imperfect test interface since it rarely drops packets, and never
duplicates or reorders them (thus negating the relative performance
benefits of DTLS over SSL). Nevertheless, some useful insights can be
gained by observing the operation of test_perf.py, including software
stack behavior in the presence of some amount of packet loss.

## Logging

The *dtls* package and its sub-packages log various occurrences,
primarily events that can aid debugging. Especially *router* emits many
messages when the logging level is set to at least *logging.DEBUG*.
dtls/test/echo_seq.py activates this logging level during its operation.

## Currently Supported Platforms

At the time of initial release, PyDTLS 0.1.0 has been tested on Ubuntu
12.04.1 LTS 32-bit and 64-bit, as well as Microsoft Windows 7 32-bit
and 64-bit, using CPython 2.7.3. Patches with additional platform
ports are welcome.

As of release 1.2.0, PyDTLS is tested on Ubuntu 16.04 LTS as well as
Microsoft Windows 10, using CPython 2.7.13.
