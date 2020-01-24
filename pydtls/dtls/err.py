# DTLS exceptions.

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

"""DTLS Errors

This module defines error functionality and exception types for the dtls
package.

Classes:

  SSLError -- exception raised for I/O errors
  InvalidSocketError -- exception raised for improper socket objects
"""

from socket import error as socket_error

SSL_ERROR_NONE = 0
SSL_ERROR_SSL = 1
SSL_ERROR_WANT_READ = 2
SSL_ERROR_WANT_WRITE = 3
SSL_ERROR_WANT_X509_LOOKUP = 4
SSL_ERROR_SYSCALL = 5
SSL_ERROR_ZERO_RETURN = 6
SSL_ERROR_WANT_CONNECT = 7
SSL_ERROR_WANT_ACCEPT = 8

ERR_BOTH_KEY_CERT_FILES = 500
ERR_BOTH_KEY_CERT_FILES_SVR = 298
ERR_NO_CERTS = 331
ERR_NO_CIPHER = 501
ERR_READ_TIMEOUT = 502
ERR_WRITE_TIMEOUT = 503
ERR_HANDSHAKE_TIMEOUT = 504
ERR_PORT_UNREACHABLE = 505

ERR_WRONG_SSL_VERSION = 0x1409210A
ERR_WRONG_VERSION_NUMBER = 0x1408A10B
ERR_COOKIE_MISMATCH = 0x1408A134
ERR_CERTIFICATE_VERIFY_FAILED = 0x14090086
ERR_NO_SHARED_CIPHER = 0x1408A0C1
ERR_SSL_HANDSHAKE_FAILURE = 0x1410C0E5
ERR_TLSV1_ALERT_UNKNOWN_CA = 0x14102418

def patch_ssl_errors():
    import ssl
    errors = [i for i in globals().iteritems() if type(i[1]) == int and str(i[0]).startswith('ERR_')]
    for k, v in errors:
        if not hasattr(ssl, k):
            setattr(ssl, k, v)

class SSLError(socket_error):
    """This exception is raised by modules in the dtls package."""
    def __init__(self, *args):
        super(SSLError, self).__init__(*args)


class InvalidSocketError(Exception):
    """There is a problem with a socket passed to the dtls package."""
    def __init__(self, *args):
        super(InvalidSocketError, self).__init__(*args)


def _make_opensslerror_class():
    global _OpenSSLError
    class __OpenSSLError(SSLError):
        """
        This exception is raised when an error occurs in the OpenSSL library
        """
        def __init__(self, ssl_error, errqueue, result, func, args):
            self.ssl_error = ssl_error
            self.errqueue = errqueue
            self.result = result
            self.func = func
            self.args = args
            SSLError.__init__(self, ssl_error, errqueue,
                              result, func, args)

    _OpenSSLError = __OpenSSLError

_make_opensslerror_class()

def openssl_error():
    """Return the OpenSSL error type for use in exception clauses"""
    return _OpenSSLError

def raise_as_ssl_module_error():
    """Exceptions raised from this module are instances of ssl.SSLError"""
    import ssl
    global SSLError
    SSLError = ssl.SSLError
    _make_opensslerror_class()

def raise_ssl_error(code, nested=None):
    """Raise an SSL error with the given error code"""
    err_string = str(code) + ": " + _ssl_errors[code]
    if nested:
        raise SSLError(code, err_string + str(nested))
    raise SSLError(code, err_string)

_ssl_errors = {
    ERR_NO_CERTS: "No root certificates specified for verification " + \
                  "of other-side certificates",
    ERR_BOTH_KEY_CERT_FILES: "Both the key & certificate files " + \
                             "must be specified",
    ERR_BOTH_KEY_CERT_FILES_SVR: "Both the key & certificate files must be " + \
                                 "specified for server-side operation",
    ERR_NO_CIPHER: "No cipher can be selected.",
    ERR_READ_TIMEOUT: "The read operation timed out",
    ERR_WRITE_TIMEOUT: "The write operation timed out",
    ERR_HANDSHAKE_TIMEOUT: "The handshake operation timed out",
    ERR_PORT_UNREACHABLE: "The peer address is not reachable",
    }
