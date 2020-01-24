# -*- coding: utf-8 -*-

# Test the support for DTLS through the SSL module. Adapted from the Python
# standard library's test_ssl.py regression test module by Björn Freise.

import unittest
import threading
import sys
import socket
import os
import pprint

from logging import basicConfig, DEBUG, getLogger
# basicConfig(level=DEBUG, format="%(asctime)s - %(threadName)-10s - %(name)s - %(levelname)s - %(message)s")
_logger = getLogger(__name__)

import ssl
from dtls.wrapper import DtlsSocket


HOST = "localhost"
CHATTY = True
CHATTY_CLIENT = True


class ThreadedEchoServer(threading.Thread):

    def __init__(self, certificate, ssl_version=None, certreqs=None, cacerts=None,
                 ciphers=None, curves=None, sigalgs=None,
                 mtu=None, server_key_exchange_curve=None, server_cert_options=None,
                 chatty=True):

        if ssl_version is None:
            ssl_version = ssl.PROTOCOL_DTLSv1
        if certreqs is None:
            certreqs = ssl.CERT_NONE

        self.certificate = certificate
        self.protocol = ssl_version
        self.certreqs = certreqs
        self.cacerts = cacerts
        self.ciphers = ciphers
        self.curves = curves
        self.sigalgs = sigalgs
        self.mtu = mtu
        self.server_key_exchange_curve = server_key_exchange_curve
        self.server_cert_options = server_cert_options
        self.chatty = chatty

        self.flag = None

        self.sock = DtlsSocket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
                               keyfile=self.certificate,
                               certfile=self.certificate,
                               server_side=True,
                               cert_reqs=self.certreqs,
                               ssl_version=self.protocol,
                               ca_certs=self.cacerts,
                               ciphers=self.ciphers,
                               curves=self.curves,
                               sigalgs=self.sigalgs,
                               user_mtu=self.mtu,
                               server_key_exchange_curve=self.server_key_exchange_curve,
                               server_cert_options=self.server_cert_options)

        if self.chatty:
            sys.stdout.write(' server:  wrapped server socket as %s\n' % str(self.sock))
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
        self.sock.listen(0)
        self.active = True
        if self.flag:
            # signal an event
            self.flag.set()
        while self.active:
            try:
                acc_ret = self.sock.recvfrom(4096)
                if acc_ret:
                    newdata, connaddr = acc_ret
                    if self.chatty:
                        sys.stdout.write(' server:  new data from ' + str(connaddr) + '\n')
                    self.sock.sendto(newdata.lower(), connaddr)
            except socket.timeout:
                pass
            except KeyboardInterrupt:
                self.stop()
            except Exception as e:
                if self.chatty:
                    sys.stdout.write(' server:  error ' + str(e) + '\n')
                pass
        if self.chatty:
            sys.stdout.write(' server:  closing socket as %s\n' % str(self.sock))
        self.sock.close()

    def stop(self):
        self.active = False
        if self.starter != threading.current_thread().ident:
            return
        self.join()  # don't allow spawning new handlers after we've checked


CERTFILE = os.path.join(os.path.dirname(__file__) or os.curdir, "certs", "keycert.pem")
CERTFILE_EC = os.path.join(os.path.dirname(__file__) or os.curdir, "certs", "keycert_ec.pem")
ISSUER_CERTFILE = os.path.join(os.path.dirname(__file__) or os.curdir, "certs", "ca-cert.pem")
ISSUER_CERTFILE_EC = os.path.join(os.path.dirname(__file__) or os.curdir, "certs", "ca-cert_ec.pem")

# certfile, protocol, certreqs, cacertsfile,
# ciphers=None, curves=None, sigalgs=None,
tests = [
    {'testcase':
        {'name': 'standard dtls v1',
         'desc': 'Standard DTLS v1 test with out-of-the box configuration and RSA certificate',
         'start_server': True},
     'input':
        {'certfile': CERTFILE,
         'protocol': ssl.PROTOCOL_DTLSv1,
         'certreqs': None,
         'cacertsfile': ISSUER_CERTFILE,
         'ciphers': None,
         'curves': None,
         'sigalgs': None,
         'client_certfile': None,
         'client_protocol': ssl.PROTOCOL_DTLSv1,
         'client_certreqs': ssl.CERT_REQUIRED,
         'client_cacertsfile': ISSUER_CERTFILE,
         'client_ciphers': None,
         'client_curves': None,
         'client_sigalgs': None},
     'result':
         {'ret_success': True,
          'error_code': None,
          'exception': None}},
    {'testcase':
        {'name': 'standard dtls v1_2',
         'desc': 'Standard DTLS v1_2 test with out-of-the box configuration and ECDSA certificate',
         'start_server': True},
     'input':
        {'certfile': CERTFILE_EC,
         'protocol': ssl.PROTOCOL_DTLSv1_2,
         'certreqs': None,
         'cacertsfile': ISSUER_CERTFILE_EC,
         'ciphers': None,
         'curves': None,
         'sigalgs': None,
         'client_certfile': None,
         'client_protocol': ssl.PROTOCOL_DTLSv1_2,
         'client_certreqs': ssl.CERT_REQUIRED,
         'client_cacertsfile': ISSUER_CERTFILE_EC,
         'client_ciphers': None,
         'client_curves': None,
         'client_sigalgs': None},
     'result':
         {'ret_success': True,
          'error_code': None,
          'exception': None}},
    {'testcase':
        {'name': 'protocol version mismatch',
         'desc': 'Client and server have different protocol versions',
         'start_server': True},
     'input':
         {'certfile': CERTFILE,
          'protocol': ssl.PROTOCOL_DTLSv1,
          'certreqs': None,
          'cacertsfile': ISSUER_CERTFILE,
          'ciphers': None,
          'curves': None,
          'sigalgs': None,
          'client_certfile': None,
          'client_protocol': ssl.PROTOCOL_DTLSv1_2,
          'client_certreqs': ssl.CERT_REQUIRED,
          'client_cacertsfile': ISSUER_CERTFILE,
          'client_ciphers': None,
          'client_curves': None,
          'client_sigalgs': None},
     'result':
         {'ret_success': False,
          'error_code': ssl.ERR_WRONG_SSL_VERSION,
          'exception': None}},
    {'testcase':
        {'name': 'certificate verify fails',
         'desc': 'Server certificate cannot be verified by client',
         'start_server': True},
     'input':
         {'certfile': CERTFILE_EC,
          'protocol': ssl.PROTOCOL_DTLSv1_2,
          'certreqs': None,
          'cacertsfile': ISSUER_CERTFILE_EC,
          'ciphers': None,
          'curves': None,
          'sigalgs': None,
          'client_certfile': None,
          'client_protocol': ssl.PROTOCOL_DTLSv1_2,
          'client_certreqs': ssl.CERT_REQUIRED,
          'client_cacertsfile': ISSUER_CERTFILE,
          'client_ciphers': None,
          'client_curves': None,
          'client_sigalgs': None},
     'result':
         {'ret_success': False,
          'error_code': ssl.ERR_CERTIFICATE_VERIFY_FAILED,
          'exception': None}},
    {'testcase':
        {'name': 'no matching curve',
         'desc': 'Client doesn\'t support curve used by server ECDSA certificate',
         'start_server': True},
     'input':
         {'certfile': CERTFILE_EC,
          'protocol': ssl.PROTOCOL_DTLSv1_2,
          'certreqs': None,
          'cacertsfile': ISSUER_CERTFILE_EC,
          'ciphers': None,
          'curves': None,
          'sigalgs': None,
          'client_certfile': None,
          'client_protocol': ssl.PROTOCOL_DTLSv1_2,
          'client_certreqs': ssl.CERT_REQUIRED,
          'client_cacertsfile': ISSUER_CERTFILE_EC,
          'client_ciphers': None,
          'client_curves': 'secp384r1',
          'client_sigalgs': None},
     'result':
         {'ret_success': False,
          'error_code': ssl.ERR_SSL_HANDSHAKE_FAILURE,
          'exception': None}},
    {'testcase':
         {'name': 'matching curve',
          'desc': '',
          'start_server': True},
     'input':
         {'certfile': CERTFILE_EC,
          'protocol': ssl.PROTOCOL_DTLSv1_2,
          'certreqs': None,
          'cacertsfile': ISSUER_CERTFILE_EC,
          'ciphers': None,
          'curves': None,
          'sigalgs': None,
          'client_certfile': None,
          'client_protocol': ssl.PROTOCOL_DTLSv1_2,
          'client_certreqs': ssl.CERT_REQUIRED,
          'client_cacertsfile': ISSUER_CERTFILE_EC,
          'client_ciphers': None,
          'client_curves': 'prime256v1',
          'client_sigalgs': None},
     'result':
         {'ret_success': True,
          'error_code': None,
          'exception': None}},
    {'testcase':
        {'name': 'no host',
         'desc': 'No server port is listening',
         'start_server': False},
     'input':
         {'certfile': CERTFILE_EC,
          'protocol': ssl.PROTOCOL_DTLSv1_2,
          'certreqs': None,
          'cacertsfile': ISSUER_CERTFILE_EC,
          'ciphers': None,
          'curves': None,
          'sigalgs': None,
          'client_certfile': None,
          'client_protocol': ssl.PROTOCOL_DTLSv1_2,
          'client_certreqs': ssl.CERT_REQUIRED,
          'client_cacertsfile': ISSUER_CERTFILE_EC,
          'client_ciphers': None,
          'client_curves': None,
          'client_sigalgs': None},
     'result':
         {'ret_success': False,
          'error_code': ssl.ERR_PORT_UNREACHABLE,
          'exception': None}},
    {'testcase':
        {'name': 'no matching sigalgs',
         'desc': '',
         'start_server': True},
     'input':
         {'certfile': CERTFILE_EC,
          'protocol': ssl.PROTOCOL_DTLSv1_2,
          'certreqs': None,
          'cacertsfile': ISSUER_CERTFILE_EC,
          'ciphers': None,
          'curves': None,
          'sigalgs': None,
          'client_certfile': None,
          'client_protocol': ssl.PROTOCOL_DTLSv1_2,
          'client_certreqs': ssl.CERT_REQUIRED,
          'client_cacertsfile': ISSUER_CERTFILE_EC,
          'client_ciphers': None,
          'client_curves': None,
          'client_sigalgs': "RSA+SHA256"},
     'result':
         {'ret_success': False,
          'error_code': ssl.ERR_SSL_HANDSHAKE_FAILURE,
          'exception': None}},
    {'testcase':
        {'name': 'matching sigalgs',
         'desc': '',
         'start_server': True},
     'input':
         {'certfile': CERTFILE_EC,
          'protocol': ssl.PROTOCOL_DTLSv1_2,
          'certreqs': None,
          'cacertsfile': ISSUER_CERTFILE_EC,
          'ciphers': None,
          'curves': None,
          'sigalgs': None,
          'client_certfile': None,
          'client_protocol': ssl.PROTOCOL_DTLSv1_2,
          'client_certreqs': ssl.CERT_REQUIRED,
          'client_cacertsfile': ISSUER_CERTFILE_EC,
          'client_ciphers': None,
          'client_curves': None,
          'client_sigalgs': "ECDSA+SHA256"},
     'result':
         {'ret_success': True,
          'error_code': None,
          'exception': None}},
    {'testcase':
        {'name': 'no matching cipher',
         'desc': 'Server using a ECDSA certificate while client is only able to use RSA encryption',
         'start_server': True},
     'input':
         {'certfile': CERTFILE_EC,
          'protocol': ssl.PROTOCOL_DTLSv1_2,
          'certreqs': None,
          'cacertsfile': ISSUER_CERTFILE_EC,
          'ciphers': None,
          'curves': None,
          'sigalgs': None,
          'client_certfile': None,
          'client_protocol': ssl.PROTOCOL_DTLSv1_2,
          'client_certreqs': ssl.CERT_REQUIRED,
          'client_cacertsfile': ISSUER_CERTFILE_EC,
          'client_ciphers': "AES256-SHA",
          'client_curves': None,
          'client_sigalgs': None},
     'result':
         {'ret_success': False,
          'error_code': ssl.ERR_SSL_HANDSHAKE_FAILURE,
          'exception': None}},
    {'testcase':
        {'name': 'matching cipher',
         'desc': '',
         'start_server': True},
     'input':
         {'certfile': CERTFILE_EC,
          'protocol': ssl.PROTOCOL_DTLSv1_2,
          'certreqs': None,
          'cacertsfile': ISSUER_CERTFILE_EC,
          'ciphers': None,
          'curves': None,
          'sigalgs': None,
          'client_certfile': None,
          'client_protocol': ssl.PROTOCOL_DTLSv1_2,
          'client_certreqs': ssl.CERT_REQUIRED,
          'client_cacertsfile': ISSUER_CERTFILE_EC,
          'client_ciphers': "ECDHE-ECDSA-AES256-SHA",
          'client_curves': None,
          'client_sigalgs': None},
     'result':
         {'ret_success': True,
          'error_code': None,
          'exception': None}},
]


def params_test(start_server, certfile, protocol, certreqs, cacertsfile,
                client_certfile=None, client_protocol=None, client_certreqs=None, client_cacertsfile=None,
                ciphers=None, curves=None, sigalgs=None,
                client_ciphers=None, client_curves=None, client_sigalgs=None,
                mtu=None, server_key_exchange_curve=None, server_cert_options=None,
                indata="FOO\n", chatty=False, connectionchatty=False):
    """
    Launch a server, connect a client to it and try various reads
    and writes.
    """
    server = ThreadedEchoServer(certfile,
                                ssl_version=protocol,
                                certreqs=certreqs,
                                cacerts=cacertsfile,
                                ciphers=ciphers,
                                curves=curves,
                                sigalgs=sigalgs,
                                mtu=mtu,
                                server_key_exchange_curve=server_key_exchange_curve,
                                server_cert_options=server_cert_options,
                                chatty=chatty)
    # should we really run the server?
    if start_server:
        flag = threading.Event()
        server.start(flag)
        # wait for it to start
        flag.wait()
    else:
        server.sock.close()
    # try to connect
    if client_protocol is None:
        client_protocol = protocol
    if client_ciphers is None:
        client_ciphers = ciphers
    if client_curves is None:
        client_curves = curves
    if client_sigalgs is None:
        client_sigalgs = sigalgs
    try:
        s = DtlsSocket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
                       keyfile=client_certfile,
                       certfile=client_certfile,
                       cert_reqs=client_certreqs,
                       ssl_version=client_protocol,
                       ca_certs=client_cacertsfile,
                       ciphers=client_ciphers,
                       curves=client_curves,
                       sigalgs=client_sigalgs,
                       user_mtu=mtu)
        s.connect((HOST, server.port))
        if connectionchatty:
            sys.stdout.write(" client:  sending %s...\n" % (repr(indata)))
        s.write(indata)
        outdata = s.read()
        if connectionchatty:
            sys.stdout.write(" client:  read %s\n" % repr(outdata))
        if outdata != indata.lower():
            raise AssertionError("bad data <<%s>> (%d) received; expected <<%s>> (%d)\n"
                                 % (outdata[:min(len(outdata), 20)], len(outdata),
                                    indata[:min(len(indata), 20)].lower(), len(indata)))
        cert = s.getpeercert()
        cipher = s.cipher()
        if connectionchatty:
            sys.stdout.write("cert:\n" + pprint.pformat(cert) + "\n")
            sys.stdout.write("cipher:\n" + pprint.pformat(cipher) + "\n")
        if connectionchatty:
            sys.stdout.write(" client:  closing connection.\n")
        try:
            s.close()
        except Exception as e:
            if connectionchatty:
                sys.stdout.write(" client:  error closing connection %s...\n" % (repr(e)))
            pass
    except Exception as e:
        if connectionchatty:
            sys.stdout.write(" client:  aborting with exception %s...\n" % (repr(e)))
        return False, e
    finally:
        if start_server:
            server.stop()
    return True, None


class TestSequenceMeta(type):
    def __new__(mcs, name, bases, dict):

        def gen_test(_case, _input, _result):
            def test(self):
                try:
                    if CHATTY or CHATTY_CLIENT:
                        sys.stdout.write("\nTestcase: %s\n" % _case['name'])
                    ret, e = params_test(_case['start_server'], chatty=CHATTY, connectionchatty=CHATTY_CLIENT, **_input)
                    if _result['ret_success']:
                        self.assertEqual(ret, _result['ret_success'])
                    else:
                        try:
                            last_error = e.errqueue[-1][0]
                        except:
                            try:
                                last_error = e.errno
                            except:
                                last_error = None
                        self.assertEqual(last_error, _result['error_code'])
                except Exception as e:
                    raise
            return test

        for testcase in tests:
            _case, _input, _result = testcase.itervalues()
            test_name = "test_%s" % _case['name'].lower().replace(' ', '_')
            dict[test_name] = gen_test(_case, _input, _result)

        return type.__new__(mcs, name, bases, dict)


class WrapperTests(unittest.TestCase):
    __metaclass__ = TestSequenceMeta

    def test_build_cert_chain(self):
        steps = [ssl.SSL_BUILD_CHAIN_FLAG_NONE, ssl.SSL_BUILD_CHAIN_FLAG_NO_ROOT]
        chatty, connectionchatty = CHATTY, CHATTY_CLIENT
        indata = 'FOO'
        certs = dict()

        if chatty or connectionchatty:
            sys.stdout.write("\nTestcase: test_build_cert_chain\n")
        for step in steps:
            server = ThreadedEchoServer(certificate=CERTFILE,
                                        ssl_version=ssl.PROTOCOL_DTLSv1_2,
                                        certreqs=ssl.CERT_NONE,
                                        cacerts=ISSUER_CERTFILE,
                                        ciphers=None,
                                        curves=None,
                                        sigalgs=None,
                                        mtu=None,
                                        server_key_exchange_curve=None,
                                        server_cert_options=step,
                                        chatty=chatty)
            flag = threading.Event()
            server.start(flag)
            # wait for it to start
            flag.wait()
            try:
                s = DtlsSocket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
                               keyfile=None,
                               certfile=None,
                               cert_reqs=ssl.CERT_REQUIRED,
                               ssl_version=ssl.PROTOCOL_DTLSv1_2,
                               ca_certs=ISSUER_CERTFILE,
                               ciphers=None,
                               curves=None,
                               sigalgs=None,
                               user_mtu=None)
                s.connect((HOST, server.port))
                if connectionchatty:
                    sys.stdout.write(" client:  sending %s...\n" % (repr(indata)))
                s.write(indata)
                outdata = s.read()
                if connectionchatty:
                    sys.stdout.write(" client:  read %s\n" % repr(outdata))
                if outdata != indata.lower():
                    raise AssertionError("bad data <<%s>> (%d) received; expected <<%s>> (%d)\n"
                                         % (outdata[:min(len(outdata), 20)], len(outdata),
                                            indata[:min(len(indata), 20)].lower(), len(indata)))
                # cert = s.getpeercert()
                # cipher = s.cipher()
                # if connectionchatty:
                #     sys.stdout.write("cert:\n" + pprint.pformat(cert) + "\n")
                #     sys.stdout.write("cipher:\n" + pprint.pformat(cipher) + "\n")
                certs[step] = s.getpeercertchain()
                if connectionchatty:
                    sys.stdout.write(" client:  closing connection.\n")
                try:
                    s.close()
                except Exception as e:
                    if connectionchatty:
                        sys.stdout.write(" client:  error closing connection %s...\n" % (repr(e)))
                    pass
            except Exception as e:
                if connectionchatty:
                    sys.stdout.write(" client:  aborting with exception %s...\n" % (repr(e)))
                raise
            finally:
                server.stop()

        if chatty:
            sys.stdout.write("certs:\n")
            for step in steps:
                sys.stdout.write("SSL_CTX_build_cert_chain: %s\n%s\n" % (step, pprint.pformat(certs[step])))
        self.assertNotEqual(certs[steps[0]], certs[steps[1]])
        self.assertEqual(len(certs[steps[0]]) - len(certs[steps[1]]), 1)

    def test_set_ecdh_curve(self):
        steps = {
            # server, client, result
            'all auto':                 (None, None,                            True),      # Auto
            'client restricted':        (None, "secp256k1:prime256v1",          True),      # client can handle key curve
            'client too restricted':    (None, "secp256k1",                     False),     # client _cannot_ handle key curve
            'client minimum':           (None, "prime256v1",                    True),      # client can only handle key curve
            'server restricted':        ("secp384r1", None,                     True),      # client can handle key curve
            'server one, client two':   ("secp384r1", "prime256v1:secp384r1",   True),      # client can handle key curve
            'server one, client one':   ("secp384r1", "secp384r1",              False),     # client _cannot_ handle key curve
        }

        chatty, connectionchatty = CHATTY, CHATTY_CLIENT
        indata = 'FOO'
        certs = dict()

        if chatty or connectionchatty:
            sys.stdout.write("\nTestcase: test_ecdh_curve\n")
        for step, tmp in steps.iteritems():
            if chatty or connectionchatty:
                sys.stdout.write("\n Subcase: %s\n" % step)
            server_curve, client_curve, result = tmp
            server = ThreadedEchoServer(certificate=CERTFILE_EC,
                                        ssl_version=ssl.PROTOCOL_DTLSv1_2,
                                        certreqs=ssl.CERT_NONE,
                                        cacerts=ISSUER_CERTFILE_EC,
                                        ciphers=None,
                                        curves=None,
                                        sigalgs=None,
                                        mtu=None,
                                        server_key_exchange_curve=server_curve,
                                        server_cert_options=None,
                                        chatty=chatty)
            flag = threading.Event()
            server.start(flag)
            # wait for it to start
            flag.wait()
            try:
                s = DtlsSocket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
                               keyfile=None,
                               certfile=None,
                               cert_reqs=ssl.CERT_REQUIRED,
                               ssl_version=ssl.PROTOCOL_DTLSv1_2,
                               ca_certs=ISSUER_CERTFILE_EC,
                               ciphers=None,
                               curves=client_curve,
                               sigalgs=None,
                               user_mtu=None)
                s.connect((HOST, server.port))
                if connectionchatty:
                    sys.stdout.write(" client:  sending %s...\n" % (repr(indata)))
                s.write(indata)
                outdata = s.read()
                if connectionchatty:
                    sys.stdout.write(" client:  read %s\n" % repr(outdata))
                if outdata != indata.lower():
                    raise AssertionError("bad data <<%s>> (%d) received; expected <<%s>> (%d)\n"
                                         % (outdata[:min(len(outdata), 20)], len(outdata),
                                            indata[:min(len(indata), 20)].lower(), len(indata)))
                if connectionchatty:
                    sys.stdout.write(" client:  closing connection.\n")
                try:
                    s.close()
                except Exception as e:
                    if connectionchatty:
                        sys.stdout.write(" client:  error closing connection %s...\n" % (repr(e)))
                    pass
            except Exception as e:
                if connectionchatty:
                    sys.stdout.write(" client:  aborting with exception %s...\n" % (repr(e)))
                if result:
                    raise
            finally:
                server.stop()

        pass


if __name__ == '__main__':
    unittest.main()
