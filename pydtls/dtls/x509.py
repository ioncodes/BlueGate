# X509: certificate support.

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

"""X509 Certificate

This module provides support for X509 certificates through the OpenSSL library.
This support includes mapping certificate data to Python dictionaries in the
manner established by the Python standard library's ssl module. This module is
required because the standard library's ssl module does not provide its support
for certificates from arbitrary sources, but instead only for certificates
retrieved from servers during handshaking or get_server_certificate by its
CPython _ssl implementation module. This author is aware of the latter module's
_test_decode_certificate function, but has decided not to use this function
because it is undocumented, and because its use would tie PyDTLS to the CPython
interpreter.
"""

from logging import getLogger
from openssl import *
from util import _Rsrc, _BIO

_logger = getLogger(__name__)


class _X509(_Rsrc):
    """Wrapper for the cryptographic library's X509 resource"""
    def __init__(self, value):
        super(_X509, self).__init__(value)

    def __del__(self):
        _logger.debug("Freeing X509: %d", self.raw)
        X509_free(self._value)
        self._value = None


class _STACK(_Rsrc):
    """Wrapper for the cryptographic library's stacks"""
    def __init__(self, value):
        super(_STACK, self).__init__(value)

    def __del__(self):
        _logger.debug("Freeing stack: %d", self.raw)
        sk_pop_free(self._value)
        self._value = None

def decode_cert(cert):
    """Convert an X509 certificate into a Python dictionary

    This function converts the given X509 certificate into a Python dictionary
    in the manner established by the Python standard library's ssl module.
    """

    ret_dict = {}
    subject_xname = X509_get_subject_name(cert.value)
    ret_dict["subject"] = _create_tuple_for_X509_NAME(subject_xname)

    notAfter = X509_get_notAfter(cert.value)
    ret_dict["notAfter"] = ASN1_TIME_print(notAfter)

    peer_alt_names = _get_peer_alt_names(cert)
    if peer_alt_names is not None:
        ret_dict["subjectAltName"] = peer_alt_names

    return ret_dict

def _test_decode_cert(cert_filename):
    """format_cert testing

    Test the certificate conversion functionality with a PEM-encoded X509
    certificate.
    """

    cert_file = _BIO(BIO_new_file(cert_filename, "rb"))
    cert = _X509(PEM_read_bio_X509_AUX(cert_file.value))
    return decode_cert(cert)

def _create_tuple_for_attribute(name, value):
    name_str = OBJ_obj2txt(name, False)
    value_str = decode_ASN1_STRING(value)
    return name_str, value_str

def _create_tuple_for_X509_NAME(xname):
    distinguished_name = []
    relative_distinguished_name = []
    level = -1
    for ind in range(X509_NAME_entry_count(xname)):
        name_entry_ptr = X509_NAME_get_entry(xname, ind)
        name_entry = name_entry_ptr.contents
        if level >= 0 and level != name_entry.set:
            distinguished_name.append(tuple(relative_distinguished_name))
            relative_distinguished_name = []
        level = name_entry.set
        asn1_object = X509_NAME_ENTRY_get_object(name_entry_ptr)
        asn1_string = X509_NAME_ENTRY_get_data(name_entry_ptr)
        attribute_tuple = _create_tuple_for_attribute(asn1_object, asn1_string)
        relative_distinguished_name.append(attribute_tuple)
    if relative_distinguished_name:
        distinguished_name.append(tuple(relative_distinguished_name))
    return tuple(distinguished_name)

def _get_peer_alt_names(cert):
    ret_list = None
    ext_index = -1
    while True:
        ext_index = X509_get_ext_by_NID(cert.value, NID_subject_alt_name,
                                        ext_index)
        if ext_index < 0:
            break
        if ret_list is None:
            ret_list = []
        ext_ptr = X509_get_ext(cert.value, ext_index)
        method_ptr = X509V3_EXT_get(ext_ptr)
        general_names = _STACK(ASN1_item_d2i(method_ptr.contents,
                                             ext_ptr.contents.value.contents))
        for name_index in range(sk_num(general_names.value)):
            name_ptr = sk_value(general_names.value, name_index)
            if name_ptr.contents.type == GEN_DIRNAME:
                name_tuple = "DirName", \
                  _create_tuple_for_X509_NAME(name_ptr.contents.d.directoryName)
            else:
                name_str = GENERAL_NAME_print(name_ptr)
                name_tuple = tuple(name_str.split(':', 1))
            ret_list.append(name_tuple)

    return tuple(ret_list) if ret_list is not None else None
