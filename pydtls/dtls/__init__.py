# PyDTLS: datagram TLS for Python.

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

"""PyDTLS package

This package exports OpenSSL's DTLS support to Python. Calling its patch
function will add the constant PROTOCOL_DTLSv1 to the Python standard library's
ssl module.  Subsequently passing a datagram socket to that module's
wrap_socket function (or instantiating its SSLSocket class with a datagram
socket) will activate this module's DTLS implementation for the returned
SSLSocket instance.

Instead of or in addition to invoking the patch functionality, the
SSLConnection class can be used directly for secure communication over datagram
sockets.

wrap_socket's parameters and their semantics have been maintained.
"""

VERSION = 1, 2, 3

def _prep_bins():
    """
    Support for running straight out of a cloned source directory instead
    of an installed distribution
    """

    from os import path
    from sys import platform, maxsize
    from shutil import copy
    bit_suffix = "-x86_64" if maxsize > 2**32 else "-x86"
    package_root = path.abspath(path.dirname(__file__))
    prebuilt_path = path.join(package_root, "prebuilt", platform + bit_suffix)
    config = {"MANIFEST_DIR": prebuilt_path}
    try:
        execfile(path.join(prebuilt_path, "manifest.pycfg"), config)
    except IOError:
        return  # there are no prebuilts for this platform - nothing to do
    files = map(lambda x: path.join(prebuilt_path, x), config["FILES"])
    for prebuilt_file in files:
        try:
            copy(path.join(prebuilt_path, prebuilt_file), package_root)
        except IOError:
            pass

_prep_bins()  # prepare before module imports

from patch import do_patch
from sslconnection import SSLContext, SSL, SSLConnection
from demux import force_routing_demux, reset_default_demux
