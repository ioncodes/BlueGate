# PyDTLS reloader.

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

"""PyDTLS package reloader

This script reloads all modules of the DTLS package. This can be useful in
runtime environments that usually persist across package file edits, such as
the IPython shell.
"""

import dtls
import dtls.err
import dtls.util
import dtls.sslconnection
import dtls.x509
import dtls.openssl
import dtls.demux
import dtls.demux.router

def main():
    reload(dtls)
    reload(dtls.err)
    reload(dtls.util)
    reload(dtls.sslconnection)
    reload(dtls.x509)
    reload(dtls.openssl)
    reload(dtls.demux)
    reload(dtls.demux.router)
    reload(dtls.sslconnection)
    reload(dtls.x509)

if __name__ == "__main__":
    main()
