# TLock: OpenSSL lock support on thread-enabled systems.

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

"""TLock

This module provides the callbacks required by the OpenSSL library in situations
where it is being entered concurrently by multiple threads. This module is
enagaged automatically by the PyDTLS package on systems that have Python
threading support. It does not have client-visible components.
"""

from logging import getLogger
from openssl import *

try:
    import threading
except ImportError:
    pass

_logger = getLogger(__name__)
DO_DEBUG_LOG = False

def tlock_init():
    if not globals().has_key("threading"):
        return  # nothing to configure
    # The standard library ssl module's lock implementation is more efficient;
    # do not override it if it has been established
    if CRYPTO_get_id_callback():
        return
    global _locks
    num_locks = CRYPTO_num_locks()
    _locks = tuple(threading.Lock() for _ in range(num_locks))
    CRYPTO_set_locking_callback(_locking_function)

def _locking_function(mode, n, file, line):
    if DO_DEBUG_LOG:
        _logger.debug("Thread lock:  mode: %d, n: %d, file: %s, line: %d",
                      mode, n, file, line)
    if mode & CRYPTO_LOCK:
        _locks[n].acquire()
    else:
        _locks[n].release()
