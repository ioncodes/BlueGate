# Shared implementation internals.

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

"""Utilities

This module contains private implementation details shared among modules of
the PyDTLS package.
"""

from logging import getLogger

_logger = getLogger(__name__)


class _Rsrc(object):
    """Wrapper base for library-owned resources"""
    def __init__(self, value):
        self._value = value

    @property
    def value(self):
        return self._value

    @property
    def raw(self):
        return self._value.raw


class _BIO(_Rsrc):
    """BIO wrapper"""
    def __init__(self, value):
        super(_BIO, self).__init__(value)
        self.owned = True

    def disown(self):
        self.owned = False

    def __del__(self):
        if self.owned:
            _logger.debug("Freeing BIO: %d", self.raw)
            from openssl import BIO_free
            BIO_free(self._value)
            self.owned = False
        self._value = None


class _EC_KEY(_Rsrc):
    """EC KEY wrapper"""
    def __init__(self, value):
        super(_EC_KEY, self).__init__(value)

    def __del__(self):
        _logger.debug("Freeing EC_KEY: %d", self.raw)
        from openssl import EC_KEY_free
        EC_KEY_free(self._value)
        self._value = None
