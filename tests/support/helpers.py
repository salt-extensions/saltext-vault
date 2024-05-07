"""
    :copyright: Copyright 2013-2017 by the SaltStack Team, see AUTHORS for more details.
    :license: Apache 2.0, see LICENSE for more details.


    tests.support.helpers
    ~~~~~~~~~~~~~~~~~~~~~

    Test support helpers
"""

import logging
import os

log = logging.getLogger(__name__)


class PatchedEnviron:
    """
    Create a patched environment
    """

    def __init__(self, **kwargs):
        self.cleanup_keys = kwargs.pop("__cleanup__", ())
        self.kwargs = kwargs
        self.original_environ = None

    def __enter__(self):
        self.original_environ = os.environ.copy()
        for key in self.cleanup_keys:
            os.environ.pop(key, None)
        os.environ.update(**self.kwargs)
        return self

    def __exit__(self, *args):
        os.environ.clear()
        os.environ.update(self.original_environ)
