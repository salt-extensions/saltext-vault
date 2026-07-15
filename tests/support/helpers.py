"""
:copyright: Copyright 2013-2017 by the SaltStack Team, see AUTHORS for more details.
:license: Apache 2.0, see LICENSE for more details.


tests.support.helpers
~~~~~~~~~~~~~~~~~~~~~

Test support helpers
"""

import logging
import os

import salt.exceptions

log = logging.getLogger(__name__)


class PatchedEnviron:
    """
    Create a patched environment
    """

    def __init__(self, **kwargs):
        self.cleanup_keys = kwargs.pop("__cleanup__", ())
        self.kwargs = kwargs
        self.original_environ: dict[str, str] | None = None

    def __enter__(self):
        self.original_environ = os.environ.copy()
        for key in self.cleanup_keys:
            os.environ.pop(key, None)
        os.environ.update(**self.kwargs)
        return self

    def __exit__(self, *args):
        os.environ.clear()
        os.environ.update(self.original_environ or {})


class WrapperFuncProxy:
    """
    Behave similarly to a loaded module in functional tests while executing via
    salt_ssh_cli instead.

    Allows to duplicate functional tests for execution modules into wrapper
    integration tests without most necessary modifications. Still consider
    reducing the test amount since wrapper integration tests are costly.

    Usage:

    .. code-block:: py

        @pytest.fixture
        def my_module(salt_ssh_cli):
            try:
                yield WrapperFuncProxy(salt_ssh_cli, exc=CommandExecutionError)
            finally:
                # Do cleanup or something

        def test_foo(my_module):
            res = my_module.foo("foo", bar=False)
            assert res is True

        def test_foo_failure(my_module):
            with pytest.raises(CommandExecutionError, match="Meh.*"):
                my_module.foo("foo", bar=True)

        def test_foo_required_arg(my_module):
            my_module.exc = SaltInvocationError
            with pytest.raises(SaltInvocationError, match="Wut.*"):
                my_module.foo("foo")
    """

    def __init__(self, salt_ssh_cli, exc=salt.exceptions.CommandExecutionError):
        self.salt_ssh_cli = salt_ssh_cli
        self.exc = exc

    def __getattr__(self, attr):
        self.func = attr
        return self

    def __call__(self, *args, _expect_fail=False, **kwargs):
        ret = self.salt_ssh_cli.run(f"vault_plugin.{self.func}", *args, **kwargs)
        if _expect_fail is True:
            assert ret.returncode > 0
            return ret
        if (
            self.exc is not None
            and ret.returncode > 0
            and isinstance(ret.data, str)
            and ret.data.startswith("An Exception occurred")
        ):
            raise self.exc(ret.data.split(":", maxsplit=1)[1].lstrip())
        assert ret.returncode == 0
        return ret.data
